//! The change path's authorization executor: the changed row where the schema
//! decides it, an `OpenFGA` server for the rest.
//!
//! `subql` ships the composition. [`RowPolicy`] answers from the row's own
//! column values wherever `rls2fga` reports that one row settles the relation,
//! and hands everything else to an inner policy, which [`OpenFgaPolicy`]
//! terminates by asking a server. This module supplies the three things that
//! composition needs from connetto and nothing else: what the model calls a
//! caller, a transport that counts its own round trips, and the wiring that
//! turns policy text into a running index.
//!
//! # Why the watcher is adapted rather than replaced
//!
//! `subql`'s [`Subject`] and connetto's [`Principal`] are both foreign to this
//! crate, so the impl needs a local type. [`FgaAuth`] therefore keeps
//! `Arc<Principal<Id, Key>>` as its watcher, exactly as every other policy
//! here does, and wraps each one in [`ModelSubject`] on the way in. The cost is
//! one vector of reference-count bumps per event. The alternative, changing the
//! watcher type itself, reaches nineteen sites across seven policy
//! implementations to satisfy a coherence rule rather than a requirement.

use std::borrow::Cow;
use std::fmt::Display;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use connetto_core::auth::Principal;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Text};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::bb8::Pool;
use openfga_client::client::{
    AuthorizationModel as ProtoModel, OpenFgaServiceClient, ReadAuthorizationModelsRequest,
};
use openfga_client::tonic::body::Body;
use openfga_client::tonic::client::GrpcService;
use openfga_client::tonic::codegen::{Body as ResponseBody, Bytes, StdError, http};
use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::generator::records::{Record, RecordDerivation};
use rls2fga::generator::tuple_generator::{TupleCondition, TupleRow};
use rls2fga::translator::Translator;
use subql::ParserDB;
use subql::backend::Postgres;
use subql::visibility::openfga::{OpenFgaError, OpenFgaPolicy};
use subql::visibility::policy::{RequestValues, RowPolicy, Subject};
use subql::visibility::shapes::Shapes;
use subql::visibility::store::{StoreDiff, StoreDiffError};
use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};

use crate::capability::CapabilityKey;
use crate::counters::{AUTHORIZATION_CALLS, add};
use crate::reach::GrantReach;

/// A transport that counts the calls that ask whether a row is visible.
///
/// **The counter belongs here and nowhere else.** [`RowPolicy`] is entered once
/// per changed event whatever it decides, so a counter on it would read one
/// from the day it landed and prove nothing, which is the trap `subql`'s own
/// module doc names. [`OpenFgaPolicy::may_see`] is entered once per event too,
/// while sending one call per batch of questions, so a counter there
/// undercounts by the batch factor. Only the transport sees round trips, and
/// round trips are what [`AUTHORIZATION_CALLS`] is documented to count.
///
/// **Questions only, which is what the counter means.** The same transport also
/// carries the writes that keep the store current, and those are upkeep rather
/// than questions: counting them would make a row's own change read as the cost
/// of answering about it, and the zero the local path earns would stop being
/// zero for a reason that has nothing to do with answering.
#[derive(Clone, Copy, Debug)]
pub struct Counted<T>(T);

impl<T> Counted<T> {
    /// Count what `inner` carries.
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: GrpcService<Body>> GrpcService<Body> for Counted<T> {
    type ResponseBody = T::ResponseBody;
    type Error = T::Error;
    type Future = T::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        if asks_a_question(request.uri().path()) {
            add(&AUTHORIZATION_CALLS, 1);
        }
        self.0.call(request)
    }
}

/// Whether a gRPC method asks whether something is visible.
///
/// Matched on the path rather than on the caller, because the caller is
/// upstream's and a method added there must not be counted by accident.
fn asks_a_question(path: &str) -> bool {
    path.ends_with("/Check") || path.ends_with("/BatchCheck")
}

/// What the authorization model calls a caller, resolved once from the
/// translation that built the model.
///
/// Both halves are read out of the translation rather than spelled here. A
/// parameter name spelled twice is spelled wrong eventually, and getting it
/// wrong is silent: a question missing a required parameter is refused by the
/// server rather than answered, so the watcher would be denied with nothing
/// naming the cause.
#[derive(Clone, Debug)]
pub struct SubjectNaming {
    /// The model's type for a person, so an identity is named `user:alice`.
    user_type: String,
    /// The condition parameter the deployment's share-key setting became.
    ///
    /// [`None`] when the model carries no grant a caller's own values complete,
    /// in which case there is nothing for a watcher to answer.
    subjects_parameter: Option<String>,
}

impl SubjectNaming {
    /// rls2fga names a person `user`, and this is the one place that assumes
    /// it.
    const USER_TYPE: &'static str = "user";

    /// The key rls2fga renders a wildcard subject with, so `user:*` reads back
    /// as everybody rather than as a person of that name.
    const WILDCARD_KEY: &'static str = "*";

    /// Read the naming a deployment's own key setting produced.
    ///
    /// The parameter is matched by the setting it mirrors, `Key::SETTING`,
    /// which is the contract the deployment already declared to the translator.
    #[must_use]
    pub fn resolve<Key: CapabilityKey>(shapes: &Shapes<ParserDB>) -> Self {
        let subjects_parameter = shapes
            .required_parameters()
            .iter()
            .find(|required| required.setting_key.as_deref() == Some(Key::SETTING))
            .map(|required| required.parameter.clone());
        Self {
            user_type: Self::USER_TYPE.to_owned(),
            subjects_parameter,
        }
    }

    /// Whether the model has a grant a caller's own values complete.
    #[must_use]
    pub const fn asks_the_caller(&self) -> bool {
        self.subjects_parameter.is_some()
    }

    /// Read one subject back as who it names.
    ///
    /// The inverse of [`ModelSubject::subjects`], which is the one rendering
    /// every question uses, so this compares against exactly what a live
    /// caller is named by.
    #[must_use]
    pub fn holder(&self, subject: &str) -> GrantHolder {
        match subject.split_once(':') {
            Some((kind, key)) if kind == self.user_type && key != Self::WILDCARD_KEY => {
                GrantHolder::Person(key.to_owned())
            }
            _ => GrantHolder::Everybody,
        }
    }
}

/// One watcher as the model names it.
///
/// Built per watcher per event from a shared principal and a shared naming, so
/// it costs two reference-count bumps and no allocation.
///
/// `Clone` and `Debug` are written out rather than derived: both handles are
/// shared, so neither needs anything of `Id` or `Key`, and a derive would
/// demand it anyway.
pub struct ModelSubject<Id, Key> {
    principal: Arc<Principal<Id, Key>>,
    naming: Arc<SubjectNaming>,
}

impl<Id, Key> core::fmt::Debug for ModelSubject<Id, Key> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModelSubject")
            .field("naming", &self.naming)
            .finish_non_exhaustive()
    }
}

impl<Id, Key> Clone for ModelSubject<Id, Key> {
    fn clone(&self) -> Self {
        Self {
            principal: Arc::clone(&self.principal),
            naming: Arc::clone(&self.naming),
        }
    }
}

impl<Id, Key> Subject for ModelSubject<Id, Key>
where
    Id: Display,
    Key: CapabilityKey,
{
    fn subjects(&self) -> impl Iterator<Item = Cow<'_, str>> {
        // A caller with no identity is named by nothing. Its share keys reach
        // the model as request values rather than as names, because rls2fga
        // renders a held key as a condition over the wildcard.
        self.principal
            .identity()
            .into_iter()
            .map(|identity| Cow::Owned(format!("{}:{}", self.naming.user_type, identity.user_id)))
    }

    fn request_value(&self, parameter: &str, out: &mut RequestValues) -> bool {
        if self.naming.subjects_parameter.as_deref() != Some(parameter) {
            return false;
        }
        // Holding none is an answer, not a refusal to answer: a caller holding
        // no key is granted by no key.
        for held in self.principal.capabilities() {
            out.push(&held.key().to_string());
        }
        true
    }
}

/// The composed executor: the row where the schema decides, the server for the
/// rest.
///
/// `T` is the transport, which production wraps in [`Counted`].
pub struct FgaAuth<Id, Key, T> {
    inner: RowPolicy<ParserDB, OpenFgaPolicy<ParserDB, T, ModelSubject<Id, Key>, Postgres>>,
    naming: Arc<SubjectNaming>,
}

impl<Id, Key, T> FgaAuth<Id, Key, T> {
    /// Compose the two halves over one shared index.
    ///
    /// The index is shared rather than built twice, so the wrapper and the
    /// policy behind it read one catalog and one set of descriptions. Two built
    /// apart could disagree, and every question would then name rows that do
    /// not exist.
    #[must_use]
    pub fn new(
        shapes: Arc<Shapes<ParserDB>>,
        delegate: OpenFgaPolicy<ParserDB, T, ModelSubject<Id, Key>, Postgres>,
        naming: Arc<SubjectNaming>,
    ) -> Self {
        Self {
            inner: RowPolicy::new(shapes, delegate),
            naming,
        }
    }

    /// The upkeep for this executor, over the index it answers from.
    ///
    /// Built here rather than assembled by a caller so the two cannot end up
    /// reading different indexes. A store maintained against one description
    /// and questioned against another names rows that do not exist. `reach` is
    /// walked over the model the same translation produced, for the same reason.
    #[must_use]
    pub fn upkeep(&self, reach: GrantReach) -> Arc<dyn StoreUpkeep>
    where
        Id: Display + Send + Sync + 'static,
        Key: CapabilityKey,
        T: GrpcService<Body> + Clone + Send + Sync + 'static,
        T::Error: Into<StdError>,
        T::ResponseBody: ResponseBody<Data = Bytes> + Send + 'static,
        <T::ResponseBody as ResponseBody>::Error: Into<StdError> + Send,
        T::Future: Send,
        Self: Sized,
    {
        Arc::new(FgaUpkeep {
            shapes: Arc::clone(self.inner.shapes()),
            delegate: self.inner.inner().clone(),
            reach,
            naming: Arc::clone(&self.naming),
        })
    }

    /// Name one watcher as the model names it.
    fn named(&self, principal: &Arc<Principal<Id, Key>>) -> ModelSubject<Id, Key> {
        ModelSubject {
            principal: Arc::clone(principal),
            naming: Arc::clone(&self.naming),
        }
    }
}

impl<Id, Key, T> VisibilityPolicy for FgaAuth<Id, Key, T>
where
    Id: Display + Send + Sync,
    Key: CapabilityKey,
    T: GrpcService<Body> + Clone + Send + Sync + 'static,
    T::Error: Into<openfga_client::tonic::codegen::StdError>,
    T::ResponseBody: openfga_client::tonic::codegen::Body<Data = openfga_client::tonic::codegen::Bytes>
        + Send
        + 'static,
    <T::ResponseBody as openfga_client::tonic::codegen::Body>::Error:
        Into<openfga_client::tonic::codegen::StdError> + Send,
    T::Future: Send,
{
    type Watcher = Arc<Principal<Id, Key>>;
    type Error = OpenFgaError;
    type Backend = Postgres;

    fn may_see<R>(
        &self,
        row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> impl Future<Output = Result<(), OpenFgaError>> + Send
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        let named: Vec<_> = watchers.iter().map(|caller| self.named(caller)).collect();
        async move { self.inner.may_see(row, &named, verdicts).await }
    }

    fn may_write<R>(
        &self,
        write: RowWrite<'_, R>,
        watcher: &Self::Watcher,
    ) -> impl Future<Output = Result<Verdict, OpenFgaError>> + Send
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        let named = self.named(watcher);
        async move { self.inner.may_write(write, &named).await }
    }
}

impl<Id, Key, T> core::fmt::Debug for FgaAuth<Id, Key, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FgaAuth")
            .field("naming", &self.naming)
            .finish_non_exhaustive()
    }
}
// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

/// Why the server refused to start against its authorization model.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    /// The schema and policy documents did not parse as one catalog.
    #[error("catalog parse failed: {0}")]
    Catalog(String),
    /// A policy has no translation and the deployment supplied no mapping.
    ///
    /// Absolute rather than degrading per table, because dropping a clause
    /// **narrows**: a dropped permissive clause grants nothing and a dropped
    /// restrictive one becomes no access, so an untranslated policy makes rows
    /// vanish rather than leak. The snapshot runs on real row-level security
    /// and shows the row, then the change path withdraws it. Refusing to start
    /// is what stops a deployment discovering that by watching data disappear.
    #[error(
        "these policy expressions have no translation and no supplied mapping, so the \
         change path would withdraw rows the snapshot shows: {0}"
    )]
    Untranslated(String),
    /// The model could not be written to the authorization server.
    #[error("writing the authorization model: {0}")]
    Model(String),
    /// A tuple query, or the load it fed, failed.
    #[error("loading the authorization store: {0}")]
    Store(String),
    /// The index refused the questions the model would need.
    #[error(transparent)]
    Index(#[from] OpenFgaError),
    /// The generated rules could not be inverted into what each fact reaches.
    ///
    /// Refused for the same reason as an untranslated policy: a rule shape the
    /// walk cannot follow makes a withdrawal reach nobody, which leaves rows on
    /// a device and announces nothing (R7).
    #[error(transparent)]
    Reach(#[from] crate::reach::ReachError),
    /// A policy shape whose withdrawals cannot reach the store.
    ///
    /// Refused for the same reason as the two above, by a third cause. A shape
    /// whose records span more than the changed row reports nothing removed and
    /// hands over a query to re-run instead, and re-running it only ever writes
    /// what is still true. So deleting the row that carried a permission leaves
    /// that permission in the store, the change path answers from the store, and
    /// live delivery continues to somebody whose access has already gone (R49).
    ///
    /// **Revisit this when the upstream repair lands.** The refusal is as wide as
    /// the gap is today, not as wide as the gap has to be: four of the six shapes
    /// it covers read one table and look repairable by classifying them as
    /// settled, and once they are, refusing them costs a deployment a shape that
    /// became safe. `upstream/subql-joined-shape-never-removes.md` carries the
    /// finding and its reproduction.
    #[error(
        "these policy shapes keep their permissions current by re-running a query, which \
         never removes one, so a withdrawal would leave the store granting access the \
         database has taken away. Change the schema, or wait for the upstream repair that \
         will narrow this refusal: {0}"
    )]
    Unwithdrawable(String),
}

/// One translation, read once, so nothing downstream reads a second.
///
/// Every piece the executor needs comes from here: the recipes, the row
/// naming, the required parameters, the relations that answer each statement,
/// the model itself, and the SQL that fills the store. Two translations of one
/// schema could disagree, and every question would then name rows that do not
/// exist.
pub struct Translated {
    catalog: ParserDB,
    translator: Translator,
    relations: Vec<rls2fga::generator::relations::RelationShapes>,
    naming: Vec<rls2fga::generator::row_naming::RowNaming>,
    notes: Vec<rls2fga::generator::notes::TranslationNote>,
    answers: Vec<rls2fga::generator::action_relations::ActionRelations>,
    open: Vec<rls2fga::generator::unrestricted::UnrestrictedTable>,
    model: rls2fga::generator::json_model::AuthorizationModel,
    tuples: Vec<rls2fga::generator::tuple_generator::TupleQuery>,
    policy_tables: Vec<String>,
    reach: GrantReach,
}

impl Translated {
    /// Translate the deployment's policies over its schema, refusing anything
    /// the translator cannot express.
    ///
    /// The two documents are parsed as one catalog, because a policy is a
    /// catalog object and `DatabaseLike::policies()` is what reports it. The
    /// schema alone is what clients sync, so the split is by purpose rather
    /// than by content.
    ///
    /// **Declaring the two settings is what makes the local path fire.** A
    /// connetto policy compares a column against `current_setting`, and a
    /// translator told nothing about those keys refuses the whole arm: the
    /// model then grants the owner alone and every share holder is denied
    /// locally, silently, with the shared rows simply not arriving. `Key` names
    /// the share-key setting and `user_setting` names the identity one, which
    /// are the same two values [`CallerBinding`](crate::capability) binds for
    /// Postgres, so the two executors are told one thing.
    ///
    /// # Errors
    ///
    /// [`SetupError::Catalog`] when the two documents do not parse, and
    /// [`SetupError::Untranslated`] naming every expression left unhandled.
    pub fn of<Key: CapabilityKey>(
        schema_sql: &str,
        policy_sql: &str,
        user_setting: &str,
    ) -> Result<Self, SetupError> {
        let mut sql = String::with_capacity(schema_sql.len() + policy_sql.len() + 1);
        sql.push_str(schema_sql);
        sql.push('\n');
        sql.push_str(policy_sql);
        let catalog = ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(&sql)
            .map_err(|err| SetupError::Catalog(err.to_string()))?;
        let translator = rls2fga::translator::TranslatorBuilder::new()
            .with_min_confidence(rls2fga::classifier::patterns::ConfidenceLevel::B)
            .with_session_attributes([
                SessionAttribute::setting(user_setting, SessionAttributeKind::CallerId),
                SessionAttribute::setting(Key::SETTING, SessionAttributeKind::SetAttribute),
            ])
            .build();

        let translation = translator.translate(&catalog);
        let relations = translation.relations();
        let naming = translation.row_naming();
        let notes = translation.notes().to_vec();
        let answers = translation.action_relations();
        // Read beside the action report, never instead of it. A table the
        // database filters nothing on is answered nowhere else when the model
        // gives it no type, which is every table no policy reaches, and
        // delegating a question the model defines no type for cannot succeed.
        let open = translation.unrestricted_tables();

        // **`outputs()` alone is not step 6's refusal, and believing it was is
        // the defect this guard exists for.** It blocks only the `Unhandled`
        // severity. A policy the classifier read but graded below the caller's
        // confidence threshold comes back as a `BelowThreshold` note, the
        // clause is dropped, and `outputs()` hands over a model that denies
        // what the database grants. Proven against `mystery_function(owner)`,
        // which yields `ClauseBelowThreshold` at confidence D with an empty
        // `unhandled()` and `outputs()` returning `Ok`.
        //
        // The predicate is rls2fga's own, because it is the crate that knows
        // which of its severities mean the model and the database disagree,
        // and it is written there as a refusal rather than a list so a
        // severity added later counts as a disagreement until someone decides
        // otherwise.
        let diverging: Vec<String> = notes
            .iter()
            .filter(|note| note.severity().diverges_from_database())
            .map(|note| format!("{note:?}"))
            .collect();
        if !diverging.is_empty() {
            return Err(SetupError::Untranslated(diverging.join("; ")));
        }
        let outputs = translator
            .translate(&catalog)
            .outputs()
            .map_err(|unhandled| SetupError::Untranslated(unhandled.to_string()))?;
        let model = outputs.json_model();
        let tuples = outputs.tuple_queries();
        let policy_tables = policy_tables(&outputs);
        drop(outputs);
        // Walked here rather than where it is first read, so a model this
        // cannot follow refuses the boot beside every other startup refusal.
        let reach = GrantReach::of(&model, &naming, &answers)?;
        let unwithdrawable = unwithdrawable_shapes(&relations);
        if !unwithdrawable.is_empty() {
            return Err(SetupError::Unwithdrawable(unwithdrawable.join("; ")));
        }

        Ok(Self {
            catalog,
            translator,
            relations,
            naming,
            notes,
            answers,
            open,
            model,
            tuples,
            policy_tables,
            reach,
        })
    }

    /// The tables the policies read, for the publication check.
    ///
    /// A policy reading a table the change stream does not carry never hears
    /// that a grant was given or taken away, so the store goes stale and then
    /// answers confidently and wrongly.
    #[must_use]
    pub fn policy_tables(&self) -> &[String] {
        &self.policy_tables
    }

    /// The model to write to the authorization server.
    #[must_use]
    pub const fn model(&self) -> &rls2fga::generator::json_model::AuthorizationModel {
        &self.model
    }

    /// The queries whose rows fill the store, each with the shape its rows take.
    #[must_use]
    pub fn tuple_queries(&self) -> &[rls2fga::generator::tuple_generator::TupleQuery] {
        &self.tuples
    }

    /// The index every reader of this translation shares.
    #[must_use]
    pub fn shapes(self) -> Arc<Shapes<ParserDB>> {
        Arc::new(
            Shapes::new(self.catalog, &self.relations)
                .with_row_naming(&self.naming)
                .with_action_relations(&self.answers)
                .with_required_parameters(&self.notes)
                .with_unrestricted_tables(&self.open),
        )
    }

    /// Put this translation's rule description on the service, adopting the
    /// one already there when it is the same description.
    ///
    /// An unchanged description means the facts behind it were loaded on the
    /// boot that wrote it, so an ordinary restart reads one page and writes
    /// nothing. Comparison is structural, over the same conversion the write
    /// call itself uses, so a description that differs in any field the server
    /// stores is a new one.
    ///
    /// # Errors
    ///
    /// [`SetupError::Model`] when the service could not be read or refused the
    /// write.
    pub async fn install_model<T>(
        &self,
        client: &mut OpenFgaServiceClient<T>,
        store_id: &str,
    ) -> Result<ModelState, SetupError>
    where
        T: GrpcService<Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: ResponseBody<Data = Bytes> + Send + 'static,
        <T::ResponseBody as ResponseBody>::Error: Into<StdError> + Send,
    {
        let wanted = serde_json::to_value(&self.model)
            .and_then(serde_json::from_value::<ProtoModel>)
            .map_err(|err| SetupError::Model(err.to_string()))?;
        let latest = client
            .read_authorization_models(ReadAuthorizationModelsRequest {
                store_id: store_id.to_owned(),
                page_size: Some(1),
                continuation_token: String::new(),
            })
            .await
            .map_err(|status| SetupError::Model(status.message().to_owned()))?
            .into_inner();
        if let Some(held) = latest.authorization_models.first()
            && held.type_definitions == wanted.type_definitions
            && held.conditions == wanted.conditions
            && held.schema_version == wanted.schema_version
        {
            return Ok(ModelState::Adopted(held.id.clone()));
        }
        rls2fga::client::write_authorization_model(client, store_id, &self.model)
            .await
            .map(ModelState::Written)
            .map_err(|err| SetupError::Model(err.to_string()))
    }

    /// Run every query that produces a fact and hand the facts back.
    ///
    /// **Raw statements on purpose.** The SQL is emitted by `rls2fga` from the
    /// deployment's own policies, so there is no schema to express it against
    /// and no column list connetto could type. What is not guessed is the shape
    /// of a result row: `TupleQuery::condition` says whether it carries three
    /// columns or five, and `Outputs::record_from_tuple_row` reads it back, so
    /// the mapping lives in the crate that emitted the query.
    ///
    /// # Errors
    ///
    /// [`SetupError::Store`] when a query failed or a row it returned does not
    /// spell a fact the model holds.
    pub async fn load_records(
        &self,
        pool: &Pool<AsyncPgConnection>,
    ) -> Result<Vec<Record>, SetupError> {
        // Scoped rather than imported at module level: diesel's blanket `load`
        // and `first` shadow the slice methods the model lookup above uses.
        use diesel_async::RunQueryDsl as _;

        let outputs = self
            .translator
            .translate(&self.catalog)
            .outputs_accepting_gaps();
        let mut conn = pool
            .get()
            .await
            .map_err(|err| SetupError::Store(err.to_string()))?;
        let mut records = Vec::new();
        for query in &self.tuples {
            let rows = if query.condition.is_some() {
                let wide: Vec<WideRow> = sql_query(&query.sql)
                    .load(&mut *conn)
                    .await
                    .map_err(|err| SetupError::Store(err.to_string()))?;
                TupleRows::Conditional(wide)
            } else {
                let plain: Vec<PlainRow> = sql_query(&query.sql)
                    .load(&mut *conn)
                    .await
                    .map_err(|err| SetupError::Store(err.to_string()))?;
                TupleRows::Plain(plain)
            };
            rows.read_into(&outputs, &mut records)?;
        }
        Ok(records)
    }

    /// The index every reader shares, the translator the materializer's engine
    /// classifies with, and what each kind of fact reaches.
    ///
    /// Handed over together because the three must describe one schema: the
    /// index keeps the catalog and lends it, the translator reads that same
    /// catalog, and the reach index was walked over the model built from it, so
    /// nothing downstream can hold a second opinion about the deployment's
    /// policies.
    #[must_use]
    pub fn into_parts(self) -> (Arc<Shapes<ParserDB>>, Translator, GrantReach) {
        let translator = self.translator;
        let reach = self.reach;
        let shapes = Arc::new(
            Shapes::new(self.catalog, &self.relations)
                .with_row_naming(&self.naming)
                .with_action_relations(&self.answers)
                .with_required_parameters(&self.notes)
                .with_unrestricted_tables(&self.open),
        );
        (shapes, translator, reach)
    }
}

/// One query's rows, in whichever shape it projects.
enum TupleRows {
    /// Three columns, no condition.
    Plain(Vec<PlainRow>),
    /// Five columns, the last two naming a condition and its context.
    Conditional(Vec<WideRow>),
}

impl TupleRows {
    /// Read every row back as the fact it spells, appending to `records`.
    ///
    /// The reader belongs to the crate that emitted the query, so what a column
    /// means is stated once rather than guessed here.
    fn read_into<DB: subql::DatabaseLike>(
        &self,
        outputs: &rls2fga::translator::Outputs<'_, DB>,
        records: &mut Vec<Record>,
    ) -> Result<(), SetupError> {
        let read = |row: TupleRow<'_>| {
            outputs
                .record_from_tuple_row(row)
                .map_err(|err| SetupError::Store(err.to_string()))
        };
        match self {
            Self::Plain(rows) => {
                for row in rows {
                    records.push(read(TupleRow {
                        object: &row.object,
                        relation: &row.relation,
                        subject: &row.subject,
                        condition: None,
                    })?);
                }
            }
            Self::Conditional(rows) => {
                // Rendered up front so each borrow outlives the row view.
                let contexts: Vec<String> =
                    rows.iter().map(|row| row.context.to_string()).collect();
                for (index, row) in rows.iter().enumerate() {
                    records.push(read(TupleRow {
                        object: &row.object,
                        relation: &row.relation,
                        subject: &row.subject,
                        condition: Some(TupleCondition {
                            name: &row.condition,
                            context: &contexts[index],
                        }),
                    })?);
                }
            }
        }
        Ok(())
    }
}

/// Whether the service already described these rules.
///
/// The distinction is the whole of decision 4: an unchanged description means
/// the facts behind it are already loaded, so a restart costs one lookup
/// whatever the data volume, and a new one means the store has nothing for it
/// yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelState {
    /// The service already held this exact description, under this id.
    Adopted(String),
    /// The description was written now, so the facts have to follow.
    Written(String),
}

impl ModelState {
    /// The id every question is asked against.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Adopted(id) | Self::Written(id) => id,
        }
    }
}

/// One row of a tuple query, owned, as the generated SQL projects it.
///
/// Five columns or three, and which it is comes off
/// `TupleQuery::condition` rather than out of the SQL, so a loader knows the
/// shape without parsing anything.
#[derive(Debug, QueryableByName)]
struct WideRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
    #[diesel(sql_type = Text)]
    condition: String,
    /// **`jsonb`, not text, and reading it as text is silently wrong.** Postgres
    /// hands a `jsonb` column over in its binary form, whose first byte is a
    /// format version, so a text binding yields a leading `\u{1}` and the
    /// record reader refuses the row for a reason that names the value rather
    /// than the binding.
    #[diesel(sql_type = Jsonb)]
    context: serde_json::Value,
}

/// The same, for a query that names no condition.
#[derive(Debug, QueryableByName)]
struct PlainRow {
    #[diesel(sql_type = Text)]
    object: String,
    #[diesel(sql_type = Text)]
    relation: String,
    #[diesel(sql_type = Text)]
    subject: String,
}

/// Every table a policy expression reads, deduplicated and sorted.
///
/// Read off the descriptions the translation carries rather than off
/// `rls2fga`'s refusal path, so a policy that failed to translate cannot leave
/// a hole in the safety net exactly where one is most wanted. Nothing reaches
/// here until [`Translated::of`] has refused an untranslated policy.
fn policy_tables<DB: subql::DatabaseLike>(
    outputs: &rls2fga::translator::Outputs<'_, DB>,
) -> Vec<String> {
    let mut tables: Vec<String> = outputs
        .tuple_queries()
        .iter()
        .filter_map(|query| query.description.as_ref())
        .flat_map(|description| description.tables.iter().cloned())
        .collect();
    tables.sort_unstable();
    tables.dedup();
    tables
}

/// Every shape whose facts travel as a query to re-run, named for the refusal.
///
/// **One question rather than a classification connetto invents.** Whether a
/// shape carries a re-run query is exactly whether its withdrawals can reach the
/// store, because the re-run is the only path its facts take and that path only
/// writes. Naming a narrower set would mean deciding upstream's business here,
/// off a reason string.
///
/// Read off the relation descriptions rather than off `Shapes`, which indexes the
/// same thing but keeps it private, and which is built after this has already
/// refused.
fn unwithdrawable_shapes(
    relations: &[rls2fga::generator::relations::RelationShapes],
) -> Vec<String> {
    let mut named = Vec::new();
    for entry in relations {
        for shape in &entry.shapes {
            if let RecordDerivation::Joined { reason, .. } = &shape.derivation {
                named.push(format!(
                    "{}#{} over {} ({reason})",
                    entry.type_name,
                    entry.relation,
                    shape.tables.join(", ")
                ));
            }
        }
    }
    named.sort_unstable();
    named.dedup();
    named
}

// ---------------------------------------------------------------------------
// Keeping the store current
// ---------------------------------------------------------------------------

/// Why one changed row did not reach the authorization store.
///
/// Every variant means the store now describes a world that has moved, so a
/// caller treats one as it treats an unreachable service: hold the event
/// rather than deliver against facts that are no longer true.
#[derive(Debug, thiserror::Error)]
pub enum UpkeepError {
    /// What the row moved could not be worked out.
    #[error("what the changed row moved could not be worked out: {0}")]
    Diff(String),
    /// The store refused the write.
    #[error("writing the difference to the authorization store: {0}")]
    Write(String),
}

/// One authorization fact that moved, and who it concerned.
///
/// What the watcher hands the session layer: the tables whose read answer
/// depends on the fact, and who to tell. The fact itself does not travel,
/// because nothing downstream can do anything with it (R7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantMove {
    /// Tables whose read answer depends on the fact that moved.
    ///
    /// **Never the table the change arrived on.** R6's two-check form already
    /// takes that one row away from the callers who lost it, precisely, so
    /// resyncing there would replace a whole subscription over a change one
    /// delete covers (R7 decision 6).
    pub tables: Vec<String>,
    /// Who the fact concerned.
    pub holder: GrantHolder,
}

/// Who a moved fact concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantHolder {
    /// One identity, spelled as the deployment spells it, with the model's type
    /// prefix taken off so the session layer compares it against the identity
    /// it already holds.
    Person(String),
    /// Everybody subscribed to the reached tables. A wildcard subject, whether
    /// or not a condition narrows it, and any subject connetto cannot resolve to
    /// a person: wider than necessary never leaves a row on a device, and
    /// narrower silently does.
    Everybody,
}

/// Bring the authorization store level with one changed row, before that row
/// reaches anybody, and report what moved.
///
/// **The ordering is the point and it is upstream's, not a preference.** Until
/// the difference is written the store still holds the facts from before the
/// change, so a question about any row those facts reach is answered from a
/// world that has moved. Answering late costs a row delivered late. Answering
/// early hands a row to somebody whose access has already gone, and no later
/// correction takes it back.
///
/// Object-safe on purpose: the session layer is generic over its policy and
/// most policies keep no store, so this is a collaborator it may or may not
/// hold rather than a bound every test double has to satisfy.
pub trait StoreUpkeep: Send + Sync {
    /// Apply what `event` moved, and do not return until it is applied.
    ///
    /// The returned moves are what the session layer resyncs on. An empty
    /// vector means nothing about who can reach what changed outside the table
    /// the event arrived on.
    fn keep_current<'a>(
        &'a self,
        event: &'a subql::ChangeEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<GrantMove>, UpkeepError>> + Send + 'a>>;
}

/// The upkeep behind [`FgaAuth`], over the same index it answers from.
struct FgaUpkeep<Id, Key, T> {
    shapes: Arc<Shapes<ParserDB>>,
    delegate: OpenFgaPolicy<ParserDB, T, ModelSubject<Id, Key>, Postgres>,
    /// What each kind of fact reaches, walked once at startup.
    reach: GrantReach,
    /// How the model spells a person, so a subject can be read back as the
    /// identity a live session carries.
    naming: Arc<SubjectNaming>,
}

impl<Id, Key, T> StoreUpkeep for FgaUpkeep<Id, Key, T>
where
    Id: Display + Send + Sync,
    Key: CapabilityKey,
    T: GrpcService<Body> + Clone + Send + Sync + 'static,
    T::Error: Into<StdError>,
    T::ResponseBody: ResponseBody<Data = Bytes> + Send + 'static,
    <T::ResponseBody as ResponseBody>::Error: Into<StdError> + Send,
    T::Future: Send,
{
    fn keep_current<'a>(
        &'a self,
        event: &'a subql::ChangeEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<GrantMove>, UpkeepError>> + Send + 'a>> {
        Box::pin(async move {
            let diff = match self.shapes.diff(event) {
                Ok(diff) => diff,
                // A truncate names no row, so nothing single-row moved and
                // there is nothing here to apply. Everything else means the
                // difference is not knowable, which is not the same as empty.
                Err(StoreDiffError::NotARowEvent) => return Ok(Vec::new()),
                Err(err) => return Err(UpkeepError::Diff(err.to_string())),
            };
            self.delegate
                .apply(&diff)
                .await
                .map_err(|err| UpkeepError::Write(err.to_string()))?;
            // Read after the store is level, never before: a replacement
            // snapshot produced against the old facts would hand back exactly
            // the rows the change took away.
            Ok(self.moved(event, &diff))
        })
    }
}

impl<Id, Key, T> FgaUpkeep<Id, Key, T> {
    /// What this difference changed about who can reach what, outside the table
    /// the change arrived on.
    ///
    /// A grant given counts as much as a grant taken away: rows the caller may
    /// now see exist already and no row event will announce them, so only a
    /// replacement carries them.
    fn moved(&self, event: &subql::ChangeEvent, diff: &StoreDiff<'_, Postgres>) -> Vec<GrantMove> {
        use subql::backend::CdcEvent as _;

        let catalog = self.shapes.catalog();
        let arrived_on = subql::catalog_helpers::table_name(catalog, event.table_id(catalog))
            .unwrap_or_default();
        let mut moves: Vec<GrantMove> = Vec::new();
        for record in diff.added.iter().chain(diff.removed.iter()) {
            let tables: Vec<String> = self
                .reach
                .tables_for(&record.object, record.relation.as_str())
                .iter()
                .filter(|table| **table != arrived_on)
                .cloned()
                .collect();
            if tables.is_empty() {
                continue;
            }
            let holder = self.naming.holder(&record.subject);
            let candidate = GrantMove { tables, holder };
            // Two records of one kind about one person say one thing, and a
            // shape emitting a record per element of a list column emits many.
            if !moves.contains(&candidate) {
                moves.push(candidate);
            }
        }
        moves
    }
}

#[cfg(test)]
mod tests {
    use rls2fga::generator::action_relations::ActionStatement;
    use subql::catalog_helpers;

    use super::{SubjectNaming, Translated};
    use crate::capability::DEFAULT_USER_SETTING;

    /// The shape every connetto table carries: one permissive policy whose
    /// `USING` is the caller's identity or the keys the caller holds.
    ///
    /// Taken from the fixtures that already exist rather than invented, so this
    /// asserts about what deployments actually write:
    /// `connetto-server/tests/rls_write_filter.rs` and
    /// `connetto-test-harness/tests/capability_live.rs` both write it.
    const OWN_SHAPE: &str = "CREATE POLICY notes_p ON notes FOR ALL USING (\
        owner = current_setting('app.user_id', true) \
        OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')))";

    /// A policy that has to read another table, which one row never settles.
    const CROSS_TABLE: &str = "CREATE POLICY docs_p ON docs FOR SELECT USING (\
        EXISTS (SELECT 1 FROM memberships \
                WHERE memberships.team = docs.team \
                  AND memberships.member = current_setting('app.user_id', true)))";

    const SCHEMA: &str = "
        CREATE TABLE notes(id INTEGER PRIMARY KEY, owner TEXT);
        ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
        CREATE TABLE memberships(team INTEGER, member TEXT, PRIMARY KEY(team, member));
        CREATE TABLE docs(id INTEGER PRIMARY KEY, team INTEGER);
        ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    ";

    fn translated(policies: &str) -> Translated {
        Translated::of::<String>(SCHEMA, policies, DEFAULT_USER_SETTING)
            .expect("every policy here is one rls2fga classifies")
    }

    /// **This is the phase's central claim, and it is the half that can be
    /// wrong in the expensive direction.** Decision 1 accepted a criterion of
    /// exactly zero round trips for connetto's own policy shape, and that rests
    /// entirely on the schema settling the relation. If this reads false, the
    /// counter test cannot assert zero and the criterion has to be restated
    /// again.
    ///
    /// Mutation-tested: dropping the `with_session_attributes` declaration in
    /// [`Translated::of`] makes it fail, which is the defect it guards, because
    /// a translator told nothing about `current_setting` refuses the held-key
    /// arm and the relation stops being decidable.
    #[test]
    fn connettos_own_policy_shape_is_answered_without_a_round_trip() {
        let shapes = translated(OWN_SHAPE).shapes();
        let notes =
            catalog_helpers::table_id(shapes.catalog(), "notes").expect("notes is in the catalog");
        assert!(
            shapes.answers_locally(notes, ActionStatement::Select),
            "the identity arm and the held-key arm are both read from the row, \
             so no watcher costs a round trip"
        );
    }

    /// The other half of the same criterion: a policy the row cannot settle is
    /// honestly delegated rather than answered cheaply and wrongly. Answering
    /// this one locally would be a wrong allow, which is the error class the
    /// whole phase exists to remove.
    #[test]
    fn a_policy_reading_another_table_is_not_answered_locally() {
        let shapes = translated(CROSS_TABLE).shapes();
        let docs =
            catalog_helpers::table_id(shapes.catalog(), "docs").expect("docs is in the catalog");
        assert!(
            !shapes.answers_locally(docs, ActionStatement::Select),
            "whether the caller is a member of the row's team is not in the row"
        );
    }

    /// The parameter a watcher answers to is read from the translation, never
    /// spelled twice. Getting it wrong is silent: a question missing a required
    /// parameter is refused by the server rather than answered, so the watcher
    /// is denied with nothing naming the cause.
    #[test]
    fn the_share_key_parameter_is_read_from_the_translation() {
        let shapes = translated(OWN_SHAPE).shapes();
        let naming = SubjectNaming::resolve::<String>(&shapes);
        assert!(
            naming.asks_the_caller(),
            "the held-key arm is a grant the caller's own values complete, so the \
             translation must report a parameter for it"
        );
    }

    /// A table the deployment put no policy on at all.
    ///
    /// Postgres shows every row of it to everybody, so the model has to agree.
    /// Disagreeing here is the vanish direction: the snapshot shows the row and
    /// the change path withholds it, which is the failure the startup refusal
    /// exists to prevent and which no error would announce.
    ///
    /// **This is the shape the browser demo's own table has**, and it took both
    /// upstreams to answer. `rls2fga` reports such a table positively, and
    /// `subql` gained the builder that can be told, since the answer is keyed
    /// by the type the model gives a table and a table no policy reaches gets
    /// none.
    #[test]
    fn a_table_with_no_policy_at_all_grants_everybody_without_a_round_trip() {
        let shapes = Translated::of::<String>(
            "CREATE TABLE orders (id INT PRIMARY KEY, quantity BIGINT NOT NULL);",
            "",
            DEFAULT_USER_SETTING,
        )
        .expect("a schema with no policy has nothing to refuse")
        .shapes();
        let orders = catalog_helpers::table_id(shapes.catalog(), "orders")
            .expect("orders is in the catalog");
        assert!(
            shapes.answers_locally(orders, ActionStatement::Select),
            "row-level security is off, so the database restricts nothing and \
             there is nothing to ask anybody"
        );
    }

    /// Step 6's refusal, which is absolute rather than degrading per table.
    #[test]
    fn a_policy_with_no_translation_refuses_startup() {
        let refused = Translated::of::<String>(
            SCHEMA,
            "CREATE POLICY notes_p ON notes FOR ALL USING (mystery_function(owner))",
            DEFAULT_USER_SETTING,
        );
        assert!(
            matches!(refused, Err(super::SetupError::Untranslated(_))),
            "an expression rls2fga cannot read must stop the server rather than \
             quietly narrow what the change path delivers"
        );
    }

    /// A share written as a row of a join table, whose facts travel as a query
    /// to re-run.
    ///
    /// Row-level security stays off `paper_shares` on purpose: the guarded form
    /// is refused by the translator for a different reason, and the unguarded
    /// one is what reaches this refusal.
    const SHARE_SCHEMA: &str = "
        CREATE TABLE papers(id INTEGER PRIMARY KEY, owner TEXT);
        ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
        CREATE TABLE paper_shares(paper_id INTEGER, viewer TEXT, PRIMARY KEY(paper_id, viewer));
    ";

    const SHARE_POLICY: &str = "CREATE POLICY papers_p ON papers FOR SELECT USING (\
        owner = current_setting('app.user_id', true) \
        OR EXISTS (SELECT 1 FROM paper_shares s WHERE s.paper_id = papers.id \
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))))";

    /// R49's refusal, which is the leak direction rather than the vanish one.
    ///
    /// Deleting the share row leaves the grant in the store, so the change path
    /// keeps delivering to a caller whose access has gone. Measured before the
    /// refusal existed: the key holder was still allowed after the row was gone,
    /// against a real Postgres and a real `OpenFGA`, and `Shapes::diff` reported
    /// nothing removed, one query to re-run, and nothing uncovered.
    #[test]
    fn a_share_written_as_a_join_table_row_refuses_startup() {
        let refusal =
            match Translated::of::<String>(SHARE_SCHEMA, SHARE_POLICY, DEFAULT_USER_SETTING) {
                Err(super::SetupError::Unwithdrawable(named)) => {
                    assert!(
                        named.contains("paper_shares"),
                        "the refusal names the table whose changes cannot be turned into a \
                     removal, or an operator cannot find the policy to change: {named}"
                    );
                    super::SetupError::Unwithdrawable(named)
                }
                Err(other) => panic!("refused, but for the wrong reason: {other}"),
                Ok(_) => panic!(
                    "a withdrawal on this shape reaches nothing, so it must stop the \
                 server rather than serve access the database has taken away"
                ),
            };
        // The refusal is as wide as the gap is today rather than as wide as it has
        // to be, so the message says the boot will start working again. An
        // operator reading only the sentence above concludes the shape is
        // permanently unsupported and rewrites a schema that did not need it.
        let shown = refusal.to_string();
        assert!(
            shown.contains("upstream repair"),
            "the message an operator sees has to say the refusal narrows later, \
             not only the rustdoc they never read: {shown}"
        );
    }
}
