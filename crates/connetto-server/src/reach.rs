//! Which tables a moved authorization fact reaches (R7).
//!
//! A withdrawn grant is a Postgres row change, and the fact it moves rarely
//! hangs on the table whose rows disappear. A membership row deleted from
//! `team_members` moves `teams:1#member@user:alice`, while the rows the caller
//! loses are in `items`, because the generated rules define `items.can_select`
//! as whoever is a member of the row's team. The link between the two exists
//! only in those rules, so this walks them once at startup and inverts the
//! result: per kind of fact, the tables whose read answer depends on it.
//!
//! **A rule shape the walk does not recognise refuses the boot.** Widening
//! instead would turn a hole in the teardown into extra traffic rather than a
//! startup failure, and the hole is silent in the direction that leaves rows on
//! a device. The same call `Translated::of` already makes for a policy it cannot
//! translate.

use std::collections::{BTreeSet, HashMap, HashSet};

use rls2fga::generator::action_relations::{ActionAnswer, ActionRelations, ActionStatement};
use rls2fga::generator::json_model::{AuthorizationModel, TypeDefinition, Userset};
use rls2fga::generator::row_naming::RowNaming;

/// Why the generated rules could not be turned into a reach index.
#[derive(Debug, thiserror::Error)]
pub enum ReachError {
    /// A relation the answer report names is not defined on its type, so what
    /// the read depends on cannot be followed.
    #[error(
        "the rules answer a read on {type_name} with {relation}, which the model does not define"
    )]
    UndefinedRelation {
        /// Type the relation was expected on.
        type_name: String,
        /// Relation the rules named.
        relation: String,
    },
    /// A tupleset relation carries no metadata, so the types it reaches are
    /// unknown and the walk cannot follow it.
    #[error(
        "the tupleset {type_name}#{relation} declares no related types, so what it reaches cannot be followed"
    )]
    UndeclaredTupleset {
        /// Type the tupleset is defined on.
        type_name: String,
        /// The tupleset relation.
        relation: String,
    },
    /// An answer shape the walk does not know. Refused rather than skipped: a
    /// shape treated as reaching nothing leaves rows on a device.
    #[error("the rules answer a read on {type_name} in a shape this cannot follow: {answer}")]
    UnknownAnswer {
        /// Type the answer belongs to.
        type_name: String,
        /// The answer, as reported.
        answer: String,
    },
}

/// The kind of fact one record is: the type it hangs on and the relation it
/// fills. Two facts of the same kind reach the same tables whatever row they
/// name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct FactKind {
    type_name: String,
    relation: String,
}

/// Per kind of fact, the tables whose read answer depends on it.
///
/// Built once at startup by [`GrantReach::of`] and read per changed row.
#[derive(Debug, Default)]
pub struct GrantReach {
    reached: HashMap<FactKind, Vec<String>>,
}

impl GrantReach {
    /// Walk the generated rules and invert them.
    ///
    /// `answers` is the per-type answer report, `naming` maps each typed table
    /// to its type, and `model` is the rule set itself.
    ///
    /// # Errors
    ///
    /// [`ReachError`] when a rule or an answer cannot be followed. Every
    /// variant means some table's dependencies are unknown, which would leave
    /// the teardown silently narrow.
    pub fn of(
        model: &AuthorizationModel,
        naming: &[RowNaming],
        answers: &[ActionRelations],
    ) -> Result<Self, ReachError> {
        let types: HashMap<&str, &TypeDefinition> = model
            .type_definitions
            .iter()
            .map(|definition| (definition.type_name.as_str(), definition))
            .collect();
        let mut reached: HashMap<FactKind, BTreeSet<String>> = HashMap::new();
        for entry in answers {
            if entry.statement != ActionStatement::Select {
                continue;
            }
            let type_name = entry.type_name.to_string();
            // A type nothing keys rows on cannot be subscribed to, so nothing
            // depends on it through a subscription.
            let tables: Vec<&str> = naming
                .iter()
                .filter(|named| named.type_name == type_name)
                .map(|named| named.table.as_str())
                .collect();
            if tables.is_empty() {
                continue;
            }
            let mut depends = HashSet::new();
            let mut seen = HashSet::new();
            for relation in read_relations(entry)? {
                walk_relation(&types, &type_name, &relation, &mut seen, &mut depends)?;
            }
            for kind in depends {
                let entry = reached.entry(kind).or_default();
                for table in &tables {
                    entry.insert((*table).to_owned());
                }
            }
        }
        Ok(Self {
            reached: reached
                .into_iter()
                .map(|(kind, tables)| (kind, tables.into_iter().collect()))
                .collect(),
        })
    }

    /// The tables whose read answer depends on a fact of this kind.
    ///
    /// `object` is a record's object as the model renders it, `type:key`, so
    /// the type is read off it rather than spelled twice.
    #[must_use]
    pub fn tables_for(&self, object: &str, relation: &str) -> &[String] {
        let Some((type_name, _)) = object.split_once(':') else {
            return &[];
        };
        self.reached
            .get(&FactKind {
                type_name: type_name.to_owned(),
                relation: relation.to_owned(),
            })
            .map_or(&[], Vec::as_slice)
    }
}

/// The relations a read answer says must grant.
fn read_relations(entry: &ActionRelations) -> Result<Vec<String>, ReachError> {
    match &entry.answer {
        ActionAnswer::Judged(judgements) => Ok(judgements
            .iter()
            .map(|judgement| judgement.relation.to_string())
            .collect()),
        // The database restricts nothing here, so no grant reaches it, and the
        // model refusing every row means no grant changes what is delivered.
        ActionAnswer::Unrestricted | ActionAnswer::Denied => Ok(Vec::new()),
        ActionAnswer::NotSeparable { relation } => Ok(vec![relation.to_string()]),
        other => Err(ReachError::UnknownAnswer {
            type_name: entry.type_name.to_string(),
            answer: format!("{other:?}"),
        }),
    }
}

/// Follow one named relation, collecting every kind of fact it rests on.
fn walk_relation(
    types: &HashMap<&str, &TypeDefinition>,
    type_name: &str,
    relation: &str,
    seen: &mut HashSet<FactKind>,
    depends: &mut HashSet<FactKind>,
) -> Result<(), ReachError> {
    let kind = FactKind {
        type_name: type_name.to_owned(),
        relation: relation.to_owned(),
    };
    // A recursive model names its own relation again, so the visited set is
    // what makes this terminate rather than an assumption about depth.
    if !seen.insert(kind.clone()) {
        return Ok(());
    }
    let rule = types
        .get(type_name)
        .and_then(|definition| definition.relations.as_ref())
        .and_then(|relations| {
            relations
                .iter()
                .find(|(name, _)| name.as_str() == relation)
                .map(|(_, rule)| rule)
        })
        .ok_or_else(|| ReachError::UndefinedRelation {
            type_name: type_name.to_owned(),
            relation: relation.to_owned(),
        })?;
    walk_userset(types, type_name, relation, rule, seen, depends)
}

/// Follow one rule, which may be anonymous inside a union or a difference.
///
/// `relation` is the named relation the rule defines, needed because a direct
/// assignment and a tupleset are both facts on that name.
fn walk_userset(
    types: &HashMap<&str, &TypeDefinition>,
    type_name: &str,
    relation: &str,
    rule: &Userset,
    seen: &mut HashSet<FactKind>,
    depends: &mut HashSet<FactKind>,
) -> Result<(), ReachError> {
    match rule {
        // Facts land directly on this relation, so this is a leaf worth
        // recording.
        Userset::This { .. } => {
            depends.insert(FactKind {
                type_name: type_name.to_owned(),
                relation: relation.to_owned(),
            });
            Ok(())
        }
        Userset::ComputedUserset { computed_userset } => walk_relation(
            types,
            type_name,
            computed_userset.relation.as_str(),
            seen,
            depends,
        ),
        Userset::TupleToUserset { tuple_to_userset } => {
            let tupleset = tuple_to_userset.tupleset.relation.as_str();
            // The tupleset holds facts of its own: `items:1#teams@teams:1` is
            // what makes the row point at its team, so a change to it moves
            // what the caller may see just as the membership does.
            walk_relation(types, type_name, tupleset, seen, depends)?;
            let related = types
                .get(type_name)
                .and_then(|definition| definition.metadata.as_ref())
                .map(|metadata| {
                    metadata
                        .relations
                        .iter()
                        .filter(|(name, _)| name.as_str() == tupleset)
                        .flat_map(|(_, meta)| meta.directly_related_user_types.iter())
                        .map(|reference| reference.type_name.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if related.is_empty() {
                return Err(ReachError::UndeclaredTupleset {
                    type_name: type_name.to_owned(),
                    relation: tupleset.to_owned(),
                });
            }
            for target in related {
                walk_relation(
                    types,
                    &target,
                    tuple_to_userset.computed_userset.relation.as_str(),
                    seen,
                    depends,
                )?;
            }
            Ok(())
        }
        Userset::Union { union } => {
            for child in &union.child {
                walk_userset(types, type_name, relation, child, seen, depends)?;
            }
            Ok(())
        }
        Userset::Intersection { intersection } => {
            for child in &intersection.child {
                walk_userset(types, type_name, relation, child, seen, depends)?;
            }
            Ok(())
        }
        // Both sides count. Removing a fact from the subtracted side grants
        // access, which changes what the caller sees exactly as adding one to
        // the base does.
        Userset::Difference { difference } => {
            walk_userset(types, type_name, relation, &difference.base, seen, depends)?;
            walk_userset(
                types,
                type_name,
                relation,
                &difference.subtract,
                seen,
                depends,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::GrantReach;
    use crate::capability::DEFAULT_USER_SETTING;
    use crate::openfga::Translated;

    /// The harness's own cross-table shape, which is what this phase exists
    /// for: the grant is a membership row and the rows that vanish are in
    /// another table entirely.
    const CROSS_TABLE: (&str, &str) = (
        "CREATE TABLE teams (id INT PRIMARY KEY);
         CREATE TABLE team_members (team_id INT REFERENCES teams(id), member TEXT NOT NULL, \
           PRIMARY KEY (team_id, member));
         CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL, \
           team_id INT NOT NULL REFERENCES teams(id), label TEXT);
         ALTER TABLE items ENABLE ROW LEVEL SECURITY;",
        "CREATE POLICY items_p ON items FOR SELECT USING (\
           EXISTS (SELECT 1 FROM team_members \
                   WHERE team_members.team_id = items.team_id \
                     AND team_members.member = current_setting('app.user_id', true)));",
    );

    fn reach(shape: (&str, &str)) -> GrantReach {
        Translated::of::<String>(shape.0, shape.1, DEFAULT_USER_SETTING)
            .expect("the shape translates")
            .into_parts()
            .2
    }

    /// **The central claim.** A membership fact hangs on the team, and the
    /// walk has to say `items`, because that is where the rows are. Reading
    /// the fact's own table instead yields `teams`, which nobody subscribes
    /// to, and the withdrawal then reaches nobody.
    #[test]
    fn a_membership_fact_reaches_the_guarded_table() {
        let reach = reach(CROSS_TABLE);
        assert_eq!(
            reach.tables_for("teams:1", "member"),
            ["items".to_owned()],
            "items.can_select is defined through the team's member relation"
        );
    }

    /// The tupleset carries facts too: the row's own pointer at its team. A
    /// row moved between teams is an `items` row change, so R6 covers the
    /// delivery, but the dependency is real and the index must report it.
    #[test]
    fn the_rows_own_pointer_at_its_team_also_reaches_it() {
        let reach = reach(CROSS_TABLE);
        assert_eq!(reach.tables_for("items:1", "teams"), ["items".to_owned()]);
    }

    /// A fact of a kind no read answer depends on reaches nothing, so an
    /// unrelated grant table costs no resync.
    #[test]
    fn an_unrelated_fact_reaches_nothing() {
        let reach = reach(CROSS_TABLE);
        assert_eq!(
            reach.tables_for("teams:1", "can_delete"),
            Vec::<String>::new(),
            "no read answer depends on can_delete"
        );
        assert_eq!(
            reach.tables_for("nothing:1", "member"),
            Vec::<String>::new(),
            "nothing is not a type any rule names"
        );
        assert_eq!(
            reach.tables_for("malformed", "member"),
            Vec::<String>::new(),
            "an object id with no type prefix names nothing"
        );
    }

    /// Parent inheritance, which is the same indirection one hop further out:
    /// the owner fact hangs on the folder and the rows are in `notes`. The
    /// folder is itself subscribable, so both tables answer.
    #[test]
    fn an_inherited_grant_reaches_the_child_table() {
        let reach = reach((
            "CREATE TABLE folders(id INT PRIMARY KEY, owner TEXT);
             CREATE TABLE notes(id INT PRIMARY KEY, folder_id INT REFERENCES folders(id), \
               body TEXT);
             ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
             ALTER TABLE notes ENABLE ROW LEVEL SECURITY;",
            "CREATE POLICY folders_p ON folders FOR SELECT USING (\
               owner = current_setting('app.user_id', true));
             CREATE POLICY notes_p ON notes FOR SELECT USING (\
               EXISTS (SELECT 1 FROM folders f WHERE f.id = notes.folder_id \
                 AND f.owner = current_setting('app.user_id', true)));",
        ));
        assert_eq!(
            reach.tables_for("folders:1", "owner"),
            ["folders".to_owned(), "notes".to_owned()],
            "the folder's owner fact decides both its own rows and its notes"
        );
    }

    /// The shape every connetto table carries: both arms read from the guarded
    /// row, so its facts reach only that table. Nothing is left for this phase
    /// to do there, which is decision 6, and the index says so plainly.
    #[test]
    fn a_row_local_grant_reaches_only_its_own_table() {
        let reach = reach((
            "CREATE TABLE items(id INT PRIMARY KEY, owner TEXT NOT NULL, label TEXT);
             ALTER TABLE items ENABLE ROW LEVEL SECURITY;",
            "CREATE POLICY items_p ON items FOR ALL USING (\
               owner = current_setting('app.user_id', true) \
               OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')));",
        ));
        assert_eq!(reach.tables_for("items:1", "owner"), ["items".to_owned()]);
    }

    /// A table the rules refuse for every row has nothing to resync.
    ///
    /// A self-referential read policy is what produces this: measured
    /// 2026-08-16, `rls2fga` reduces it to `can_select: no_access`, so the
    /// answer report says the statement is denied and no grant change can alter
    /// what is delivered. Reporting a table here instead would resync every
    /// subscriber of it on any fact that moved, for a set that is empty either
    /// way.
    ///
    /// **The walk's own cycle guard is not what this pins.** Nothing `rls2fga`
    /// emits today names a relation that reaches itself, so the visited set is
    /// defensive: the model format allows the shape, and building one by hand
    /// here is not possible because `RelationName` cannot be constructed
    /// outside its own crate.
    #[test]
    fn a_table_the_rules_refuse_entirely_reaches_nothing() {
        let reach = reach((
            "CREATE TABLE docs(id INT PRIMARY KEY, parent_id INT REFERENCES docs(id), \
               owner TEXT);
             ALTER TABLE docs ENABLE ROW LEVEL SECURITY;",
            "CREATE POLICY docs_p ON docs FOR SELECT USING (\
               owner = current_setting('app.user_id', true) \
               OR EXISTS (SELECT 1 FROM docs p WHERE p.id = docs.parent_id \
                 AND p.owner = current_setting('app.user_id', true)));",
        ));
        assert!(
            reach.tables_for("docs:1", "owner").is_empty(),
            "the rules deny every row of this table, so no fact about it changes \
             what any subscriber receives"
        );
        assert_eq!(
            reach.tables_for("docs:1", "no_access"),
            Vec::<String>::new(),
            "and neither does a relation the rules never mention"
        );
    }
}
