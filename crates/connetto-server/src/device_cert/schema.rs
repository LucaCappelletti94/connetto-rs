//! The deployment's enrolment tables (R74 decisions 17, 26, 27 and 28).
//!
//! connetto owns no schema. A deployment declares three tables and names them
//! through [`ConnettoEnrolmentSchema`], by hand or through
//! [`connetto_schema!`](crate::connetto_schema), as the `Enrolments` member of
//! its [`ConnettoSchema`](crate::schema::ConnettoSchema). The member runs one
//! statement per function, and [`pg_enrolment_store`] composes them inside one
//! transaction and takes every decision itself.
//!
//! ```sql
//! CREATE TABLE connetto_device_enrolments (
//!     key_id BYTEA PRIMARY KEY,
//!     user_id TEXT NOT NULL,
//!     session_id UUID NOT NULL,
//!     enrolled_at TIMESTAMPTZ NOT NULL,
//!     last_seen TIMESTAMPTZ NOT NULL,
//!     revoked_at TIMESTAMPTZ
//!     -- then one column per descriptor field
//! );
//! CREATE TABLE connetto_device_certificates (
//!     serial BYTEA PRIMARY KEY,
//!     key_id BYTEA NOT NULL REFERENCES connetto_device_enrolments (key_id),
//!     issuer BYTEA NOT NULL,
//!     expires_at TIMESTAMPTZ NOT NULL
//! );
//! CREATE INDEX ON connetto_device_certificates (issuer, expires_at);
//! CREATE TABLE connetto_device_lists (
//!     issuer BYTEA PRIMARY KEY,
//!     last_number BIGINT NOT NULL
//! );
//! ```

use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use connetto_core::SessionId;
use connetto_core::device_cert::{DeviceDescriptor, KeyId, Revoked};
use diesel::QueryResult;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncConnection as _, AsyncPgConnection};

use super::enrolment::{
    Device, Enrolment, EnrolmentError, EnrolmentFuture, EnrolmentStore, Recorded, Revocation,
};

/// One statement of a [`ConnettoEnrolmentSchema`], run on a borrowed
/// connection.
pub type Statement<'c, T> = Pin<Box<dyn Future<Output = QueryResult<T>> + Send + 'c>>;

/// What the enrolment table holds about one key, the row locked until the
/// transaction ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyFacts {
    /// Whether the key is enrolled under the account asked about, true when
    /// none was named.
    pub owned: bool,
    /// Whether the key's enrolment is revoked.
    pub revoked: bool,
}

/// A key's first enrolment.
#[derive(Debug)]
pub struct NewEnrolment<'a, Id, D> {
    /// The device key.
    pub key: KeyId,
    /// The account it enrols under.
    pub user: &'a Id,
    /// The session that asked.
    pub session: SessionId,
    /// When, which is both its enrolment and its last sighting.
    pub at: SystemTime,
    /// The descriptor the device sent.
    pub descriptor: D,
}

/// A renewal of a key already enrolled under the same account.
#[derive(Debug)]
pub struct Renewal<D> {
    /// The device key.
    pub key: KeyId,
    /// The session that asked.
    pub session: SessionId,
    /// When, its new last sighting.
    pub at: SystemTime,
    /// The descriptor the device sent.
    pub descriptor: D,
}

/// One certificate issued to an enrolled key.
#[derive(Debug, Clone, Copy)]
pub struct NewCertificate {
    /// Its X.509 serial.
    pub serial: [u8; 16],
    /// The enrolled key it certifies.
    pub key: KeyId,
    /// The issuer that signed it.
    pub issuer: KeyId,
    /// When it expires.
    pub expires_at: SystemTime,
}

/// One enrolled device of an account, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow<D> {
    /// The device key.
    pub key: KeyId,
    /// When the key first enrolled.
    pub enrolled_at: SystemTime,
    /// When the key last enrolled or renewed.
    pub last_seen: SystemTime,
    /// When the key was revoked.
    pub revoked_at: Option<SystemTime>,
    /// The descriptor the device last sent.
    pub descriptor: D,
}

/// The enrolment, certificate and list-number tables, one statement per
/// function.
///
/// Every function runs exactly one statement on the connection it is handed,
/// inside the transaction the store opened, and decides nothing.
pub trait ConnettoEnrolmentSchema: Send + Sync + 'static {
    /// The deployment's typed distributed user id.
    type Id: Clone + core::fmt::Display + Send + Sync + 'static;
    /// The application's device descriptor, one column per field.
    type Descriptor: DeviceDescriptor + Clone;

    /// The tables this member reads and writes, by name, which startup
    /// requires to exist when device identity is on (R98 decision 5).
    const TABLES: &'static [&'static str];

    /// `key`'s enrolment, locked `FOR UPDATE`, and whether `user` holds it.
    fn key_facts<'c>(
        conn: &'c mut AsyncPgConnection,
        key: KeyId,
        user: Option<&'c Self::Id>,
    ) -> Statement<'c, Option<KeyFacts>>;

    /// Insert a first enrolment unless the key already has one, answering
    /// whether a row was inserted.
    fn insert_enrolment<'c>(
        conn: &'c mut AsyncPgConnection,
        enrolment: NewEnrolment<'c, Self::Id, Self::Descriptor>,
    ) -> Statement<'c, bool>;

    /// Record a renewal's session, sighting and descriptor.
    fn renew_enrolment(
        conn: &mut AsyncPgConnection,
        renewal: Renewal<Self::Descriptor>,
    ) -> Statement<'_, ()>;

    /// Insert one issued certificate.
    fn insert_certificate(
        conn: &mut AsyncPgConnection,
        certificate: NewCertificate,
    ) -> Statement<'_, ()>;

    /// Mark `key` revoked at `at`, answering the session that last enrolled it.
    fn revoke_key(
        conn: &mut AsyncPgConnection,
        key: KeyId,
        at: SystemTime,
    ) -> Statement<'_, SessionId>;

    /// Every enrolment of `user`, revoked ones included.
    fn devices<'c>(
        conn: &'c mut AsyncPgConnection,
        user: &'c Self::Id,
    ) -> Statement<'c, Vec<DeviceRow<Self::Descriptor>>>;

    /// Every serial `issuer` signed for a revoked key that has not expired at
    /// `now`, with when the key was revoked.
    fn revoked_serials(
        conn: &mut AsyncPgConnection,
        issuer: KeyId,
        now: SystemTime,
    ) -> Statement<'_, Vec<Revoked>>;

    /// Advance `issuer`'s list number, answering the new one, which is 1 for an
    /// issuer with none yet.
    fn next_list_number(conn: &mut AsyncPgConnection, issuer: KeyId) -> Statement<'_, i64>;
}

/// An [`EnrolmentStore`] over the deployment's enrolment tables, `D`'s
/// [`Enrolments`] member, on the owner pool.
///
/// [`Enrolments`]: crate::schema::ConnettoSchema::Enrolments
#[must_use]
pub fn pg_enrolment_store<D>(pool: Pool<AsyncPgConnection>) -> Arc<dyn EnrolmentStore<D::Id>>
where
    D: crate::schema::ConnettoSchema,
{
    Arc::new(PgEnrolments::<D::Enrolments> {
        pool,
        schema: PhantomData,
    })
}

/// The Postgres [`EnrolmentStore`], generic over the deployment's member.
struct PgEnrolments<S> {
    pool: Pool<AsyncPgConnection>,
    schema: PhantomData<fn() -> S>,
}

impl<S: ConnettoEnrolmentSchema> EnrolmentStore<S::Id> for PgEnrolments<S> {
    fn record(&self, enrolment: Enrolment<S::Id>) -> EnrolmentFuture<'_, Recorded> {
        Box::pin(async move {
            let Ok(descriptor) = rmp_serde::from_slice::<S::Descriptor>(&enrolment.descriptor)
            else {
                return Ok(Recorded::UnreadableDescriptor);
            };
            let mut conn = self.pool.get().await.map_err(EnrolmentError::new)?;
            conn.transaction::<_, diesel::result::Error, _>(async move |c| {
                let Enrolment {
                    user,
                    key,
                    serial,
                    issuer,
                    issued_at,
                    expires_at,
                    session,
                    descriptor: _,
                } = enrolment;
                let mut facts = S::key_facts(c, key, Some(&user)).await?;
                if facts.is_none() {
                    let first = NewEnrolment {
                        key,
                        user: &user,
                        session,
                        at: issued_at,
                        descriptor: descriptor.clone(),
                    };
                    // A concurrent first enrolment of the same key inserted
                    // its row between the read and the insert.
                    if !S::insert_enrolment(c, first).await? {
                        facts = Some(
                            S::key_facts(c, key, Some(&user))
                                .await?
                                .ok_or(diesel::result::Error::NotFound)?,
                        );
                    }
                }
                match facts {
                    Some(KeyFacts { revoked: true, .. }) => return Ok(Recorded::Revoked),
                    Some(KeyFacts { owned: false, .. }) => return Ok(Recorded::HeldElsewhere),
                    Some(_) => {
                        let renewal = Renewal {
                            key,
                            session,
                            at: issued_at,
                            descriptor,
                        };
                        S::renew_enrolment(c, renewal).await?;
                    }
                    None => {}
                }
                let certificate = NewCertificate {
                    serial,
                    key,
                    issuer,
                    expires_at,
                };
                S::insert_certificate(c, certificate).await?;
                Ok(Recorded::Granted)
            })
            .await
            .map_err(EnrolmentError::new)
        })
    }

    fn devices<'a>(&'a self, user: &'a S::Id) -> EnrolmentFuture<'a, Vec<Device>> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(EnrolmentError::new)?;
            let rows = S::devices(&mut conn, user)
                .await
                .map_err(EnrolmentError::new)?;
            rows.into_iter()
                .map(|row| {
                    Ok(Device {
                        key: row.key,
                        enrolled_at: row.enrolled_at,
                        last_seen: row.last_seen,
                        revoked_at: row.revoked_at,
                        descriptor: rmp_serde::to_vec_named(&row.descriptor)
                            .map_err(EnrolmentError::new)?,
                    })
                })
                .collect()
        })
    }

    fn revoke<'a>(
        &'a self,
        user: Option<&'a S::Id>,
        key: KeyId,
        at: SystemTime,
    ) -> EnrolmentFuture<'a, Revocation> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(EnrolmentError::new)?;
            conn.transaction::<_, diesel::result::Error, _>(async move |c| {
                match S::key_facts(c, key, user).await? {
                    None | Some(KeyFacts { owned: false, .. }) => Ok(Revocation::NotFound),
                    Some(KeyFacts { revoked: true, .. }) => Ok(Revocation::AlreadyRevoked),
                    Some(_) => Ok(Revocation::Revoked {
                        session: S::revoke_key(c, key, at).await?,
                    }),
                }
            })
            .await
            .map_err(EnrolmentError::new)
        })
    }

    fn revoked_serials(&self, issuer: KeyId, now: SystemTime) -> EnrolmentFuture<'_, Vec<Revoked>> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(EnrolmentError::new)?;
            S::revoked_serials(&mut conn, issuer, now)
                .await
                .map_err(EnrolmentError::new)
        })
    }

    fn next_list_number(&self, issuer: KeyId) -> EnrolmentFuture<'_, u64> {
        Box::pin(async move {
            let mut conn = self.pool.get().await.map_err(EnrolmentError::new)?;
            let number = S::next_list_number(&mut conn, issuer)
                .await
                .map_err(EnrolmentError::new)?;
            u64::try_from(number).map_err(EnrolmentError::new)
        })
    }
}

/// A key id read back from its `BYTEA` column.
///
/// # Errors
///
/// A deserialization error when the column does not hold 32 bytes.
#[doc(hidden)]
pub fn __key_id(bytes: &[u8]) -> QueryResult<KeyId> {
    <[u8; 32]>::try_from(bytes)
        .map(KeyId::from_bytes)
        .map_err(|err| diesel::result::Error::DeserializationError(Box::new(err)))
}

/// The inferred type `_`, one per descriptor field of
/// [`connetto_enrolment_tables!`].
#[doc(hidden)]
#[macro_export]
macro_rules! __connetto_type_hole {
    ($field:ident) => {
        _
    };
}

/// Generate the default enrolment tables and their
/// [`ConnettoEnrolmentSchema`] impl, over the deployment's `Id` and its SQL
/// type and the descriptor type with its fields' SQL types.
///
/// Invoked at module scope with `diesel` in scope, it emits the three
/// `diesel::table!` modules and a unit struct `ConnettoEnrolments`. The
/// descriptor is destructured field by field, so a field list that disagrees
/// with the type does not compile. With no descriptor it is `()`.
#[doc(hidden)]
#[macro_export]
macro_rules! connetto_enrolment_tables {
    ($id:ty, $id_sql:ty; $($desc:ident)::+ { $($field:ident : $field_sql:ty),* $(,)? }) => {
        $crate::connetto_enrolment_tables!(
            @emit $id, $id_sql; {$($desc)::+}; ($($desc)::+ { $($field),* }); $($field : $field_sql),*
        );
    };
    ($id:ty, $id_sql:ty;) => {
        $crate::connetto_enrolment_tables!(@emit $id, $id_sql; {()}; (()););
    };
    (@emit $id:ty, $id_sql:ty; {$($desc:tt)*}; ($($shape:tt)*); $($field:ident : $field_sql:ty),*) => {
        diesel::table! {
            /// One row per enrolled device key.
            connetto_device_enrolments (key_id) {
                /// The SHA-256 of the key's `SubjectPublicKeyInfo`.
                key_id -> diesel::sql_types::Bytea,
                /// The account the key is enrolled under.
                user_id -> $id_sql,
                /// The session that last enrolled or renewed it.
                session_id -> diesel::sql_types::Uuid,
                /// When it first enrolled.
                enrolled_at -> diesel::sql_types::Timestamptz,
                /// When it last enrolled or renewed.
                last_seen -> diesel::sql_types::Timestamptz,
                /// When it was revoked.
                revoked_at -> diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
                $( $field -> $field_sql, )*
            }
        }

        diesel::table! {
            /// One row per issued certificate.
            connetto_device_certificates (serial) {
                /// Its X.509 serial.
                serial -> diesel::sql_types::Bytea,
                /// The enrolled key it certifies.
                key_id -> diesel::sql_types::Bytea,
                /// The issuer that signed it, by key id.
                issuer -> diesel::sql_types::Bytea,
                /// When it expires.
                expires_at -> diesel::sql_types::Timestamptz,
            }
        }

        diesel::table! {
            /// One row per issuer, its last revocation-list number.
            connetto_device_lists (issuer) {
                /// The issuer, by key id.
                issuer -> diesel::sql_types::Bytea,
                /// The last number handed out.
                last_number -> diesel::sql_types::BigInt,
            }
        }

        diesel::allow_tables_to_appear_in_same_query!(
            connetto_device_enrolments,
            connetto_device_certificates,
        );

        /// The default enrolment tables over the deployment's `Id`.
        #[derive(Debug, Clone, Copy, Default)]
        pub struct ConnettoEnrolments;

        impl $crate::device_cert::ConnettoEnrolmentSchema for ConnettoEnrolments {
            type Id = $id;
            type Descriptor = $($desc)*;
            const TABLES: &'static [&'static str] = &[
                "connetto_device_enrolments",
                "connetto_device_certificates",
                "connetto_device_lists",
            ];

            fn key_facts<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                key: $crate::device_cert::KeyId,
                user: Option<&'c Self::Id>,
            ) -> $crate::device_cert::Statement<'c, Option<$crate::device_cert::KeyFacts>> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, OptionalExtension as _, QueryDsl};
                    use diesel_async::RunQueryDsl;
                    let keyed = QueryDsl::filter(
                        connetto_device_enrolments::table,
                        connetto_device_enrolments::key_id.eq(key.as_bytes().to_vec()),
                    );
                    let found: Option<(bool, bool)> = match user {
                        Some(user) => RunQueryDsl::first(
                            QueryDsl::for_update(QueryDsl::select(
                                keyed,
                                (
                                    connetto_device_enrolments::user_id.eq(user.clone()),
                                    connetto_device_enrolments::revoked_at.is_not_null(),
                                ),
                            )),
                            conn,
                        )
                        .await
                        .optional()?,
                        None => RunQueryDsl::first::<bool>(
                            QueryDsl::for_update(QueryDsl::select(
                                keyed,
                                connetto_device_enrolments::revoked_at.is_not_null(),
                            )),
                            conn,
                        )
                        .await
                        .optional()?
                        .map(|revoked| (true, revoked)),
                    };
                    Ok(found.map(|(owned, revoked)| $crate::device_cert::KeyFacts { owned, revoked }))
                })
            }

            fn insert_enrolment<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                enrolment: $crate::device_cert::NewEnrolment<'c, Self::Id, Self::Descriptor>,
            ) -> $crate::device_cert::Statement<'c, bool> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel_async::RunQueryDsl as _;
                    let $crate::device_cert::NewEnrolment {
                        key,
                        user,
                        session,
                        at,
                        descriptor,
                    } = enrolment;
                    let $($shape)* = descriptor;
                    let at = $crate::ban::Instant::from(at);
                    let inserted = diesel::insert_into(connetto_device_enrolments::table)
                        .values((
                            connetto_device_enrolments::key_id.eq(key.as_bytes().to_vec()),
                            connetto_device_enrolments::user_id.eq(user.clone()),
                            connetto_device_enrolments::session_id.eq(session),
                            connetto_device_enrolments::enrolled_at.eq(at),
                            connetto_device_enrolments::last_seen.eq(at),
                            $( connetto_device_enrolments::$field.eq($field), )*
                        ))
                        .on_conflict_do_nothing()
                        .execute(conn)
                        .await?;
                    Ok(inserted == 1)
                })
            }

            fn renew_enrolment(
                conn: &mut diesel_async::AsyncPgConnection,
                renewal: $crate::device_cert::Renewal<Self::Descriptor>,
            ) -> $crate::device_cert::Statement<'_, ()> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, QueryDsl};
                    use diesel_async::RunQueryDsl as _;
                    let $crate::device_cert::Renewal {
                        key,
                        session,
                        at,
                        descriptor,
                    } = renewal;
                    let $($shape)* = descriptor;
                    diesel::update(QueryDsl::filter(
                        connetto_device_enrolments::table,
                        connetto_device_enrolments::key_id.eq(key.as_bytes().to_vec()),
                    ))
                    .set((
                        connetto_device_enrolments::session_id.eq(session),
                        connetto_device_enrolments::last_seen.eq($crate::ban::Instant::from(at)),
                        $( connetto_device_enrolments::$field.eq($field), )*
                    ))
                    .execute(conn)
                    .await?;
                    Ok(())
                })
            }

            fn insert_certificate(
                conn: &mut diesel_async::AsyncPgConnection,
                certificate: $crate::device_cert::NewCertificate,
            ) -> $crate::device_cert::Statement<'_, ()> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel_async::RunQueryDsl as _;
                    diesel::insert_into(connetto_device_certificates::table)
                        .values((
                            connetto_device_certificates::serial.eq(certificate.serial.to_vec()),
                            connetto_device_certificates::key_id
                                .eq(certificate.key.as_bytes().to_vec()),
                            connetto_device_certificates::issuer
                                .eq(certificate.issuer.as_bytes().to_vec()),
                            connetto_device_certificates::expires_at
                                .eq($crate::ban::Instant::from(certificate.expires_at)),
                        ))
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            }

            fn revoke_key(
                conn: &mut diesel_async::AsyncPgConnection,
                key: $crate::device_cert::KeyId,
                at: std::time::SystemTime,
            ) -> $crate::device_cert::Statement<'_, $crate::SessionId> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, QueryDsl};
                    use diesel_async::RunQueryDsl as _;
                    diesel::update(QueryDsl::filter(
                        connetto_device_enrolments::table,
                        connetto_device_enrolments::key_id.eq(key.as_bytes().to_vec()),
                    ))
                    .set(connetto_device_enrolments::revoked_at.eq(Some($crate::ban::Instant::from(at))))
                    .returning(connetto_device_enrolments::session_id)
                    .get_result(conn)
                    .await
                })
            }

            fn devices<'c>(
                conn: &'c mut diesel_async::AsyncPgConnection,
                user: &'c Self::Id,
            ) -> $crate::device_cert::Statement<'c, Vec<$crate::device_cert::DeviceRow<Self::Descriptor>>> {
                Box::pin(async move {
                    use diesel::{ExpressionMethods as _, QueryDsl};
                    use diesel_async::RunQueryDsl;
                    let rows: Vec<(
                        Vec<u8>,
                        $crate::ban::Instant,
                        $crate::ban::Instant,
                        Option<$crate::ban::Instant>,
                        $( $crate::__connetto_type_hole!($field), )*
                    )> = RunQueryDsl::load(
                        QueryDsl::select(
                            QueryDsl::filter(
                                connetto_device_enrolments::table,
                                connetto_device_enrolments::user_id.eq(user.clone()),
                            ),
                            (
                                connetto_device_enrolments::key_id,
                                connetto_device_enrolments::enrolled_at,
                                connetto_device_enrolments::last_seen,
                                connetto_device_enrolments::revoked_at,
                                $( connetto_device_enrolments::$field, )*
                            ),
                        ),
                        conn,
                    )
                    .await?;
                    rows.into_iter()
                        .map(|(key, enrolled_at, last_seen, revoked_at, $($field,)*)| {
                            Ok($crate::device_cert::DeviceRow {
                                key: $crate::device_cert::__key_id(&key)?,
                                enrolled_at: enrolled_at.into(),
                                last_seen: last_seen.into(),
                                revoked_at: revoked_at.map(Into::into),
                                descriptor: $($shape)*,
                            })
                        })
                        .collect()
                })
            }

            fn revoked_serials(
                conn: &mut diesel_async::AsyncPgConnection,
                issuer: $crate::device_cert::KeyId,
                now: std::time::SystemTime,
            ) -> $crate::device_cert::Statement<'_, Vec<$crate::device_cert::Revoked>> {
                Box::pin(async move {
                    use diesel::{
                        BoolExpressionMethods as _, ExpressionMethods as _, JoinOnDsl as _,
                        NullableExpressionMethods as _, QueryDsl,
                    };
                    use diesel_async::RunQueryDsl;
                    let joined = QueryDsl::inner_join(
                        connetto_device_certificates::table,
                        connetto_device_enrolments::table.on(
                            connetto_device_certificates::key_id.eq(connetto_device_enrolments::key_id),
                        ),
                    );
                    let revoked = QueryDsl::filter(
                        joined,
                        connetto_device_certificates::issuer
                            .eq(issuer.as_bytes().to_vec())
                            .and(connetto_device_certificates::expires_at.gt($crate::ban::Instant::from(now)))
                            .and(connetto_device_enrolments::revoked_at.is_not_null()),
                    );
                    let rows: Vec<(Vec<u8>, $crate::ban::Instant)> = RunQueryDsl::load(
                        QueryDsl::select(
                            revoked,
                            (
                                connetto_device_certificates::serial,
                                connetto_device_enrolments::revoked_at.assume_not_null(),
                            ),
                        ),
                        conn,
                    )
                    .await?;
                    Ok(rows
                        .into_iter()
                        .map(|(serial, at)| $crate::device_cert::Revoked { serial, at: at.into() })
                        .collect())
                })
            }

            fn next_list_number(
                conn: &mut diesel_async::AsyncPgConnection,
                issuer: $crate::device_cert::KeyId,
            ) -> $crate::device_cert::Statement<'_, i64> {
                Box::pin(async move {
                    use diesel::ExpressionMethods as _;
                    use diesel_async::RunQueryDsl as _;
                    diesel::insert_into(connetto_device_lists::table)
                        .values((
                            connetto_device_lists::issuer.eq(issuer.as_bytes().to_vec()),
                            connetto_device_lists::last_number.eq(1_i64),
                        ))
                        .on_conflict(connetto_device_lists::issuer)
                        .do_update()
                        .set(connetto_device_lists::last_number.eq(connetto_device_lists::last_number + 1))
                        .returning(connetto_device_lists::last_number)
                        .get_result(conn)
                        .await
                })
            }
        }
    };
}
