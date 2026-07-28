//! The in-memory auth store is generic over the developer's distributed id
//! type. This drives it with `rosetta_uuid::Uuid` (the demo id) to prove the
//! resolved `AuthContext::user_id` is the typed value, not a string, and that
//! the same verified identity resolves to one id across logins while rotation
//! and revocation carry the typed id through.

use std::sync::Arc;
use std::time::SystemTime;

use connetto_server::{
    AuthConfig, AuthStore, IdentityResolver, InMemoryAuthStore, ResolveFuture, ResolvedIdentity,
    VerifiedClaims,
};
use rosetta_uuid::Uuid;

/// A fixed namespace for the deterministic `(issuer, subject)` to `Uuid`
/// mapping, standing in for the developer's `IdentityResolver`.
const NS: uuid::Uuid = uuid::Uuid::from_u128(0x2b7e_1516_28ae_d2a6_abf7_1588_09cf_4f3c);

fn identity(subject: &str) -> ResolvedIdentity {
    ResolvedIdentity {
        issuer: "https://issuer.example".to_owned(),
        subject: subject.to_owned(),
        email: None,
        name: None,
        amr: Vec::new(),
        acr: None,
        tenant_id: Some("tenant-typed".to_owned()),
        roles: vec!["member".to_owned()],
        claims: std::collections::BTreeMap::new(),
    }
}

/// The deterministic v5 uuid over `issuer|subject`, mapped into the demo
/// `rosetta_uuid::Uuid`.
fn expected_id(subject: &str) -> Uuid {
    uuid::Uuid::new_v5(&NS, format!("https://issuer.example|{subject}").as_bytes()).into()
}

/// The typed resolver: the in-memory stand-in for a developer's
/// [`IdentityResolver`] over a typed distributed id.
struct TypedResolver;

impl IdentityResolver for TypedResolver {
    type Id = Uuid;

    fn resolve<'a>(&'a self, claims: &'a VerifiedClaims) -> ResolveFuture<'a, Uuid> {
        let id: Uuid = uuid::Uuid::new_v5(
            &NS,
            format!("{}|{}", claims.issuer, claims.subject).as_bytes(),
        )
        .into();
        Box::pin(async move { Ok(id) })
    }
}

fn store() -> InMemoryAuthStore<Uuid> {
    let config = AuthConfig::default();
    InMemoryAuthStore::<Uuid>::with_resolver(config.refresh_lifetimes(), Arc::new(TypedResolver))
}

#[tokio::test]
async fn in_memory_store_carries_a_typed_user_id() {
    let store = store();
    let now = SystemTime::now();

    let first = store
        .create_session(&identity("dave"), now)
        .await
        .expect("first session");
    let second = store
        .create_session(&identity("dave"), now)
        .await
        .expect("second session");

    // The resolved user id is the typed value, not a string, and the same
    // verified identity resolves to one id across logins.
    let expected = expected_id("dave");
    assert_eq!(first.context.user_id, expected);
    assert_eq!(first.context.user_id, second.context.user_id);
    assert_ne!(first.session_id, second.session_id, "distinct sessions");
    assert_eq!(first.context.roles, vec!["member".to_owned()]);
    assert_eq!(first.context.tenant_id.as_deref(), Some("tenant-typed"));

    // A different identity resolves to a different typed id.
    let other = store
        .create_session(&identity("erin"), now)
        .await
        .expect("other session");
    assert_ne!(other.context.user_id, first.context.user_id);
}

#[tokio::test]
async fn typed_id_survives_rotation_and_revocation() {
    let store = store();
    let now = SystemTime::now();

    let issued = store
        .create_session(&identity("frank"), now)
        .await
        .expect("create");
    assert!(
        store
            .session_is_live(&issued.session_id, now)
            .await
            .expect("live check")
    );

    let rotated = store
        .rotate_refresh(&issued.refresh_token, now)
        .await
        .expect("rotate");
    assert_eq!(rotated.context.user_id, issued.context.user_id);
    assert_ne!(rotated.refresh_token, issued.refresh_token, "token rotates");

    store
        .revoke_session(&issued.session_id)
        .await
        .expect("revoke");
    assert!(
        !store
            .session_is_live(&issued.session_id, now)
            .await
            .expect("post-revoke live check")
    );
}
