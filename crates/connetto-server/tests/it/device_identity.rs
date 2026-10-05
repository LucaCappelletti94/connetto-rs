//! Needs Docker: the fixture starts its own Postgres.
//!
//! A server the builder assembles with device identity enrols a signed-in
//! device into the deployment's own enrolment tables (R74 step 3).

use connetto_core::device_cert::{CertificateRequest, KeyId};
use connetto_core::messages::{
    ControlMessage, DevicesList, DevicesRequest, EnrolChallenge, EnrolChallengeRequest, EnrolGrant,
    EnrolRequest,
};
use connetto_core::traits::Transport;
use connetto_server::WebSocketTransport;
use connetto_server::device_cert::DeviceCertConfig;
use connetto_test_harness::{Fixture, isolated_session_keyring};
use diesel::QueryableByName;
use diesel_async::RunQueryDsl as _;
use rcgen::PublicKeyData as _;
use tokio::net::{TcpListener, TcpStream};

use super::e2e::{PG_SERIAL, mint_token, reset_fixture};
use super::enrolment::{device_key, rooted_issuer};
use super::lifecycle::{admin_pool, builder_over, live_session, next_control, wait_ready};

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

/// The next control frame that is not a pushed revocation list.
async fn reply(client: &mut WebSocketTransport<TcpStream>) -> ControlMessage {
    loop {
        match next_control(client).await {
            ControlMessage::RevocationUpdate(_) => {}
            other => return other,
        }
    }
}

#[tokio::test]
async fn a_built_server_enrols_a_device_into_the_deployment_tables() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;
    connetto_test_harness::stack::provision_enrolment_tables(&fixture).await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let (_, _, issuer) = rooted_issuer();
    let issuer_key = issuer.key_id();
    let parts = builder
        .device_identity(Some(DeviceCertConfig::new(issuer)))
        .build()
        .await
        .expect("the deployment with device identity assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    let base = format!("http://127.0.0.1:{port}");
    wait_ready(&base).await;

    let (token, user_id) = mint_token(&base).await;
    let mut client = live_session(&format!("127.0.0.1:{port}"), &token).await;
    client
        .send_control(ControlMessage::EnrolChallengeRequest(
            EnrolChallengeRequest {
                request_id: "c".into(),
            },
        ))
        .await
        .expect("ask for a challenge");
    let ControlMessage::EnrolChallenge(EnrolChallenge { nonce, .. }) = reply(&mut client).await
    else {
        panic!("the server handed no challenge");
    };
    let key = device_key();
    client
        .send_control(ControlMessage::EnrolRequest(EnrolRequest {
            request_id: "e".into(),
            csr: CertificateRequest::build(&key, &nonce).expect("csr"),
            lifetime_secs: None,
            descriptor: rmp_serde::to_vec_named(&()).expect("encode"),
        }))
        .await
        .expect("enrol");
    match reply(&mut client).await {
        ControlMessage::EnrolGrant(EnrolGrant {
            revocation_lists, ..
        }) => assert_eq!(revocation_lists.len(), 1, "the issuer's own list"),
        other => panic!("the enrolment answered {other:?}"),
    }

    let mut conn = pool.get().await.expect("a connection");
    let enrolled: Count = diesel::sql_query(
        "SELECT count(*) AS n FROM connetto_device_enrolments WHERE user_id = $1 AND key_id = $2",
    )
    .bind::<diesel::sql_types::Text, _>(&user_id)
    .bind::<diesel::sql_types::Bytea, _>(
        KeyId::of_public_key(&key.subject_public_key_info())
            .as_bytes()
            .to_vec(),
    )
    .get_result(&mut conn)
    .await
    .expect("read the enrolment");
    assert_eq!(
        enrolled.n, 1,
        "the key is enrolled under the signed-in account"
    );
    let numbered: Count =
        diesel::sql_query("SELECT last_number AS n FROM connetto_device_lists WHERE issuer = $1")
            .bind::<diesel::sql_types::Bytea, _>(issuer_key.as_bytes().to_vec())
            .get_result(&mut conn)
            .await
            .expect("read the list number");
    assert_eq!(
        numbered.n, 1,
        "the published list took the issuer's first number"
    );

    client
        .send_control(ControlMessage::DevicesRequest(DevicesRequest {
            request_id: "d".into(),
        }))
        .await
        .expect("list devices");
    match reply(&mut client).await {
        ControlMessage::DevicesList(DevicesList { devices, .. }) => {
            assert_eq!(devices.len(), 1);
            assert_eq!(
                devices[0].key_id,
                *KeyId::of_public_key(&key.subject_public_key_info()).as_bytes()
            );
        }
        other => panic!("the device list answered {other:?}"),
    }
    stream.abort();
    http.abort();
}

/// What `connetto-ca init` and `connetto-ca issuer` leave on disk, as the
/// operator copies it to the server: `root.der` beside an issuer directory.
fn ca_output(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    use connetto_core::device_cert::layout::{ISSUER_CERTIFICATE, ISSUER_KEY, ROOT_CERTIFICATE};
    use connetto_core::device_cert::{DeploymentId, RootCa};
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
    use std::time::{Duration, SystemTime};

    let day = Duration::from_hours(24);
    let now = SystemTime::now();
    let root = RootCa::create(
        DeploymentId::from_uuid(uuid::Uuid::from_u128(7)),
        now - day,
        3650 * day,
    )
    .expect("root");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("issuer key");
    let certificate = root
        .sign_issuer(
            &key.subject_public_key_info(),
            now - day,
            395 * day,
            [2; 16],
        )
        .expect("issuer");
    let issuer_dir = dir.join("issuer-2026");
    std::fs::create_dir(&issuer_dir).expect("issuer dir");
    std::fs::write(issuer_dir.join(ISSUER_CERTIFICATE), certificate).expect("issuer.der");
    std::fs::write(issuer_dir.join(ISSUER_KEY), key.serialize_der()).expect("issuer.key");
    let root_path = dir.join(ROOT_CERTIFICATE);
    std::fs::write(&root_path, root.certificate()).expect("root.der");
    (root_path, issuer_dir)
}

/// The binary reads the device settings from `connetto-ca`'s directories: a
/// root without an issuer directory refuses naming the setting, and an issuer
/// directory turns device identity on, so a deployment without the enrolment
/// tables refuses naming the first.
#[tokio::test]
async fn the_binary_turns_device_identity_on_from_the_issuer_directory() {
    use super::e2e::{
        Authorization, NO_POLICIES, build_auth_stack, run_server_exit_output, with_user_url,
    };

    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;
    let url = fixture.admin_url().to_owned();
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let auth_stack = build_auth_stack().await;
    let auth_env = auth_stack.env_pairs("http://127.0.0.1:0");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let ca = tempfile::TempDir::new().expect("ca dir");
    let (root, issuer_dir) = ca_output(ca.path());
    let (root, issuer_dir) = (root.display().to_string(), issuer_dir.display().to_string());
    let base: Vec<(&str, &str)> = auth_env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .chain(authorization.env_pairs())
        .collect();

    let mut root_only = base.clone();
    root_only.push(("CONNETTO_DEVICE_ROOT", &root));
    let output = run_server_exit_output(&url, Some(&reader_url), &root_only).await;
    assert!(!output.status.success(), "a root alone refuses");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CONNETTO_DEVICE_ROOT is set without CONNETTO_DEVICE_ISSUER_DIR"),
        "{stderr}"
    );

    let mut on = base;
    on.push(("CONNETTO_DEVICE_ROOT", &root));
    on.push(("CONNETTO_DEVICE_ISSUER_DIR", &issuer_dir));
    let output = run_server_exit_output(&url, Some(&reader_url), &on).await;
    assert!(!output.status.success(), "no enrolment tables refuses");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("table connetto_device_enrolments does not exist"),
        "{stderr}"
    );
}
