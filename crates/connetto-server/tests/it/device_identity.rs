//! Needs Docker: the fixture starts its own Postgres.
//!
//! A server the builder assembles with device identity enrols a signed-in
//! device into the deployment's own enrolment tables (R74 step 3).

use chrono::Utc;
use connetto_core::device_cert::{AttestationLevel, CertificateRequest, DeviceCertificate, KeyId};
use connetto_core::messages::{
    ControlMessage, DevicesList, DevicesRequest, EnrolChallenge, EnrolChallengeRequest, EnrolGrant,
    EnrolRefusal, EnrolRequest,
};
use connetto_core::traits::Transport;
use connetto_server::WebSocketTransport;
use connetto_server::device_cert::{AndroidStatus, DeviceCertConfig};
use connetto_test_harness::{Fixture, isolated_session_keyring};
use diesel::QueryableByName;
use diesel::{ExpressionMethods as _, OptionalExtension as _, QueryDsl as _};
use diesel_async::RunQueryDsl as _;
use rcgen::PublicKeyData as _;
use tokio::net::{TcpListener, TcpStream};

use super::e2e::{PG_SERIAL, mint_token, reset_fixture};
use super::enrolment::{android_evidence, chip_attestation, device_key, rooted_issuer};
use super::lifecycle::{admin_pool, builder_over, live_session, next_control, wait_ready};

#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

// The deployment's enrolment table as this test reads and seeds it.
diesel::table! {
    connetto_device_enrolments (key_id) {
        key_id -> Binary,
        user_id -> Text,
        session_id -> Uuid,
        enrolled_at -> Timestamptz,
        last_seen -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        attestation -> Text,
    }
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

/// A fresh enrolment nonce the server hands to the session.
async fn challenge_nonce(client: &mut WebSocketTransport<TcpStream>) -> [u8; 32] {
    client
        .send_control(ControlMessage::EnrolChallengeRequest(
            EnrolChallengeRequest {
                request_id: "c".into(),
            },
        ))
        .await
        .expect("ask for a challenge");
    let ControlMessage::EnrolChallenge(EnrolChallenge { nonce, .. }) = reply(client).await else {
        panic!("the server handed no challenge");
    };
    nonce
}

/// Enrol `key` with `attestation` against the challenge `nonce` carries.
async fn enrol_request(
    client: &mut WebSocketTransport<TcpStream>,
    key: &rcgen::KeyPair,
    nonce: [u8; 32],
    attestation: Option<connetto_core::messages::DeviceAttestation>,
) -> ControlMessage {
    client
        .send_control(ControlMessage::EnrolRequest(EnrolRequest {
            request_id: "e".into(),
            csr: CertificateRequest::build(key, &nonce).expect("csr"),
            lifetime_secs: None,
            descriptor: rmp_serde::to_vec_named(&()).expect("encode"),
            attestation,
        }))
        .await
        .expect("enrol");
    reply(client).await
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
            attestation: None,
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

#[tokio::test]
async fn a_chip_proven_enrolment_records_its_level_and_a_renewal_keeps_it() {
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
    let key = device_key();
    let (root, chain, _) = chip_attestation(&key);
    let list = tempfile::NamedTempFile::new().expect("a status list file");
    std::fs::write(list.path(), r#"{"entries": {}}"#).expect("a clean status list");
    let config = DeviceCertConfig::new(issuer)
        .with_android_roots(vec![root])
        .with_android_status(AndroidStatus::File(list.path().to_path_buf()))
        .with_accepted_attestation([AttestationLevel::ChipProven]);
    let parts = builder
        .device_identity(Some(config))
        .build()
        .await
        .expect("the deployment with device identity assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    let base = format!("http://127.0.0.1:{port}");
    wait_ready(&base).await;

    let (token, user_id) = mint_token(&base).await;
    let mut client = live_session(&format!("127.0.0.1:{port}"), &token).await;

    // A key whose stored level the deployment does not accept: renewing it is
    // refused, no attestation sent to try again.
    let seeded = device_key();
    let mut conn = pool.get().await.expect("a connection");
    diesel::insert_into(connetto_device_enrolments::table)
        .values((
            connetto_device_enrolments::key_id.eq(KeyId::of_public_key(
                &seeded.subject_public_key_info(),
            )
            .as_bytes()
            .to_vec()),
            connetto_device_enrolments::user_id.eq(&user_id),
            connetto_device_enrolments::session_id.eq(uuid::Uuid::nil()),
            connetto_device_enrolments::enrolled_at.eq(Utc::now()),
            connetto_device_enrolments::last_seen.eq(Utc::now()),
            connetto_device_enrolments::attestation.eq(AttestationLevel::Unproven.as_str()),
        ))
        .execute(&mut conn)
        .await
        .expect("seed the stored level");
    let nonce = challenge_nonce(&mut client).await;
    let reply = enrol_request(&mut client, &seeded, nonce, None).await;
    match reply {
        ControlMessage::EnrolRefused(refused) => {
            assert_eq!(refused.reason, EnrolRefusal::AttestationRequired);
        }
        other => panic!("a stored unproven renewal was answered {other:?}"),
    }

    // A fresh key that attests nothing: the deployment accepts only
    // chip-proven keys, so the enrolment is refused.
    let nonce = challenge_nonce(&mut client).await;
    let reply = enrol_request(&mut client, &device_key(), nonce, None).await;
    match reply {
        ControlMessage::EnrolRefused(refused) => {
            assert_eq!(refused.reason, EnrolRefusal::AttestationRequired);
        }
        other => panic!("an unattested enrolment was answered {other:?}"),
    }

    // A fresh key with a chip-proven chain: granted, and recorded as
    // `chip-proven` in the deployment's own table.
    let nonce = challenge_nonce(&mut client).await;
    let reply = enrol_request(&mut client, &key, nonce, Some(android_evidence(chain))).await;
    let ControlMessage::EnrolGrant(EnrolGrant { chain: granted, .. }) = reply else {
        panic!("the chip enrolment answered no grant");
    };
    let leaf = DeviceCertificate::parse(&granted[0]).expect("the leaf meets the profile");
    assert_eq!(leaf.attestation(), AttestationLevel::ChipProven);
    let stored: Option<String> = connetto_device_enrolments::table
        .select(connetto_device_enrolments::attestation)
        .filter(connetto_device_enrolments::user_id.eq(&user_id))
        .filter(
            connetto_device_enrolments::key_id.eq(KeyId::of_public_key(
                &key.subject_public_key_info(),
            )
            .as_bytes()
            .to_vec()),
        )
        .first(&mut conn)
        .await
        .optional()
        .expect("read the stored level");
    assert_eq!(stored.as_deref(), Some("chip-proven"));

    // A renewal of the chip key that attests nothing: the recorded level
    // stands and the enrolment is still granted.
    let nonce = challenge_nonce(&mut client).await;
    let reply = enrol_request(&mut client, &key, nonce, None).await;
    let ControlMessage::EnrolGrant(EnrolGrant { chain: renewed, .. }) = reply else {
        panic!("the renewal answered no grant");
    };
    let renewed = DeviceCertificate::parse(&renewed[0]).expect("the renewal meets the profile");
    assert_eq!(renewed.attestation(), AttestationLevel::ChipProven);

    stream.abort();
    http.abort();
}

/// What `connetto-ca init` and `connetto-ca issuer` leave on disk, as the
/// operator copies it to the server: `root.der` beside an issuer directory.
fn ca_output(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    use connetto_core::device_cert::layout::{ISSUER_CERTIFICATE, ISSUER_KEY, ROOT_CERTIFICATE};
    use connetto_core::device_cert::{CertificateSerial, DeploymentId, RootCa};
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
            CertificateSerial::new([2; 16]).expect("the serial is positive"),
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

/// A device setting the binary cannot use refuses boot naming the setting it
/// choked on, every refusal before the server binds.
#[tokio::test]
async fn the_binary_refuses_unusable_device_settings() {
    use super::e2e::{build_auth_stack, run_server_exit_output, with_user_url};

    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let auth_stack = build_auth_stack().await;
    let auth_env = auth_stack.env_pairs("http://127.0.0.1:0");
    let base: Vec<(&str, &str)> = auth_env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let ca = tempfile::TempDir::new().expect("ca dir");
    let (root, issuer_dir) = ca_output(ca.path());
    let (root, issuer_dir) = (root.display().to_string(), issuer_dir.display().to_string());
    let missing = |name: &str| ca.path().join(name).display().to_string();
    let retired_dir = missing("no-such-issuer");
    let root_list = missing("no-such-list");
    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        (
            vec![("CONNETTO_DEVICE_ACCEPTED_ATTESTATION", "chip-proven,bogus")],
            "CONNETTO_DEVICE_ACCEPTED_ATTESTATION names \"bogus\"",
        ),
        (
            vec![
                ("CONNETTO_DEVICE_APP_ATTEST_APP_IDS", "TEAMID.bundle.id"),
                ("CONNETTO_DEVICE_APP_ATTEST_ENVIRONMENT", "staging"),
            ],
            "CONNETTO_DEVICE_APP_ATTEST_ENVIRONMENT is \"staging\"",
        ),
        (
            vec![("CONNETTO_DEVICE_CERT_CEILING_SECS", "soon")],
            "parsing CONNETTO_DEVICE_CERT_CEILING_SECS",
        ),
        (
            vec![("CONNETTO_DEVICE_RETIRED_ISSUER_DIRS", &retired_dir)],
            "reading the issuer certificate",
        ),
        (
            vec![("CONNETTO_DEVICE_ROOT_LIST", &root_list)],
            "reading the root's list",
        ),
    ];

    for (extra, expected) in cases {
        let mut envs = base.clone();
        envs.push(("CONNETTO_DEVICE_ROOT", root.as_str()));
        envs.push(("CONNETTO_DEVICE_ISSUER_DIR", issuer_dir.as_str()));
        envs.extend(extra);
        let output = run_server_exit_output(&url, Some(&reader_url), &envs).await;
        assert!(!output.status.success(), "{expected} refuses");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "the refusal names the setting, got: {stderr}"
        );
    }
}
