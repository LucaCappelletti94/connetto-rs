//! The built binary, driven the way the operator runs it, always under a
//! passphrase file so no terminal prompt runs.

use std::path::Path;
use std::process::Command;

use connetto_core::device_cert::layout::{
    ISSUER_CERTIFICATE, ISSUER_KEY, ROOT_CERTIFICATE, ROOT_LIST,
};
use connetto_core::device_cert::{
    DeploymentId, DeviceIssuer, RevocationList, certificate_serial, deployment_of_root,
};
use uuid::Uuid;

const PASSPHRASE: &str = "correct horse battery staple";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_connetto-ca")
}

/// Run the binary with `args` under a passphrase file at `file`, returning
/// its exit code, stdout and stderr.
fn invoke_with(args: &[&str], file: &Path) -> (i32, String, String) {
    let out = Command::new(binary())
        .args(args)
        .arg("--passphrase-file")
        .arg(file)
        .output()
        .expect("the binary runs");
    (
        out.status.code().expect("a code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run the binary with a fresh passphrase file holding `passphrase`.
fn invoke(args: &[&str], passphrase: &str) -> (i32, String, String) {
    let dir = tempfile::tempdir().expect("a passphrase dir");
    let file = dir.path().join("passphrase");
    std::fs::write(&file, passphrase).expect("the passphrase writes");
    invoke_with(args, &file)
}

#[test]
fn init_writes_the_root_and_prints_the_deployment_it_named() {
    let ca = tempfile::tempdir().expect("a ca dir");
    let dir = ca.path().to_str().expect("utf-8");
    let (code, out, err) = invoke(&["init", dir], PASSPHRASE);
    assert_eq!(code, 0, "init succeeds: {err}");
    let deployment = DeploymentId::from_uuid(Uuid::parse_str(out.trim()).expect("a uuid"));
    let root = std::fs::read(ca.path().join(ROOT_CERTIFICATE)).expect("the root certificate");
    let key = std::fs::read(ca.path().join(connetto_ca::ROOT_KEY)).expect("the root key");
    assert_ne!(key, [] as [u8; 0]);
    assert_eq!(
        deployment_of_root(&root),
        Ok(deployment),
        "the printed uuid names the root on disk"
    );

    let (code, _out, err) = invoke(&["init", dir], PASSPHRASE);
    assert_ne!(code, 0, "a second init refuses");
    assert!(
        err.contains("already exists"),
        "the refusal names the files it would overwrite: {err}"
    );
}

#[test]
fn issuer_writes_a_pair_the_core_loads_against_the_root() {
    let ca = tempfile::tempdir().expect("a ca dir");
    let out = tempfile::tempdir().expect("an issuer dir");
    let ca_dir = ca.path().to_str().expect("utf-8");
    let out_dir = out.path().to_str().expect("utf-8");
    let (code, printed, err) = invoke(&["init", ca_dir], PASSPHRASE);
    assert_eq!(code, 0, "init succeeds: {err}");
    let deployment = DeploymentId::from_uuid(Uuid::parse_str(printed.trim()).expect("a uuid"));

    let (code, _out, err) = invoke(&["issuer", ca_dir, out_dir], PASSPHRASE);
    assert_eq!(code, 0, "issuer succeeds: {err}");
    let root = std::fs::read(ca.path().join(ROOT_CERTIFICATE)).expect("the root certificate");
    let certificate =
        std::fs::read(out.path().join(ISSUER_CERTIFICATE)).expect("the issuer certificate");
    let key = std::fs::read(out.path().join(ISSUER_KEY)).expect("the issuer key");
    let loaded = DeviceIssuer::from_pkcs8(certificate, &key, &root)
        .expect("the core loads what the ceremony wrote");
    assert_eq!(loaded.deployment(), deployment);
}

#[test]
fn a_wrong_passphrase_is_named_on_stderr() {
    let ca = tempfile::tempdir().expect("a ca dir");
    let out = tempfile::tempdir().expect("an issuer dir");
    let ca_dir = ca.path().to_str().expect("utf-8");
    let out_dir = out.path().to_str().expect("utf-8");
    let (code, _out, err) = invoke(&["init", ca_dir], PASSPHRASE);
    assert_eq!(code, 0, "init succeeds: {err}");

    let (code, _out, err) = invoke(&["issuer", ca_dir, out_dir], "not the passphrase");
    assert_ne!(code, 0, "the wrong passphrase signs nothing");
    assert!(
        err.contains("the passphrase does not open the root key"),
        "the failure names the cause: {err}"
    );
}

#[test]
fn a_missing_passphrase_file_is_named_with_its_cause() {
    let ca = tempfile::tempdir().expect("a ca dir");
    let out = tempfile::tempdir().expect("an issuer dir");
    let ca_dir = ca.path().to_str().expect("utf-8");
    let out_dir = out.path().to_str().expect("utf-8");
    let (code, _out, err) = invoke(&["init", ca_dir], PASSPHRASE);
    assert_eq!(code, 0, "init succeeds: {err}");

    let missing = ca.path().join("absent");
    let (code, _out, err) = invoke_with(&["issuer", ca_dir, out_dir], &missing);
    assert_ne!(code, 0, "without a passphrase file nothing signs");
    assert!(
        err.contains("reading the passphrase"),
        "the failure names the step: {err}"
    );
    assert!(err.contains("caused by:"), "the cause chain prints: {err}");
}

#[test]
fn a_passphrase_file_may_end_in_a_newline() {
    let ca = tempfile::tempdir().expect("a ca dir");
    let out = tempfile::tempdir().expect("an issuer dir");
    let ca_dir = ca.path().to_str().expect("utf-8");
    let out_dir = out.path().to_str().expect("utf-8");

    let with = tempfile::tempdir().expect("a passphrase dir");
    let with_file = with.path().join("passphrase");
    std::fs::write(&with_file, format!("{PASSPHRASE}\n")).expect("it writes");
    let (code, _out, err) = invoke_with(&["init", ca_dir], &with_file);
    assert_eq!(code, 0, "init trims the newline: {err}");

    let without = tempfile::tempdir().expect("a passphrase dir");
    let without_file = without.path().join("passphrase");
    std::fs::write(&without_file, PASSPHRASE).expect("it writes");
    let (code, _out, err) = invoke_with(&["issuer", ca_dir, out_dir], &without_file);
    assert_eq!(
        code, 0,
        "the same passphrase without the newline signs: {err}"
    );
}

#[test]
fn revoke_issuer_writes_the_root_list_naming_the_issuer() {
    let ca = tempfile::tempdir().expect("a ca dir");
    let out = tempfile::tempdir().expect("an issuer dir");
    let ca_dir = ca.path().to_str().expect("utf-8");
    let out_dir = out.path().to_str().expect("utf-8");
    let (code, _out, err) = invoke(&["init", ca_dir], PASSPHRASE);
    assert_eq!(code, 0, "init succeeds: {err}");
    let (code, _out, err) = invoke(&["issuer", ca_dir, out_dir], PASSPHRASE);
    assert_eq!(code, 0, "issuer succeeds: {err}");

    let issuer_file = out.path().join(ISSUER_CERTIFICATE);
    let (code, _out, err) = invoke(
        &[
            "revoke-issuer",
            ca_dir,
            issuer_file.to_str().expect("utf-8"),
        ],
        PASSPHRASE,
    );
    assert_eq!(code, 0, "the revocation signs: {err}");
    let root = std::fs::read(ca.path().join(ROOT_CERTIFICATE)).expect("the root certificate");
    let list_der = std::fs::read(ca.path().join(ROOT_LIST)).expect("the root list");
    let list = RevocationList::verify(&list_der, &root, std::slice::from_ref(&root))
        .expect("the core verifies the list against the root");
    let issuer_der = std::fs::read(&issuer_file).expect("the issuer certificate");
    let serial = certificate_serial(&issuer_der).expect("the serial the issuer carries");
    assert_eq!(list.number(), 1, "the first list is number one");
    assert!(
        list.revokes(&serial),
        "the list names the issuer it revoked"
    );
}

#[test]
fn a_revoke_of_a_file_that_is_not_a_certificate_is_named() {
    let ca = tempfile::tempdir().expect("a ca dir");
    let ca_dir = ca.path().to_str().expect("utf-8");
    let (code, _out, err) = invoke(&["init", ca_dir], PASSPHRASE);
    assert_eq!(code, 0, "init succeeds: {err}");

    let bad = tempfile::tempdir().expect("a file dir");
    let bad_file = bad.path().join("not-a-certificate");
    std::fs::write(&bad_file, [0xff, 0x00, 0x13]).expect("it writes");
    let (code, _out, err) = invoke(
        &["revoke-issuer", ca_dir, bad_file.to_str().expect("utf-8")],
        PASSPHRASE,
    );
    assert_ne!(code, 0, "a file that is not a certificate is not revoked");
    assert!(
        err.contains("not a revocation list or certificate"),
        "the failure names the cause: {err}"
    );
}

#[test]
fn an_issuer_with_no_root_names_the_missing_file() {
    let ca = tempfile::tempdir().expect("an empty ca dir");
    let out = tempfile::tempdir().expect("an issuer dir");
    let ca_dir = ca.path().to_str().expect("utf-8");
    let out_dir = out.path().to_str().expect("utf-8");

    let (code, _out, err) = invoke(&["issuer", ca_dir, out_dir], PASSPHRASE);
    assert_ne!(code, 0, "without a root nothing signs");
    assert!(
        err.contains(ROOT_CERTIFICATE),
        "the missing file is named: {err}"
    );
    assert!(err.contains("caused by:"), "the cause chain prints: {err}");
}

#[test]
fn a_malformed_invocation_prints_the_usage() {
    let ca = tempfile::tempdir().expect("a ca dir");
    let dir = ca.path().to_str().expect("utf-8");

    for (code, _out, err) in [
        invoke(&["bogus", dir], PASSPHRASE),
        invoke(&["init"], PASSPHRASE),
        invoke(&["issuer", dir], PASSPHRASE),
    ] {
        assert_ne!(code, 0, "malformed arguments refuse to run: {err}");
        assert!(
            err.contains("usage: connetto-ca"),
            "the usage prints: {err}"
        );
    }

    let out = Command::new(binary())
        .arg("--passphrase-file")
        .output()
        .expect("the binary runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(
        out.status.code().expect("a code"),
        0,
        "a dangling flag refuses to run: {stderr}"
    );
    assert!(
        stderr.contains("usage: connetto-ca"),
        "the usage prints: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn a_ceremony_that_fails_to_write_leaves_no_partial_files() {
    let ca = tempfile::tempdir().expect("a ca dir");
    let out = tempfile::tempdir().expect("an issuer dir");
    let ca_dir = ca.path().to_str().expect("utf-8");
    let out_dir = out.path().to_str().expect("utf-8");
    let (code, _out, err) = invoke(&["init", ca_dir], PASSPHRASE);
    assert_eq!(code, 0, "init succeeds: {err}");

    std::os::unix::fs::symlink(
        "a target that does not exist",
        out.path().join(ISSUER_CERTIFICATE),
    )
    .expect("a broken symlink");
    let (code, _out, err) = invoke(&["issuer", ca_dir, out_dir], PASSPHRASE);
    assert_ne!(
        code, 0,
        "a file that cannot be written refuses the ceremony: {err}"
    );
    assert!(
        !out.path().join(ISSUER_KEY).exists(),
        "the key already written goes again"
    );
    assert!(
        err.contains(ISSUER_CERTIFICATE),
        "the failing file is named: {err}"
    );
}
