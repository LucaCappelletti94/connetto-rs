//! Prepares a Mac to sign `examples/dioxus-desktop-demo` for the iOS devices
//! paired with it, unattended, through an App Store Connect API key.
//!
//! ```text
//! CONNETTO_ASC_KEY_ID=… CONNETTO_ASC_ISSUER=… CONNETTO_ASC_KEY=AuthKey_….p8 \
//!   cargo run -p connetto-test-harness --bin connetto-ios-signing
//! ```
//!
//! Every step reuses what already exists. The signing key and certificate
//! live in a keychain of their own, unlocked with a password kept beside the
//! key, so an SSH session can sign while the login keychain stays locked. The
//! demo's bundle identifier and every paired iPhone and iPad are registered,
//! and a development profile covering them is written where `dx` looks for
//! one. It prints the identity's SHA-1, which `dx build --apple-team-id`
//! takes.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use connetto_test_harness::ios_signing;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde_json::{Value, json};
use tokio::process::Command;

const BUNDLE: &str = "dev.connetto.dioxusdemo";
const PROFILE_NAME: &str = "connetto dioxus demo development";
const API: &str = "https://api.appstoreconnect.apple.com/v1";

#[tokio::main]
async fn main() -> Result<()> {
    let api = Api::from_env()?;
    let dir = ios_signing::folder()?;
    tokio::fs::create_dir_all(&dir).await?;

    let keychain = Keychain::open(&dir).await?;
    let certificate = ensure_certificate(&api, &keychain, &dir).await?;
    let bundle = ensure_bundle(&api).await?;
    let devices = ensure_devices(&api).await?;
    let profile = ensure_profile(&api, &bundle, &certificate, &devices).await?;
    eprintln!(
        "profile {} covers {} device(s)",
        profile.display(),
        devices.len()
    );
    let identity = ios_signing::identity()
        .await?
        .context("the keychain holds no valid signing identity")?;
    println!("{identity}");
    Ok(())
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is unset")
}

/// App Store Connect, authenticated with a short-lived ES256 token.
struct Api {
    client: openidconnect::reqwest::Client,
    key_id: String,
    issuer: String,
    key: EcdsaKeyPair,
}

impl Api {
    fn from_env() -> Result<Self> {
        let var = |name: &str| std::env::var(name).with_context(|| format!("{name} is unset"));
        let pem = std::fs::read_to_string(var("CONNETTO_ASC_KEY")?)
            .context("reading the API key file")?;
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let der = STANDARD.decode(body).context("decoding the API key")?;
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &SystemRandom::new())
                .map_err(|err| anyhow!("the API key is not a P-256 PKCS#8 key: {err}"))?;
        Ok(Self {
            client: openidconnect::reqwest::Client::new(),
            key_id: var("CONNETTO_ASC_KEY_ID")?,
            issuer: var("CONNETTO_ASC_ISSUER")?,
            key,
        })
    }

    fn token(&self) -> Result<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let header = json!({ "alg": "ES256", "kid": self.key_id, "typ": "JWT" });
        let claims = json!({
            "iss": self.issuer,
            "iat": now,
            "exp": now + 600,
            "aud": "appstoreconnect-v1",
        });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = self
            .key
            .sign(&SystemRandom::new(), signing_input.as_bytes())
            .map_err(|_| anyhow!("signing the API token"))?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }

    async fn get(&self, route: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{API}/{route}"))
            .bearer_auth(self.token()?)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .with_context(|| format!("GET {route}"))?;
        answer(response, route).await
    }

    async fn post(&self, route: &str, body: &Value) -> Result<Value> {
        let response = self
            .client
            .post(format!("{API}/{route}"))
            .bearer_auth(self.token()?)
            .json(body)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .with_context(|| format!("POST {route}"))?;
        answer(response, route).await
    }

    async fn delete(&self, route: &str) -> Result<()> {
        let response = self
            .client
            .delete(format!("{API}/{route}"))
            .bearer_auth(self.token()?)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .with_context(|| format!("DELETE {route}"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            bail!("DELETE {route} answered {}", response.status())
        }
    }
}

async fn answer(response: openidconnect::reqwest::Response, route: &str) -> Result<Value> {
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .with_context(|| format!("reading {route}"))?;
    if !status.is_success() {
        let errors = body["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|error| format!("{}: {}", error["code"], error["detail"]))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("{route} answered {status}: {errors}");
    }
    Ok(body)
}

/// The keychain the identity lives in, unlocked for this session.
struct Keychain {
    path: PathBuf,
    password: String,
}

impl Keychain {
    async fn open(dir: &Path) -> Result<Self> {
        let path = ios_signing::keychain()?;
        let password_file = dir.join("keychain-password");
        let password = if password_file.exists() {
            tokio::fs::read_to_string(&password_file)
                .await?
                .trim()
                .to_owned()
        } else {
            let password = run("openssl", &["rand", "-hex", "32"])
                .await?
                .trim()
                .to_owned();
            write_private(&password_file, password.as_bytes()).await?;
            password
        };
        let keychain = Self { path, password };
        let path = keychain.path.display().to_string();
        if !keychain.path.exists() {
            run(
                "security",
                &["create-keychain", "-p", &keychain.password, &path],
            )
            .await?;
            // No timeout and no lock on sleep, so a long run stays unlocked.
            run("security", &["set-keychain-settings", &path]).await?;
        }
        run(
            "security",
            &["unlock-keychain", "-p", &keychain.password, &path],
        )
        .await?;
        let listed = run("security", &["list-keychains", "-d", "user"]).await?;
        if !listed.contains(ios_signing::KEYCHAIN) {
            let mut keychains: Vec<String> = listed
                .lines()
                .map(|line| line.trim().trim_matches('"').to_owned())
                .filter(|line| !line.is_empty())
                .collect();
            keychains.push(path.clone());
            let mut args = vec!["list-keychains", "-d", "user", "-s"];
            args.extend(keychains.iter().map(String::as_str));
            run("security", &args).await?;
        }
        Ok(keychain)
    }

    async fn import(&self, key: &Path, certificate: &Path, dir: &Path) -> Result<()> {
        let pem = dir.join("certificate.pem");
        run(
            "openssl",
            &[
                "x509",
                "-inform",
                "DER",
                "-in",
                &certificate.display().to_string(),
                "-out",
                &pem.display().to_string(),
            ],
        )
        .await?;
        let p12 = dir.join("identity.p12");
        let p12_password = &self.password;
        run(
            "openssl",
            &[
                "pkcs12",
                "-export",
                "-legacy",
                "-inkey",
                &key.display().to_string(),
                "-in",
                &pem.display().to_string(),
                "-out",
                &p12.display().to_string(),
                "-passout",
                &format!("pass:{p12_password}"),
            ],
        )
        .await?;
        let path = self.path.display().to_string();
        let imported = run(
            "security",
            &[
                "import",
                &p12.display().to_string(),
                "-k",
                &path,
                "-P",
                p12_password,
                "-T",
                "/usr/bin/codesign",
            ],
        )
        .await;
        tokio::fs::remove_file(&p12).await.ok();
        imported?;
        run(
            "security",
            &[
                "set-key-partition-list",
                "-S",
                "apple-tool:,apple:,codesign:",
                "-s",
                "-k",
                &self.password,
                &path,
            ],
        )
        .await?;
        Ok(())
    }
}

/// The id of a development certificate whose key this Mac holds, imported
/// into the keychain. The certificate is recorded before it is
/// imported, and one already on the account for the local key is reused, so
/// a failed run never leaves a second certificate behind.
async fn ensure_certificate(api: &Api, keychain: &Keychain, dir: &Path) -> Result<String> {
    let key = dir.join("signing-key.pem");
    if !key.exists() {
        let pem = run("openssl", &["genrsa", "2048"]).await?;
        write_private(&key, pem.as_bytes()).await?;
    }
    let certificate = dir.join("certificate.cer");
    let id = if let Some((id, der)) = account_certificate_for(api, &key).await? {
        write_private(&certificate, &der).await?;
        id
    } else {
        let csr = run(
            "openssl",
            &[
                "req",
                "-new",
                "-key",
                &key.display().to_string(),
                "-subj",
                "/CN=connetto iOS signing",
            ],
        )
        .await?;
        let created = api
            .post(
                "certificates",
                &json!({ "data": { "type": "certificates", "attributes": {
                    "certificateType": "DEVELOPMENT",
                    "csrContent": csr,
                } } }),
            )
            .await?;
        let der = STANDARD
            .decode(
                created["data"]["attributes"]["certificateContent"]
                    .as_str()
                    .context("a certificate without content")?,
            )
            .context("decoding the certificate")?;
        write_private(&certificate, &der).await?;
        created["data"]["id"]
            .as_str()
            .context("a certificate without an id")?
            .to_owned()
    };
    if ios_signing::identity().await?.is_none() {
        keychain.import(&key, &certificate, dir).await?;
    }
    Ok(id)
}

/// The development certificate on the account whose public key is the local
/// signing key's, with its content.
async fn account_certificate_for(api: &Api, key: &Path) -> Result<Option<(String, Vec<u8>)>> {
    let ours = run(
        "openssl",
        &["pkey", "-in", &key.display().to_string(), "-pubout"],
    )
    .await?;
    let listed = api
        .get("certificates?filter[certificateType]=DEVELOPMENT&limit=200")
        .await?;
    let scratch = std::env::temp_dir().join("connetto-candidate.cer");
    for certificate in listed["data"].as_array().into_iter().flatten() {
        let (Some(id), Some(content)) = (
            certificate["id"].as_str(),
            certificate["attributes"]["certificateContent"].as_str(),
        ) else {
            continue;
        };
        let der = STANDARD
            .decode(content)
            .context("decoding a listed certificate")?;
        tokio::fs::write(&scratch, &der).await?;
        let theirs = run(
            "openssl",
            &[
                "x509",
                "-inform",
                "DER",
                "-in",
                &scratch.display().to_string(),
                "-noout",
                "-pubkey",
            ],
        )
        .await?;
        if theirs.trim() == ours.trim() {
            tokio::fs::remove_file(&scratch).await.ok();
            return Ok(Some((id.to_owned(), der)));
        }
    }
    tokio::fs::remove_file(&scratch).await.ok();
    Ok(None)
}

/// The id of the demo's bundle identifier, registered when missing.
async fn ensure_bundle(api: &Api) -> Result<String> {
    let found = api
        .get(&format!("bundleIds?filter[identifier]={BUNDLE}"))
        .await?;
    if let Some(bundle) = found["data"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|bundle| bundle["attributes"]["identifier"] == BUNDLE)
    {
        return Ok(bundle["id"]
            .as_str()
            .context("a bundle without an id")?
            .to_owned());
    }
    let created = api
        .post(
            "bundleIds",
            &json!({ "data": { "type": "bundleIds", "attributes": {
                "identifier": BUNDLE,
                "name": "connetto dioxus demo",
                "platform": "IOS",
            } } }),
        )
        .await?;
    Ok(created["data"]["id"]
        .as_str()
        .context("a bundle without an id")?
        .to_owned())
}

/// The ids of every iPhone and iPad paired with this Mac, registered when
/// missing.
async fn ensure_devices(api: &Api) -> Result<Vec<String>> {
    let listing = std::env::temp_dir().join("connetto-devicectl.json");
    run(
        "xcrun",
        &[
            "devicectl",
            "list",
            "devices",
            "--json-output",
            &listing.display().to_string(),
        ],
    )
    .await?;
    let listed: Value = serde_json::from_slice(&tokio::fs::read(&listing).await?)
        .context("parsing the device list")?;
    let mut ids = Vec::new();
    for device in listed["result"]["devices"].as_array().into_iter().flatten() {
        let hardware = &device["hardwareProperties"];
        if hardware["platform"] != "iOS" {
            continue;
        }
        let Some(udid) = hardware["udid"].as_str() else {
            continue;
        };
        let name = device["deviceProperties"]["name"].as_str().unwrap_or(udid);
        let found = api.get(&format!("devices?filter[udid]={udid}")).await?;
        let id = if let Some(id) = found["data"][0]["id"].as_str() {
            id.to_owned()
        } else {
            let created = api
                .post(
                    "devices",
                    &json!({ "data": { "type": "devices", "attributes": {
                        "name": name,
                        "udid": udid,
                        "platform": "IOS",
                    } } }),
                )
                .await?;
            created["data"]["id"]
                .as_str()
                .context("a device without an id")?
                .to_owned()
        };
        eprintln!("device {name} ({udid})");
        ids.push(id);
    }
    if ids.is_empty() {
        bail!("no iPhone or iPad is paired with this Mac");
    }
    Ok(ids)
}

/// A development profile for the bundle, the certificate and every device,
/// written where `dx` reads profiles. An older profile of the same name is
/// replaced, since a profile's devices and certificates are fixed.
async fn ensure_profile(
    api: &Api,
    bundle: &str,
    certificate: &str,
    devices: &[String],
) -> Result<PathBuf> {
    let existing = api
        .get(&format!("profiles?filter[name]={PROFILE_NAME}"))
        .await?;
    for profile in existing["data"].as_array().into_iter().flatten() {
        if let Some(id) = profile["id"].as_str() {
            api.delete(&format!("profiles/{id}")).await?;
        }
    }
    let ids = |kind: &str, ids: &[String]| {
        ids.iter()
            .map(|id| json!({ "type": kind, "id": id }))
            .collect::<Vec<_>>()
    };
    let created = api
        .post(
            "profiles",
            &json!({ "data": {
                "type": "profiles",
                "attributes": { "name": PROFILE_NAME, "profileType": "IOS_APP_DEVELOPMENT" },
                "relationships": {
                    "bundleId": { "data": { "type": "bundleIds", "id": bundle } },
                    "certificates": { "data": ids("certificates", &[certificate.to_owned()]) },
                    "devices": { "data": ids("devices", devices) },
                },
            } }),
        )
        .await?;
    let attributes = &created["data"]["attributes"];
    let content = STANDARD
        .decode(
            attributes["profileContent"]
                .as_str()
                .context("a profile without content")?,
        )
        .context("decoding the profile")?;
    let uuid = attributes["uuid"]
        .as_str()
        .context("a profile without a uuid")?;
    let folder = home()?.join("Library/Developer/Xcode/UserData/Provisioning Profiles");
    tokio::fs::create_dir_all(&folder).await?;
    let path = folder.join(format!("{uuid}.mobileprovision"));
    tokio::fs::write(&path, content).await?;
    Ok(path)
}

async fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    tokio::fs::write(path, bytes)
        .await
        .with_context(|| format!("writing {}", path.display()))?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

/// Run `program` and return its standard output, failing with its standard
/// error. Arguments are never echoed, since some carry passwords.
async fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("starting {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
