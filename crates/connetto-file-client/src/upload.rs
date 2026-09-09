//! The upload negotiation: intent, the needed-hashes answer, chunk `PUT`s and
//! the commit, all under one granted write ticket.
//!
//! The bytes that leave here are plaintext. The file server verifies the
//! BLAKE3 of each chunk body against the hash in the URL and, at commit,
//! reassembles the stored chunks and checks the file identity, so it must
//! hold plaintext. Encryption at rest is the local store's and the file
//! server's own business on their own sides.

use connetto_file_core::{ChunkStore, FileId, Manifest};
use serde::{Deserialize, Serialize};

use crate::error::ContentError;
use crate::http::{ContentHttp, HttpReply};

/// The intent body: the whole manifest the upload declares.
#[derive(Serialize)]
struct IntentRequest {
    /// Total byte count, the sum of the declared chunk lengths.
    total_len: u64,
    /// The ordered chunk list.
    chunks: Vec<ChunkMetaJson>,
}

/// One chunk in the intent body.
#[derive(Serialize)]
struct ChunkMetaJson {
    /// Lower-hex BLAKE3 hash of the chunk's plaintext.
    hash: String,
    /// Plaintext byte length.
    len: u64,
}

/// The intent answer: the hashes this upload must supply.
#[derive(Deserialize)]
struct IntentResponse {
    /// Lower-hex hashes still needed, the rest having deduped.
    needed: Vec<String>,
}

/// The three addresses one write ticket authorizes, taken from the granted
/// URL.
///
/// The grant carries the intent address with the ticket inside it, and the
/// chunk and commit addresses are siblings under the same base with the same
/// ticket. Deriving them here is the file crates' business: chapter 18 keeps
/// token and route vocabulary out of `connetto-core` and inside the file
/// crates, and this is one of them.
struct WriteEndpoints {
    base: String,
    token: String,
}

impl WriteEndpoints {
    /// Splits a granted write URL of the shape `<base>/files/<hex>/intent?t=<token>`.
    fn parse(grant_url: &str) -> Result<Self, ContentError> {
        let malformed = |why: &str| ContentError::MalformedGrant(format!("{why}: {grant_url}"));
        let (address, token) = grant_url
            .split_once("?t=")
            .ok_or_else(|| malformed("no ticket query"))?;
        if token.is_empty() {
            return Err(malformed("empty ticket"));
        }
        let path = address
            .strip_suffix("/intent")
            .ok_or_else(|| malformed("not an upload intent address"))?;
        let base = path
            .rsplit_once("/files/")
            .ok_or_else(|| malformed("no file path segment"))?
            .0;
        if base.is_empty() {
            return Err(malformed("no server base"));
        }
        Ok(Self {
            base: base.to_owned(),
            token: token.to_owned(),
        })
    }

    /// Where one chunk's bytes go.
    fn chunk(&self, hash: &str) -> String {
        format!("{}/chunks/{}?t={}", self.base, hash, self.token)
    }

    /// Where the commit goes.
    fn commit(&self, file_id: FileId) -> String {
        format!("{}/files/{}/commit?t={}", self.base, file_id, self.token)
    }
}

/// Runs one whole upload for `manifest` under the address `grant_url` names.
///
/// Chunks are sent only when the intent answer asks for them, so a file whose
/// bytes the server already holds costs two round trips and no payload. A
/// resume is this same call again: re-sending the intent is what the file
/// server documents as the resume path.
pub(crate) async fn upload<H: ContentHttp, S: ChunkStore>(
    http: &H,
    grant_url: &str,
    manifest: &Manifest,
    store: &S,
) -> Result<(), ContentError> {
    let endpoints = WriteEndpoints::parse(grant_url)?;
    let total_len: u64 = manifest.chunks().iter().map(|chunk| chunk.len).sum();
    let intent = IntentRequest {
        total_len,
        chunks: manifest
            .chunks()
            .iter()
            .map(|chunk| ChunkMetaJson {
                hash: chunk.hash.to_string(),
                len: chunk.len,
            })
            .collect(),
    };
    let body = serde_json::to_vec(&intent).map_err(|source| ContentError::Decode {
        stage: "intent request",
        source,
    })?;
    let reply = send(http.post(grant_url, Some(body)), "intent").await?;
    let reply = expect(reply, 200, "intent")?;
    let answer: IntentResponse =
        serde_json::from_slice(&reply.body).map_err(|source| ContentError::Decode {
            stage: "intent",
            source,
        })?;

    for chunk in manifest.chunks() {
        let hex = chunk.hash.to_string();
        if !answer.needed.iter().any(|needed| needed == &hex) {
            continue;
        }
        let bytes = store
            .read_chunk(&chunk.hash)
            .await
            .map_err(|err| ContentError::Store(err.to_string()))?;
        let reply = send(http.put(&endpoints.chunk(&hex), bytes), "chunk").await?;
        expect(reply, 204, "chunk")?;
    }

    let reply = send(
        http.post(&endpoints.commit(manifest.file_id()), None),
        "commit",
    )
    .await?;
    expect(reply, 200, "commit").map(|_| ())
}

/// Downloads a whole file under a granted read URL.
pub(crate) async fn download<H: ContentHttp>(
    http: &H,
    grant_url: &str,
) -> Result<Vec<u8>, ContentError> {
    let reply = send(http.get(grant_url, None), "download").await?;
    Ok(expect(reply, 200, "download")?.body)
}

/// Maps a transport failure onto the content error, naming the stage.
async fn send<E: core::fmt::Display>(
    request: impl Future<Output = Result<HttpReply, E>>,
    stage: &'static str,
) -> Result<HttpReply, ContentError> {
    request
        .await
        .map_err(|err| ContentError::Transport(format!("{stage}: {err}")))
}

/// Accepts exactly the status the protocol specifies for this stage.
fn expect(reply: HttpReply, wanted: u16, stage: &'static str) -> Result<HttpReply, ContentError> {
    if reply.status == wanted {
        return Ok(reply);
    }
    Err(ContentError::Http {
        stage,
        status: reply.status,
    })
}
