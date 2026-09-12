pub(super) mod read;
pub(super) mod write;

use crate::ClientError;

use super::{
    LOCAL_ROWS, MANIFEST, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS_BYTES, PENDING, SYNCED_ROWS,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) format: String,
    pub(super) version: u32,
    pub(super) scope: String,
    pub(super) schema_fingerprint: String,
    #[serde(default)]
    pub(super) account: Option<String>,
    pub(super) compression: String,
    pub(super) note: String,
    pub(super) entries: Vec<Entry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) kind: String,
    pub(super) path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) encoding: Option<String>,
}

/// Validate that `path` is a safe relative archive path and not a reserved name.
pub(super) fn validate_attachment_path(
    path: &str,
    error: fn(String) -> ClientError,
) -> Result<(), ClientError> {
    let reserved = [MANIFEST, SYNCED_ROWS, LOCAL_ROWS, PENDING];
    let valid = !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !reserved.contains(&path)
        && path
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."));
    if valid {
        Ok(())
    } else {
        Err(error(format!(
            "the archive attachment path {path:?} is not a safe relative path"
        )))
    }
}

pub(super) fn checked_attachment_total(
    path: &str,
    size: u64,
    total: u64,
    error: fn(String) -> ClientError,
) -> Result<u64, ClientError> {
    if size > MAX_ATTACHMENT_BYTES {
        return Err(error(format!(
            "archive attachment {path} is {size} bytes, above the {MAX_ATTACHMENT_BYTES}-byte limit"
        )));
    }
    total
        .checked_add(size)
        .filter(|total| *total <= MAX_ATTACHMENTS_BYTES)
        .ok_or_else(|| {
            error(format!(
                "archive attachments exceed the {MAX_ATTACHMENTS_BYTES}-byte aggregate limit"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::super::{MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS_BYTES};
    use super::checked_attachment_total;
    use super::read::decode_pending;
    use super::write::encode_pending;
    use crate::ClientError;

    /// The queue's framing carries every record, in order, whatever the bytes
    /// inside one look like.
    #[test]
    fn the_queue_framing_round_trips() {
        let records = vec![vec![0u8, 1, 2], Vec::new(), vec![255u8; 300]];
        let encoded = encode_pending(&records);
        assert_eq!(decode_pending(&encoded).expect("decode"), records);
    }

    /// A truncated queue entry is refused rather than read as a shorter one.
    #[test]
    fn a_truncated_queue_entry_is_refused() {
        let encoded = encode_pending(&[vec![1u8, 2, 3]]);
        assert!(decode_pending(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn attachment_size_limits_apply_to_export_and_import() {
        let oversized = checked_attachment_total(
            "content/chunks/oversized",
            MAX_ATTACHMENT_BYTES + 1,
            0,
            ClientError::Export,
        )
        .expect_err("oversized export attachment");
        assert!(oversized.to_string().contains("above"));

        let aggregate = checked_attachment_total(
            "content/chunks/last",
            1,
            MAX_ATTACHMENTS_BYTES,
            ClientError::Import,
        )
        .expect_err("oversized import aggregate");
        assert!(aggregate.to_string().contains("aggregate"));
    }
}
