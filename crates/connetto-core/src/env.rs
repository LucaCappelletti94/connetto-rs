//! Program configuration read from the environment, shared by the reference
//! binaries.
//!
//! Off by default for the same reason the stdout log destination is: a library
//! reads no environment and opens no file, so only a program pays for this.

/// The value of `key`, or `default` when it is unset or not UTF-8.
#[must_use]
pub fn var_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// Why [`read_ddl`] found no DDL.
#[derive(Debug, thiserror::Error)]
pub enum DdlError {
    /// Neither the inline variable nor its `_FILE` companion is set.
    #[error("set {key} or {key}_FILE")]
    Unset {
        /// The variable that was looked for.
        key: String,
    },
    /// The path named by the `_FILE` companion could not be read.
    #[error("reading {path}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

/// Read a DDL from `key` directly, or from the path in `<key>_FILE`.
///
/// # Errors
///
/// [`DdlError`] when neither name is set, or when the named file cannot be
/// read.
pub fn read_ddl(key: &str) -> Result<String, DdlError> {
    if let Ok(inline) = std::env::var(key) {
        return Ok(inline);
    }
    let path = std::env::var(format!("{key}_FILE")).map_err(|_| DdlError::Unset {
        key: key.to_owned(),
    })?;
    std::fs::read_to_string(&path).map_err(|source| DdlError::Read { path, source })
}
