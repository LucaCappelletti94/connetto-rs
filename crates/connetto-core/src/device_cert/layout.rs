//! The file names `connetto-ca` writes and the server reads (R74).

/// The root certificate, the file applications are built with.
pub const ROOT_CERTIFICATE: &str = "root.der";
/// The issuer certificate the server presents.
pub const ISSUER_CERTIFICATE: &str = "issuer.der";
/// The issuer key the server holds, plain PKCS #8.
pub const ISSUER_KEY: &str = "issuer.key";
/// The root's list of revoked issuers, the file the server publishes.
pub const ROOT_LIST: &str = "root-list.der";
