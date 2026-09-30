//! The seam the platform's file layer plugs into when a build attaches
//! content.

use std::path::PathBuf;

use connetto_core::Transport;
use connetto_core::traits::MaybeSend;

use crate::ClientError;
use crate::live::ConnettoClient;

/// Where the content store sits, the builder's answer for a build.
#[derive(Clone, Debug)]
pub enum ContentPlace {
    /// Durable, at the content directory beside the replica file.
    Durable(PathBuf),
    /// In memory, nothing at rest.
    InMemory,
}

/// The seam the platform's file layer plugs into when a build attaches
/// content handling.
///
/// The builder computes the place and the root key. The implementer builds
/// the content client on the running client, applies its heal queries, and
/// starts the outbox drive. The trait stays free of native types, so the
/// browser store plugs into the same seam.
pub trait AttachContent<T: Transport> {
    /// The running content client this piece builds.
    type Handle: MaybeSend + 'static;

    /// Build the content client on the running `client`, encrypting under
    /// `root_key` and placing the store at `place`.
    fn attach(
        self,
        client: ConnettoClient<T>,
        root_key: [u8; 32],
        place: ContentPlace,
    ) -> impl Future<Output = Result<Self::Handle, ClientError>> + MaybeSend;
}
