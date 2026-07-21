//! Authorization policies for the write and read paths.
//!
//! The server gates every mutation through an [`AuthPolicy`]. Until `OpenFGA` and
//! `rls2fga` land, [`PermissiveAuth`] is the stand-in.

use std::convert::Infallible;

use connetto_core::auth::AuthContext;
use connetto_core::traits::{AuthPolicy, MutationOp};

/// A permissive [`AuthPolicy`] that grants every read and write.
///
/// The stand-in until `OpenFGA` and `rls2fga` land. It authorizes
/// unconditionally, so it must not front a production deployment.
#[derive(Debug, Clone, Copy, Default)]
pub struct PermissiveAuth;

impl AuthPolicy for PermissiveAuth {
    type Error = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn can_read(
        &self,
        _ctx: &AuthContext,
        _table: &str,
        _pk: &[u8],
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn can_write(
        &self,
        _ctx: &AuthContext,
        _table: &str,
        _pk: &[u8],
        _op: MutationOp,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
