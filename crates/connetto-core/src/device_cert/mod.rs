//! Device certificates (R74), the identity a native device proves to its
//! peers when no server is reachable.
//!
//! The deployment's offline root signs a replaceable issuer, and the issuer
//! signs each device's certificate over a request the device's chip key made.
//! A certificate follows the SPIFFE X509-SVID profile, naming its device by one
//! URI, `connetto://<deployment>/account/<account>/device/<key>`. See R74 in
//! `plans/master-implementation-plan.md` and chapter 19.

mod authority;
mod certificate;
mod identity;
mod request;

pub use authority::{DeviceIssuer, IssueError, IssuerError, RootCa, RootError, deployment_of_root};
pub use certificate::{DeviceCertificate, ProfileError};
pub use identity::{DeploymentId, DeviceIdentity, IdentityError, KeyId};
pub use request::{CertificateRequest, RequestError};

#[cfg(test)]
use request::challenge_attribute;

#[cfg(test)]
mod tests;
