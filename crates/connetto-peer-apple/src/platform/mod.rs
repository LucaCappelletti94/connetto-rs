#![expect(
    unsafe_code,
    reason = "the platform's frameworks take raw selectors and owned blocks, each sound under its module's lock"
)]
//! The Apple platform's frameworks, each behind its one lock (R76).

pub(super) mod device;
pub(super) mod hotspot;
pub(super) mod peripheral;
