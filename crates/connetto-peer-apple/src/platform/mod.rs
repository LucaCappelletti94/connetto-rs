//! The Apple platform's frameworks, each behind its one lock (R76).

pub(super) mod device;
#[expect(
    unsafe_code,
    reason = "the NetworkExtension calls objc2 marks unsafe and the libc reads of the Wi-Fi route, each sound as its SAFETY comment states"
)]
pub(super) mod hotspot;
#[expect(
    unsafe_code,
    reason = "the CoreBluetooth calls objc2 marks unsafe and the delegate's state, each sound under the one STANDING lock and the manager's serial queue"
)]
pub(super) mod peripheral;
