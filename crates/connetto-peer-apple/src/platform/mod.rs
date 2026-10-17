//! The Apple platform's frameworks, each behind its one lock (R76).

#[cfg_attr(
    target_os = "macos",
    expect(
        unsafe_code,
        reason = "the host name read through libc, sound as its SAFETY comment states"
    )
)]
pub(super) mod device;
#[expect(
    unsafe_code,
    reason = "the NetworkExtension and CoreWLAN calls objc2 marks unsafe and the libc reads of the Wi-Fi route, each sound as its SAFETY comment states"
)]
pub(super) mod hotspot;
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "the CoreLocation calls objc2 marks unsafe, each made on the main thread's one manager"
)]
pub(super) mod location;
#[expect(
    unsafe_code,
    reason = "the CoreBluetooth calls objc2 marks unsafe and the delegate's state, each sound under the one STANDING lock and the manager's serial queue"
)]
pub(super) mod peripheral;
