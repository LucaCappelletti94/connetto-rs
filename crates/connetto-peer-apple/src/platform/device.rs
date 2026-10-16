//! The device's name and idiom, off the app's main queue (R76).

use dispatch2::DispatchQueue;
use objc2::MainThreadMarker;
use objc2_ui_kit::{UIDevice, UIUserInterfaceIdiom};

use crate::{Error, HOP_WITHIN, Idiom, is_generic_name};

/// The device's user-set name, or `None` for the platform's generic answer.
pub(crate) fn device_name() -> Option<String> {
    on_main(|device| {
        let name = device.name().to_string();
        (!is_generic_name(&name)).then_some(name)
    })
    .ok()
    .flatten()
}

/// The device's interface idiom.
pub(crate) fn device_idiom() -> Idiom {
    on_main(|device| match device.userInterfaceIdiom() {
        UIUserInterfaceIdiom::Phone => Idiom::Phone,
        UIUserInterfaceIdiom::Pad => Idiom::Pad,
        _ => Idiom::Other,
    })
    .unwrap_or(Idiom::Other)
}

/// Run `read` on the app's main queue and take its answer.
///
/// `UIDevice`'s instance methods require the main thread, and the app's main
/// run loop runs the work this queue posts there.
fn on_main<R: Send + 'static, F: FnOnce(&UIDevice) -> R + Send + 'static>(
    read: F,
) -> Result<R, Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    DispatchQueue::main().exec_async(move || {
        let answer = MainThreadMarker::new().map_or(
            Err(Error::Missing("the app's main thread".to_owned())),
            |marker| {
                let device = UIDevice::currentDevice(marker);
                Ok(read(&device))
            },
        );
        let _ = tx.send(answer);
    });
    rx.recv_timeout(HOP_WITHIN)
        .map_err(|_| Error::TimedOut(HOP_WITHIN))?
}
