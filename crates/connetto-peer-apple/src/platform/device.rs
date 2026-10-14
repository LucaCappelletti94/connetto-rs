//! The device's name and idiom, per the platform (R76).

#[cfg(target_os = "ios")]
use dispatch2::DispatchQueue;
#[cfg(target_os = "ios")]
use objc2::MainThreadMarker;
#[cfg(target_os = "ios")]
use objc2_ui_kit::{UIDevice, UIUserInterfaceIdiom};

#[cfg(target_os = "macos")]
use crate::Idiom;
#[cfg(target_os = "ios")]
use crate::{Error, HOP_WITHIN, Idiom, is_generic_name};

/// The device's user-set name, or `None` for the platform's generic answer.
pub(crate) fn device_name() -> Option<String> {
    #[cfg(target_os = "ios")]
    {
        on_main(|device| {
            let name = device.name().to_string();
            (!is_generic_name(&name)).then_some(name)
        })
        .ok()
        .flatten()
    }
    #[cfg(target_os = "macos")]
    {
        // The Mac names itself by the hostname the user sets for it.
        let mut buffer = [0u8; 256];
        // SAFETY: the buffer is writable and the call writes at most its
        // length, answering 0 when it writes a name.
        let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
        if result == 0 {
            let length = buffer
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(buffer.len());
            Some(String::from_utf8_lossy(&buffer[..length]).into_owned())
        } else {
            None
        }
    }
}

/// The device's interface idiom.
pub(crate) fn device_idiom() -> Idiom {
    #[cfg(target_os = "ios")]
    {
        on_main(|device| match device.userInterfaceIdiom() {
            UIUserInterfaceIdiom::Phone => Idiom::Phone,
            UIUserInterfaceIdiom::Pad => Idiom::Pad,
            _ => Idiom::Other,
        })
        .unwrap_or(Idiom::Other)
    }
    #[cfg(target_os = "macos")]
    {
        // A Mac is neither a phone nor a pad, so it never hosts (R76
        // decision 1).
        Idiom::Other
    }
}

/// Run `read` on the app's main queue and take its answer.
///
/// `UIDevice`'s instance methods require the main thread, and the app's main
/// run loop runs the work this queue posts there.
#[cfg(target_os = "ios")]
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
