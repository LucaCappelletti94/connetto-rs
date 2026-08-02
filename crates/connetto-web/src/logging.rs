//! The developer-console destination every browser connetto program installs.
//!
//! A browser has no stdout, so the native destination in
//! `connetto_core::logging` has no counterpart here and a program installs
//! [`init_console`] instead. Each event becomes one console line at the
//! console's own severity, so the browser's level filter and its stack capture
//! work on connetto events exactly as they do on the page's own.
//!
//! Nothing is shipped to the server. A browser event stays on the device.
//!
//! The destination is written here rather than taken from a crate because it
//! is one [`MakeWriter`] over `web_sys::console`, and the two published
//! wrappers for this have not seen a release since 2023 and 2021.

use std::io::Write;

use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

/// Install the developer-console destination for this browsing context.
///
/// Events at `info` and above, without a timestamp, because the console stamps
/// its own. Every browsing context is a wasm instance of its own, so a page and
/// the DB worker it spawns each install one.
///
/// Calling this a second time leaves the first destination in place, so a
/// worker whose entry point runs twice cannot die on a panic from here.
pub fn init_console() {
    let _ = tracing_subscriber::fmt()
        .with_writer(ConsoleWriter)
        .with_max_level(Level::INFO)
        .without_time()
        .with_ansi(false)
        .try_init();
}

/// Makes one [`ConsoleLine`] per event, at that event's level.
#[derive(Clone, Copy)]
struct ConsoleWriter;

impl<'a> MakeWriter<'a> for ConsoleWriter {
    type Writer = ConsoleLine;

    fn make_writer(&'a self) -> Self::Writer {
        ConsoleLine {
            level: Level::INFO,
            line: Vec::new(),
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        ConsoleLine {
            level: *meta.level(),
            line: Vec::new(),
        }
    }
}

/// One formatted event, emitted to the console when the formatter drops it.
///
/// The console takes a whole message, not a byte stream, so the line is
/// buffered until the writer's life ends and the event is known complete.
struct ConsoleLine {
    level: Level,
    line: Vec<u8>,
}

impl Write for ConsoleLine {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.line.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for ConsoleLine {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.line);
        let value = wasm_bindgen::JsValue::from_str(text.trim_end());
        match self.level {
            Level::TRACE | Level::DEBUG => web_sys::console::debug_1(&value),
            Level::INFO => web_sys::console::info_1(&value),
            Level::WARN => web_sys::console::warn_1(&value),
            Level::ERROR => web_sys::console::error_1(&value),
        }
    }
}
