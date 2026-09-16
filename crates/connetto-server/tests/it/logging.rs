use std::io::Write;
use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;
use tracing::Instrument;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    /// How many bytes have been written, which is where a capture starts reading.
    fn written(&self) -> usize {
        self.0.lock().len()
    }

    /// Every record written past `from`, each parsed as one JSON object.
    ///
    /// A record reaches the buffer in one write under the lock, so `from` is
    /// always a record boundary.
    fn lines(&self, from: usize) -> Vec<serde_json::Value> {
        let written = self.0.lock();
        String::from_utf8_lossy(written.get(from..).unwrap_or_default())
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

static BUFFER: LazyLock<Buffer> = LazyLock::new(|| {
    let buffer = Buffer::default();
    connetto_core::logging::install(buffer.clone(), "info");
    buffer
});

/// What one test provoked, out of the one log this target shares.
///
/// A subscriber is process-global, so every module here writes to one buffer
/// while hundreds of tests run at the same time. A capture reads back only the
/// records emitted under its own test's span, which is what makes an assertion
/// about this test rather than about whatever a concurrent one wrote.
pub(crate) struct LogCapture {
    buffer: Buffer,
    from: usize,
    test: &'static str,
}

impl LogCapture {
    /// The records this test's span produced since the capture opened.
    pub(crate) fn lines(&self) -> Vec<serde_json::Value> {
        self.buffer
            .lines(self.from)
            .into_iter()
            .filter(|line| {
                line["spans"].as_array().is_some_and(|chain| {
                    chain
                        .iter()
                        .any(|span| span["name"] == "test" && span["test"] == self.test)
                })
            })
            .collect()
    }
}

/// Run `body` under a `test` span naming it, capturing what that span logs.
///
/// `test` is the calling test's own name, and a record reaches the capture
/// only when it was emitted somewhere under that span. A task the body spawns
/// joins the chain by instrumenting the spawn with [`tracing::Span::current`],
/// which is what every connection helper in this target does.
pub(crate) async fn with_capture<B, F>(test: &'static str, body: B) -> F::Output
where
    B: FnOnce(LogCapture) -> F,
    F: Future,
{
    let buffer = BUFFER.clone();
    let capture = LogCapture {
        from: buffer.written(),
        buffer,
        test,
    };
    body(capture)
        .instrument(tracing::info_span!("test", test))
        .await
}
