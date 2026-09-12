use std::io::Write;
use std::sync::{Arc, LazyLock};

use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    fn take(&self) {
        self.0.lock().clear();
    }

    fn lines(&self) -> Vec<serde_json::Value> {
        String::from_utf8_lossy(&self.0.lock())
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

/// Held for as long as one test reads the log, so two log-reading tests in this
/// process never share a buffer.
static READER: AsyncMutex<()> = AsyncMutex::const_new(());

/// One test's exclusive view of the process-global log destination.
///
/// A subscriber is process-global, so every module in this target writes to one
/// buffer. Opening a capture empties it and locks out the other log-reading
/// tests, which is what makes an assertion about what this test provoked.
pub(crate) struct LogCapture {
    buffer: Buffer,
    _reader: MutexGuard<'static, ()>,
}

impl LogCapture {
    /// Every record written since this capture opened, each parsed as one JSON object.
    pub(crate) fn lines(&self) -> Vec<serde_json::Value> {
        self.buffer.lines()
    }
}

pub(crate) async fn capture() -> LogCapture {
    let reader = READER.lock().await;
    let buffer = BUFFER.clone();
    buffer.take();
    LogCapture {
        buffer,
        _reader: reader,
    }
}
