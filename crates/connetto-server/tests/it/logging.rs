use parking_lot::Mutex;
use std::io::Write;
use std::sync::{Arc, LazyLock};

use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
pub(crate) struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    pub(crate) fn lines(&self) -> Vec<serde_json::Value> {
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

pub(crate) fn install_once() -> Buffer {
    BUFFER.clone()
}
