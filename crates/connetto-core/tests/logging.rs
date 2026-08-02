//! The stdout destination's line format, asserted on the exact bytes a program
//! would have written.
//!
//! Aggregators parse these lines, and the connection context is the only place
//! a session handle reaches a log line, so both are contracts rather than
//! formatting taste. The destination is process-global, so this file installs
//! it once and holds a single test.

#![cfg(feature = "logging")]

use std::io::Write;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

/// Collects every written line into a shared buffer.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("buffer poisoned")).into_owned()
    }
}

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("buffer poisoned")
            .extend_from_slice(buf);
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

#[test]
fn an_event_is_one_json_object_and_picks_up_its_connection_context() {
    let buffer = Buffer::default();
    connetto_core::logging::install(buffer.clone(), "info");

    let connection = tracing::info_span!("connection", session = "session-1", user = "user-1");
    connection.in_scope(|| tracing::info!(bind = "127.0.0.1:8080", "sync listener started"));
    tracing::info!("outside every connection");

    let lines: Vec<serde_json::Value> = buffer
        .contents()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each line is one JSON object"))
        .collect();
    assert_eq!(lines.len(), 2, "one line per event: {lines:?}");

    // Named values, not a formatted string: the message and the event's own
    // fields sit beside each other at the root.
    assert_eq!(lines[0]["message"], "sync listener started");
    assert_eq!(lines[0]["bind"], "127.0.0.1:8080");
    assert_eq!(lines[0]["level"], "INFO");

    // The writing site named neither, and the line carries both.
    assert_eq!(lines[0]["span"]["session"], "session-1");
    assert_eq!(lines[0]["span"]["user"], "user-1");

    // Absent means absent. An event belonging to no connection carries no
    // stand-in handle.
    assert_eq!(lines[1]["message"], "outside every connection");
    assert!(
        lines[1]["span"].is_null(),
        "an event outside every context must carry none: {}",
        lines[1]
    );
}
