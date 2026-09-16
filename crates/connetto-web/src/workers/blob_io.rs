//! Streaming read and write over `web_sys::Blob`.
//!
//! [`BlobSource`] implements [`std::io::Read`] and [`std::io::Seek`] so any
//! reader that works on a synchronous `Cursor<Vec<u8>>` works on a `Blob`
//! from the tab.
//! The `Blob` handle crosses `postMessage` without copying its bytes, and each
//! read pulls one slice through `FileReaderSync`, the one synchronous seekable
//! read a dedicated worker has.
//!
//! [`BlobSink`] implements [`std::io::Write`].
//! Every full part is turned into its own `web_sys::Blob` pushed onto an
//! array so the browser can spill it to disk, and nothing in this module holds
//! the full archive at once.

use std::io;

/// A browser refusal on the way in or out of a [`Blob`](web_sys::Blob).
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// `FileReaderSync` is absent, which is what a page rather than a
    /// dedicated worker meets.
    #[error("this context has no FileReaderSync, so a blob cannot be read here: {detail}")]
    NoReader {
        /// The browser exception text.
        detail: String,
    },
    /// One part of a sink could not become a blob of its own.
    #[error("the browser refused one part of the archive: {detail}")]
    Part {
        /// The browser exception text.
        detail: String,
    },
    /// The parts could not be joined into the archive.
    #[error("the browser refused the archive built from its parts: {detail}")]
    Archive {
        /// The browser exception text.
        detail: String,
    },
}

/// A synchronous seekable reader over a `web_sys::Blob`.
///
/// Each read pulls one slice through `FileReaderSync`, so it must run inside
/// a dedicated worker.
/// The constructor reports the absence of `FileReaderSync` rather than
/// panicking, which is what a page rather than a worker would meet.
pub struct BlobSource {
    blob: web_sys::Blob,
    reader: web_sys::FileReaderSync,
    /// Current read position in bytes.
    pos: u64,
    /// Total blob length in bytes.
    len: u64,
}

impl BlobSource {
    /// Opens a synchronous reader over `blob`.
    ///
    /// # Errors
    ///
    /// Returns a [`BlobError`] when `FileReaderSync::new()` fails, which
    /// happens outside a dedicated worker.
    pub fn new(blob: web_sys::Blob) -> Result<Self, BlobError> {
        let reader = web_sys::FileReaderSync::new().map_err(|err| BlobError::NoReader {
            detail: format!("{err:?}"),
        })?;
        let size = blob.size();
        debug_assert!(
            size.is_finite() && size >= 0.0 && size.fract() == 0.0,
            "Blob.size must be a finite non-negative integer"
        );
        // An f64 is exact to 2^53 bytes, well above any blob a browser holds.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "Blob.size is a finite non-negative integer byte count"
        )]
        let len = size as u64;
        Ok(Self {
            blob,
            reader,
            pos: 0,
            len,
        })
    }
}

impl io::Read for BlobSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let remaining = self.len - self.pos;
        let buf_len =
            u64::try_from(buf.len()).map_err(|_| io::Error::other("buffer length exceeds u64"))?;
        let to_read = remaining.min(buf_len);
        let end = self.pos + to_read;
        // A position inside a browser blob stays inside the f64 exact range.
        debug_assert!(
            end <= (1_u64 << 53),
            "blob position must fit in f64 exact integer range"
        );
        #[expect(
            clippy::cast_precision_loss,
            reason = "positions within browser blob fit in f64 exact integer range"
        )]
        let slice = self
            .blob
            .slice_with_f64_and_f64(self.pos as f64, end as f64)
            .map_err(|_| io::Error::other("Blob.slice failed"))?;
        let buffer = self
            .reader
            .read_as_array_buffer(&slice)
            .map_err(|_| io::Error::other("FileReaderSync.readAsArrayBuffer failed"))?;
        let array = js_sys::Uint8Array::new(&buffer);
        let bytes_read = usize::try_from(array.byte_length())
            .expect("a Uint8Array byte length fits usize on supported targets");
        if bytes_read > buf.len() {
            return Err(io::Error::other(
                "the blob slice read back longer than it was asked for",
            ));
        }
        array.copy_to(&mut buf[..bytes_read]);
        self.pos += u64::try_from(bytes_read).expect("a read length fits u64");
        Ok(bytes_read)
    }
}

impl io::Seek for BlobSource {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let len_i64 = i64::try_from(self.len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "blob too large for seek arithmetic",
            )
        })?;
        let new_pos: i64 = match pos {
            io::SeekFrom::Start(n) => i64::try_from(n).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "seek offset too large for i64")
            })?,
            io::SeekFrom::End(n) => len_i64.checked_add(n).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "seek arithmetic overflow")
            })?,
            io::SeekFrom::Current(n) => i64::try_from(self.pos)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "current position too large for i64",
                    )
                })?
                .checked_add(n)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek arithmetic overflow")
                })?,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start of blob",
            ));
        }
        // Guarded by the new_pos >= 0 check above.
        #[expect(clippy::cast_sign_loss, reason = "guarded by non-negative check above")]
        let new_u64 = new_pos as u64;
        self.pos = new_u64;
        Ok(self.pos)
    }
}

/// Maximum bytes per part before the current buffer is flushed to a [`Blob`](web_sys::Blob).
const PART_BYTES: usize = 4 * 1024 * 1024;

/// A streaming writer whose output the browser owns part by part.
///
/// Each full part becomes a `web_sys::Blob` at once, which the browser may
/// spill to disk, so this holds one part and never the archive.
/// [`into_blob`](BlobSink::into_blob) closes the tail part and returns one
/// `Blob` over the sequence.
pub struct BlobSink {
    /// One `web_sys::Blob` per part written so far.
    parts: js_sys::Array,
    /// The part being filled, cleared each time it reaches `PART_BYTES`.
    buf: Vec<u8>,
}

impl BlobSink {
    /// Creates an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parts: js_sys::Array::new(),
            buf: Vec::new(),
        }
    }

    /// Hands `bytes` to the browser as one more part.
    fn push_part(parts: &js_sys::Array, bytes: &[u8]) -> Result<(), BlobError> {
        let array = js_sys::Uint8Array::from(bytes);
        let part = web_sys::Blob::new_with_u8_array_sequence(&js_sys::Array::of1(&array)).map_err(
            |err| BlobError::Part {
                detail: format!("{err:?}"),
            },
        )?;
        parts.push(&part);
        Ok(())
    }

    /// Closes the part being filled, if it holds anything.
    fn flush_part(&mut self) -> Result<(), BlobError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        Self::push_part(&self.parts, &self.buf)?;
        self.buf.clear();
        Ok(())
    }

    /// Closes the tail part and returns one `Blob` over every part.
    ///
    /// # Errors
    ///
    /// Returns a [`BlobError`] when the browser refuses a `Blob` constructor.
    pub fn into_blob(mut self) -> Result<web_sys::Blob, BlobError> {
        self.flush_part()?;
        web_sys::Blob::new_with_blob_sequence(&self.parts).map_err(|err| BlobError::Archive {
            detail: format!("{err:?}"),
        })
    }
}

impl Default for BlobSink {
    fn default() -> Self {
        Self::new()
    }
}

impl io::Write for BlobSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // A whole chunk arrives as one write, so it becomes its own part
        // rather than being copied through the part buffer.
        if self.buf.is_empty() && data.len() >= PART_BYTES {
            Self::push_part(&self.parts, data).map_err(io::Error::other)?;
            return Ok(data.len());
        }
        let mut remaining = data;
        while !remaining.is_empty() {
            let space = PART_BYTES - self.buf.len();
            let take = remaining.len().min(space);
            self.buf.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.buf.len() >= PART_BYTES {
                self.flush_part().map_err(io::Error::other)?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
