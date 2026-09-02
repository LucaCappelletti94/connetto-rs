//! MIME-class chunking parameters: the table that governs content-defined
//! chunking, slab sizing, and compression for each file class.

/// Chunking and compression parameters for a MIME class.
///
/// When `avg` is zero the chunking strategy is fixed-size slabs of `max` bytes
/// rather than content-defined chunking. Otherwise `FastCDC` is used with the
/// given `min`, `avg`, and `max` values (all in bytes). In both cases a file
/// whose total length is at or under `max` skips chunking entirely and is
/// stored as one chunk.
#[derive(Debug, Clone, Copy)]
pub struct ChunkParams {
    /// Expected average chunk size in bytes. Zero selects fixed-size slabs.
    pub avg: u32,
    /// Minimum chunk size in bytes (ignored when `avg` is zero).
    pub min: u32,
    /// Maximum chunk size in bytes, and the slab size for fixed chunking.
    pub max: u32,
    /// Skip zstd compression for this class.
    ///
    /// True for already-compressed content where zstd produces no gain and
    /// wastes CPU. False for text-heavy scientific and generic data where
    /// compression roughly halves storage.
    pub skip_compression: bool,
}

/// MIME class used to select chunking parameters from the built-in table.
///
/// Classes that compress poorly (JPEG, PNG, video, gzip, zip) select
/// [`MEDIA_PARAMS`]. All other classes select [`TEXT_PARAMS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeClass {
    /// Nucleotide sequence data (FASTA format).
    Fasta,
    /// Mass spectrometry data (Mascot Generic Format).
    Mgf,
    /// Comma-separated values.
    Csv,
    /// JSON documents.
    Json,
    /// JPEG images.
    Jpeg,
    /// PNG images.
    Png,
    /// Video files (MP4, MKV, `WebM`, and similar).
    Video,
    /// gzip-compressed data.
    Gzip,
    /// ZIP archives.
    Zip,
    /// Any unrecognised or generic content.
    Generic,
}

/// Parameters for text, scientific, and generic classes.
///
/// `FastCDC` with 256 `KiB` min, 1 MiB average, 4 MiB max. zstd compression is
/// enabled because FASTA and similar data compresses well.
pub const TEXT_PARAMS: ChunkParams = ChunkParams {
    avg: 1_048_576,
    min: 262_144,
    max: 4_194_304,
    skip_compression: false,
};

/// Parameters for already-compressed media classes.
///
/// Fixed-size 16 MiB slabs (no CDC). Files at or under 16 MiB are stored as
/// one chunk. zstd is skipped because JPEG, PNG, video, gzip, and zip are
/// already compressed and zstd finds nothing to gain.
pub const MEDIA_PARAMS: ChunkParams = ChunkParams {
    avg: 0,
    min: 0,
    max: 16_777_216,
    skip_compression: true,
};

impl MimeClass {
    /// Returns the chunking parameters for this MIME class.
    #[must_use]
    pub const fn params(self) -> ChunkParams {
        match self {
            Self::Fasta | Self::Mgf | Self::Csv | Self::Json | Self::Generic => TEXT_PARAMS,
            Self::Jpeg | Self::Png | Self::Video | Self::Gzip | Self::Zip => MEDIA_PARAMS,
        }
    }
}
