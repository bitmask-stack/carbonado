use thiserror::Error;

#[derive(Error, Debug)]
pub enum CarbonadoError {
    /// std io error
    #[error(transparent)]
    StdIoError(#[from] std::io::Error),

    /// std array tryfromslice error
    #[error(transparent)]
    StdArrayTryFromSliceError(#[from] std::array::TryFromSliceError),

    /// Infallable error (errors that can never happen)
    #[error(transparent)]
    Infallible(#[from] std::convert::Infallible),

    /// zstd error
    #[error("zstd encode/decode failed: {0}")]
    ZstdError(String),

    // The old EciesError variant was removed as part of the clean break to the v2 symmetric model.
    // All encryption-related errors now go through the new symmetric primitives (see crypto.rs).
    /// bao decode error
    #[error(transparent)]
    BaoDecodeError(#[from] bao::decode::Error),

    /// FEC (reed-solomon-erasure) error. Transparent for now (structural; no secret leakage).
    #[error(transparent)]
    FecError(reed_solomon_erasure::Error),

    /// FEC shard geometry does not divide evenly over the stripe layout.
    #[error("Input bytes must divide evenly over FEC shard count.")]
    UnevenFecChunks,

    /// Unnecessary scrub
    #[error("Data does not need to be scrubbed.")]
    UnnecessaryScrub,

    /// Scrubbed padding has different lengths
    #[error("Scrubbed padding should remain the same.")]
    ScrubbedPaddingMismatch,

    /// Scrubbed data has different lengths
    #[error("Mismatch between scrubbed data length, input len: {0}, scrubbed len: {1}")]
    ScrubbedLengthMismatch(usize, usize),

    /// Scrub requires the Verification bit (slice extraction for FEC shard candidates).
    #[error(
        "Scrub requires Verification bit in format (for slice-based candidate extraction from verifiable)"
    )]
    ScrubRequiresVerification,

    /// Hash decode error
    #[error("Hash must be {0} bytes long, an input of {1} bytes was provided.")]
    HashDecodeError(usize, usize),

    /// Invalid scrubbed bao hash
    #[error("Scrubbed hash is not equal to original hash.")]
    InvalidScrubbedHash,

    /// FEC padding should be zero when encoding (Carbonado adds its own)
    #[error("Padding from FEC should always be zero, since Carbonado adds its own padding. Padding was {0}.")]
    EncodeFecPaddingError(usize),

    /// Invalid chunk length
    #[error("Chunk length should be as calculated. Calculated chunk length was {0}, but actual chunk length was {1}")]
    EncodeInvalidChunkLength(u32, usize),

    /// Invalid verifiable slice length
    #[error("Verifiable slice count should be evenly divisible by 8. Remainder was {0}.")]
    InvalidVerifiableSliceCount(u32),

    /// Invalid magic number
    #[error("File header lacks Carbonado magic number and may not be a proper Carbonado file. Magic number found was {0}.")]
    InvalidMagicNumber(String),

    /// Invalid header length calculation
    #[error("Invalid header length calculation")]
    InvalidHeaderLength,

    /// Missing required verification outboard sidecar for outboard decode.
    #[error("Verification outboard sidecar data required for this format but not supplied")]
    MissingVerificationOutboard,

    /// Missing required FEC parity sidecar for outboard decode.
    #[error("FEC parity sidecar data required for Fec outboard format but not supplied")]
    MissingFecParity,

    /// Outboard sidecar validation failed (e.g. malformed sidecar data or read failure)
    #[error("Outboard sidecar verification failed: {0}")]
    OutboardVerificationFailed(String),

    /// Inboard bao response truncated or incomplete during keyed decode
    #[error("Bao inboard response truncated: {0}")]
    BaoResponseTruncated(String),

    /// Slice index starts at or beyond logical content length
    #[error("Invalid slice index {index} for content length {content_len} bytes")]
    InvalidSliceIndex { index: u32, content_len: u64 },

    /// Incorrect public key format (legacy v1 ECIES-era; unused in v2 symmetric clean break).
    /// Retained to avoid breaking changes to the error enum surface.
    #[error("Incorrect public key format")]
    IncorrectPubKeyFormat,

    // === New symmetric crypto errors (v2) ===
    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Ciphertext too short (expected at least nonce+tag or tag for the provided nonce)")]
    InvalidCiphertextLength,

    /// Declared ciphertext length exceeded during bounded streaming decrypt.
    #[error("Ciphertext exceeds declared length ({declared} bytes declared)")]
    CiphertextExceedsDeclaredLength { declared: u64 },

    /// Declared encoded-body length exceeded during bounded inboard decode.
    #[error("Encoded body exceeds declared length ({declared} bytes declared)")]
    EncodedBodyExceedsDeclaredLength { declared: u64 },

    #[error("HMAC authentication failed")]
    AuthenticationFailed,

    #[error("Failed to obtain randomness")]
    RandomnessError,

    /// Reserved for optional or not-yet-shipped features (distinct from v1 removal).
    #[error("Not implemented")]
    NotImplemented,

    /// Post-quantum cryptography operation failed (SLH-DSA etc. via `bitcoinpqc`)
    #[error("Post-quantum cryptography error: {0}")]
    PqcError(String),

    /// Internal state corruption (e.g. poisoned lock in streaming helpers)
    #[error("Internal state corrupted: {0}")]
    InternalStateError(String),

    /// Adamantine catalog wire envelope has invalid magic (expected `ADAMANTINE10\n`)
    #[error("Invalid Adamantine magic")]
    InvalidAdamantineMagic,

    /// Adamantine catalog version is not supported (v1.0 requires `ADAMANTINE10\n`)
    #[error("Unsupported Adamantine version: {major}.{minor}")]
    UnsupportedAdamantineVersion { major: u8, minor: u8 },

    /// Adamantine header is truncated or malformed
    #[error("Invalid Adamantine header")]
    InvalidAdamantineHeader,

    /// Adamantine payload_len does not match available bytes
    #[error("Invalid Adamantine payload length: expected {expected}, available {available}")]
    InvalidAdamantinePayloadLength { expected: u32, available: usize },

    /// Adamantine declared payload_len exceeds the maximum allowed rkyv payload size
    #[error("Adamantine payload too large: declared {declared} bytes, max {max}")]
    InvalidAdamantinePayloadTooLarge { declared: u32, max: usize },

    /// Adamantine flags are invalid for v1.0 (reserved bits set)
    #[error("Invalid Adamantine flags: {0}")]
    InvalidAdamantineFlags(u8),

    /// Adamantine carbonado_fmt byte is not a valid directory catalog format (c14/c15)
    #[error(
        "Invalid Adamantine carbonado format: expected 0x0E (c14) or 0x0F (c15), got 0x{0:02x}"
    )]
    InvalidAdamantineCarbonadoFormat(u8),

    /// Adamantine header `carbonado_fmt` disagrees with the format parsed from the `.adam.c{N}` filename
    #[error(
        "Adamantine carbonado_fmt 0x{header:02x} does not match catalog filename format 0x{filename:02x}"
    )]
    AdamantineFormatFilenameMismatch { header: u8, filename: u8 },

    /// Directory encode options disagree (e.g. odd format without `encrypted`, or even explicit format with `encrypted`)
    #[error("directory format options conflict: {0}")]
    DirectoryFormatConflict(String),

    /// Deprecated directory layout mismatch (pre–Adamantine 1.0); retained for error taxonomy stability
    #[error("directory layout mismatch: {0}")]
    DirectoryLayoutMismatch(String),

    /// Per-file segment format disagrees with catalog encryption or allowed c12–c15 (Verification+FEC)
    #[error("segment format mismatch: {0}")]
    SegmentFormatMismatch(String),

    /// Legacy CBOR filepack manifest failed parsing or conversion (interop only)
    #[error("Invalid filepack CBOR: {0}")]
    InvalidFilepackCbor(String),

    /// rkyv FilepackManifest payload failed validation or deserialization
    #[error("Invalid FilepackManifest: {0}")]
    InvalidFilepackManifest(String),

    /// FilepackManifest catalog_bao_root does not match filename or decoded catalog root
    #[error("Catalog bao root mismatch")]
    CatalogBaoRootMismatch,

    /// Encrypted directory/catalog operations require a non-zero master key
    #[error("Encrypted format requires a non-zero master key")]
    ZeroMasterKeyNotAllowed,

    /// Non-zero master key supplied without `DirectoryEncodeOptions.encrypted = true`
    #[error("non-zero master key requires explicit encrypted directory encode")]
    EncryptedDirectoryNotRequested,

    /// OpenTimestamps proof failed verification against the expected Bao root
    #[error("OpenTimestamps proof verification failed")]
    OtsVerificationFailed,

    /// OpenTimestamps proof blob exceeds maximum allowed size or is malformed
    #[error("Invalid OpenTimestamps proof: {0}")]
    InvalidOtsProof(String),

    /// Directory decode requires the `ots` feature to verify REQUIRE_OTS proofs
    #[error("archive requires the `ots` feature to verify REQUIRE_OTS proofs")]
    OtsFeatureRequired,

    /// REQUIRE_OTS flag set but entry has no ots_proof
    #[error("REQUIRE_OTS flag set but entry {0} has no ots_proof")]
    OtsProofRequired(String),

    /// Segment main artifact length does not match manifest main_len
    #[error("main_len mismatch for {rel_path} chunk_index {chunk_index}")]
    SegmentMainLenMismatch { rel_path: String, chunk_index: u32 },

    /// Segment header Bao root does not match manifest `segment_bao_root`
    #[error("segment bao root mismatch for {rel_path} chunk_index {chunk_index}")]
    SegmentBaoRootMismatch { rel_path: String, chunk_index: u32 },

    /// Recovered file content does not match manifest content_blake3
    #[error("content_blake3 mismatch for {0}")]
    ContentBlake3Mismatch(String),

    /// Resolved output path escapes the output directory
    #[error("path escapes output directory: {0}")]
    OutputPathEscape(String),

    /// Directory archive input path is not a directory
    #[error("Path is not a directory: {0}")]
    NotADirectory(String),

    /// Missing segment file during directory decode
    #[error("Missing segment for {0}")]
    MissingSegment(String),

    /// Symlinks are not followed or archived in directory encode
    #[error("Symlinks are not allowed in directory archives: {0}")]
    SymlinkNotAllowed(String),

    /// Catalog `.adam.c14`/`.adam.c15` path or filename is invalid
    #[error("Invalid catalog path: {0}")]
    InvalidCatalogPath(String),

    /// Directory encode encountered an unsupported file type (FIFO, socket, device, etc.)
    #[error("Unsupported file type in directory archive: {0}")]
    UnsupportedFileType(String),

    /// Segment mains/sidecars exist but `{catalog}.adam.cXX` catalog is missing.
    #[error("Missing directory catalog: {0}")]
    MissingCatalog(String),

    /// Encrypted outboard decode requires an out-of-band header carrying `payload_nonce`.
    #[error("Encrypted outboard decode requires out-of-band header for payload nonce")]
    MissingOutboardHeader,

    /// Shard iterator is not a contiguous sequence starting at chunk_index 0.
    #[error("Invalid shard sequence: {0}")]
    InvalidShardSequence(String),

    /// Two or more shards share the same chunk_index.
    #[error("Duplicate shard index: {0}")]
    DuplicateShardIndex(u32),

    /// Expected chunk_index is missing from the shard set.
    #[error("Missing shard index: expected {expected}, found {found}")]
    MissingShardIndex { expected: u32, found: u32 },

    /// Caller-supplied `ShardSource.chunk_index` does not match the authenticated header value.
    #[error(
        "Shard index mismatch: caller claimed {claimed}, header authenticated {authenticated}"
    )]
    ShardIndexMismatch { claimed: u32, authenticated: u32 },
}

impl From<reed_solomon_erasure::Error> for CarbonadoError {
    fn from(value: reed_solomon_erasure::Error) -> Self {
        Self::FecError(value)
    }
}
