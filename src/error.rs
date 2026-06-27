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

    /// snap error
    #[error(transparent)]
    SnapError(#[from] snap::Error),

    /// Snappy into_inner error when writing bytes to compression
    #[error("Snappy into_inner error when writing bytes to compression.")]
    SnapWriteIntoInnerError(String),

    // The old EciesError variant was removed as part of the clean break to the v2 symmetric model.
    // All encryption-related errors now go through the new symmetric primitives (see crypto.rs).
    /// bao decode error
    #[error(transparent)]
    BaoDecodeError(#[from] bao::decode::Error),

    /// FEC (reed-solomon-erasure) error. Transparent for now (structural; no secret leakage).
    #[error(transparent)]
    FecError(#[from] reed_solomon_erasure::Error),

    /// An uneven number of input bytes were provided for zfec chunks
    #[error("Input bytes must divide evenly over number of zfec chunks.")]
    UnevenZfecChunks,

    /// Unnecessary scrub
    #[error("Data does not need to be scrubbed.")]
    UnnecessaryScrub,

    /// Scrubbed padding has different lengths
    #[error("Scrubbed padding should remain the same.")]
    ScrubbedPaddingMismatch,

    /// Scrubbed data has different lengths
    #[error("Mismatch between scrubbed data length, input len: {0}, scrubbed len: {1}")]
    ScrubbedLengthMismatch(usize, usize),

    /// Scrub requires the Bao bit (uses slice extraction for FEC shard candidates)
    #[error(
        "Scrub requires Bao bit in format (for slice-based candidate extraction from verifiable)"
    )]
    ScrubRequiresBao,

    /// Hash decode error
    #[error("Hash must be {0} bytes long, an input of {1} bytes was provided.")]
    HashDecodeError(usize, usize),

    /// Invalid scrubbed bao hash
    #[error("Scrubbed hash is not equal to original hash.")]
    InvalidScrubbedHash,

    /// FEC padding should be zero when encoding (Carbonado adds its own)
    #[error("Padding from FEC should always be zero, since Carbonado adds its own padding. Padding was {0}.")]
    EncodeZfecPaddingError(usize),

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

    /// Invalid header length calculation
    #[error("Incorrect public key format")]
    IncorrectPubKeyFormat,

    // === New symmetric crypto errors (v2) ===
    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Ciphertext too short (expected at least nonce+tag or tag for the provided nonce)")]
    InvalidCiphertextLength,

    #[error("HMAC authentication failed")]
    AuthenticationFailed,

    #[error("Failed to obtain randomness")]
    RandomnessError,

    #[error("Not implemented")]
    NotImplemented,

    /// Post-quantum cryptography operation failed (SLH-DSA etc. via libbitcoinpqc)
    #[error("Post-quantum cryptography error: {0}")]
    PqcError(String),

    /// Internal state corruption (e.g. poisoned lock in streaming helpers)
    #[error("Internal state corrupted: {0}")]
    InternalStateError(String),
}
