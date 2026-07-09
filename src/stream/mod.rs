//! Streaming encode/decode pipeline (Carbonado v2 P2 + P3 segment sharding).
//!
//! Buffer `&[u8]` helpers in [`crate::encoding`] / [`crate::decoding`] delegate here.
//!
//! P3 multi-segment sharding lives in [`shard`]: [`encode_shard_stream`] requires
//! [`std::io::BufRead`] on the input (use [`std::io::BufReader`] for unbuffered sources)
//! so `has_more` can peek without losing bytes between shards.

pub mod bao;
pub mod compress;
pub mod crypto_stream;
pub mod decode;
#[cfg(feature = "async")]
mod decode_async;
pub mod encode;
pub mod fec;
pub mod io;
#[cfg(feature = "parallel")]
#[doc(hidden)]
pub mod parallel;
pub mod shard;
pub mod slice;
pub(crate) mod spool;

pub(crate) use slice::extract_slice_inboard_for_scrub;
pub use slice::{slice_to_chunk_ranges, verify_slice_inboard_seekable, verify_slice_outboard};

pub use decode::{
    stream_decode, stream_decode_buffer, stream_decode_outboard, stream_decode_outboard_buffer,
    stream_decrypt_header_path,
};
#[cfg(feature = "async")]
pub use decode_async::stream_decode_async;
pub use encode::{
    stream_encode_buffer, stream_encode_inboard, stream_encode_inboard_body,
    stream_encode_outboard, stream_encode_outboard_buffer, stream_preprocess,
};
pub use shard::{
    decode_shards_stream, encode_shard_stream, ShardEncodeResult, ShardSource,
    DEFAULT_SEGMENT_PLAINTEXT_BUDGET,
};
