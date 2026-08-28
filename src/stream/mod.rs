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

pub use fec::{
    concat_data_leaves, concat_parity_leaves, encode_stripes, stripe_data_and_parity_leaves,
    write_data_leaves, write_outboard_parity,
};
pub use slice::{
    classify_inboard_leaves, inboard_leaf_data_ranges, leaf_index_to_stripe_symbol,
    slice_to_chunk_ranges, stripe_symbol_to_leaf_index, verify_slice_inboard_seekable,
    verify_slice_outboard,
};

pub use compress::ZstdEncode;
pub use decode::{
    stream_decode, stream_decode_buffer, stream_decode_outboard, stream_decode_outboard_buffer,
    stream_decode_outboard_buffer_with_dict, stream_decrypt_header_path,
};
#[cfg(feature = "async")]
pub use decode_async::stream_decode_async;
pub use encode::{
    stream_encode_buffer, stream_encode_buffer_with_nonce, stream_encode_buffer_with_zstd,
    stream_encode_inboard, stream_encode_inboard_body, stream_encode_inboard_with_nonce,
    stream_encode_outboard, stream_encode_outboard_buffer, stream_preprocess,
};
pub use shard::{
    DEFAULT_SEGMENT_PLAINTEXT_BUDGET, ShardEncodeResult, ShardSource, decode_shards_stream,
    encode_shard_stream, encode_shard_stream_with_zstd,
};
