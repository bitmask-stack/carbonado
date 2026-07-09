//! Multi-segment sharding via authenticated `Header.chunk_index` (P3).

use std::io::{BufRead, Read, Write};

use crate::{
    constants::Format,
    error::CarbonadoError,
    file::{decode_stream, Header},
    structs::EncodeInfo,
};

/// Default max logical plaintext bytes per shard (`u32::MAX` logical bytes).
///
/// Matches the `u32` bookkeeping ceiling for [`EncodeInfo::input_len`] and the practical
/// per-segment limit implied by u32 `Header.encoded_len` / `EncodeInfo::bytes_verifiable`
/// after compression, encryption, FEC, and Bao expansion. Callers may pass a smaller
/// `segment_plaintext_budget` for application-level chunking.
pub const DEFAULT_SEGMENT_PLAINTEXT_BUDGET: u64 = u32::MAX as u64;

/// Result of encoding one shard from a longer input stream.
#[derive(Clone, Debug)]
pub struct ShardEncodeResult {
    pub header: Header,
    pub encode_info: EncodeInfo,
    /// `true` when unread input remains after this shard (caller should encode again with
    /// `chunk_index + 1`).
    pub has_more: bool,
}

fn has_more_buffered_input<R: BufRead>(reader: &mut R) -> Result<bool, CarbonadoError> {
    let buf = reader.fill_buf().map_err(CarbonadoError::StdIoError)?;
    Ok(!buf.is_empty())
}

/// Encode one inboard shard (header returned separately; body written to `output`).
///
/// Reads from `input` until `segment_plaintext_budget` logical plaintext bytes are consumed
/// or EOF is reached. Each shard receives an independent keyed Bao root in its header.
/// `chunk_index` is bound under `header_mac` (see [`Header::new`]).
///
/// `input` should be wrapped in [`std::io::BufReader`] when reading from an unbuffered source
/// so `has_more` detection can peek without losing bytes.
pub fn encode_shard_stream<R: BufRead, W: Write>(
    master_key: &[u8],
    mut input: R,
    format: u8,
    chunk_index: u32,
    segment_plaintext_budget: u64,
    metadata: Option<[u8; 8]>,
    mut output: W,
) -> Result<ShardEncodeResult, CarbonadoError> {
    let fmt = Format::from(format);
    let mut payload_nonce = [0u8; 16];
    let mut limited = input.by_ref().take(segment_plaintext_budget);
    let (hash, info, stats) = crate::stream::encode::stream_encode_inboard(
        master_key,
        &mut limited,
        format,
        &mut output,
        &mut payload_nonce,
        true,
    )?;

    let has_more = if stats.input_len == segment_plaintext_budget {
        has_more_buffered_input(&mut input)?
    } else {
        false
    };

    let header = Header::new(
        master_key,
        payload_nonce,
        hash.as_bytes(),
        [0u8; 32],
        fmt,
        chunk_index,
        info.output_len,
        info.padding_len,
        metadata,
    )?;
    Ok(ShardEncodeResult {
        header,
        encode_info: info,
        has_more,
    })
}

/// One encoded shard (header + body) identified by its authenticated `chunk_index`.
#[derive(Clone, Debug)]
pub struct ShardSource {
    pub chunk_index: u32,
    pub encoded: Vec<u8>,
}

/// Decode an ordered shard set and concatenate plaintext to `output`.
///
/// Shards must form a contiguous `chunk_index` sequence `0..N-1` with no duplicates or gaps.
/// An empty shard iterator yields `Ok(0)` with no output written.
/// Returns total plaintext bytes written.
///
/// When `ShardSource.chunk_index` disagrees with the authenticated header after MAC verify,
/// returns [`CarbonadoError::ShardIndexMismatch`].
pub fn decode_shards_stream<W: Write>(
    master_key: &[u8],
    shards: impl IntoIterator<Item = ShardSource>,
    mut output: W,
) -> Result<u64, CarbonadoError> {
    let mut shards: Vec<ShardSource> = shards.into_iter().collect();
    if shards.is_empty() {
        return Ok(0);
    }

    shards.sort_by_key(|s| s.chunk_index);

    if shards[0].chunk_index != 0 {
        return Err(CarbonadoError::InvalidShardSequence(
            "shards must start at chunk_index 0".into(),
        ));
    }

    for window in shards.windows(2) {
        if window[0].chunk_index == window[1].chunk_index {
            return Err(CarbonadoError::DuplicateShardIndex(window[1].chunk_index));
        }
    }

    let mut total = 0u64;
    for (expected, shard) in shards.iter().enumerate() {
        let expected = expected as u32;
        if shard.chunk_index != expected {
            return Err(CarbonadoError::MissingShardIndex {
                expected,
                found: shard.chunk_index,
            });
        }

        let mut cursor = std::io::Cursor::new(&shard.encoded);
        let (header, written) = decode_stream(master_key, &mut cursor, &mut output)?;
        if header.chunk_index != shard.chunk_index {
            return Err(CarbonadoError::ShardIndexMismatch {
                claimed: shard.chunk_index,
                authenticated: header.chunk_index,
            });
        }

        total += written;
    }

    Ok(total)
}
