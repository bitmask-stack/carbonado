use std::io::{Cursor, Read};

use bao_tree::{
    io::{
        outboard::{EmptyOutboard, PostOrderMemOutboard},
        sync::{keyed_decode_ranges, keyed_valid_ranges, ReadAt, WriteAt},
        DecodeError,
    },
    iter::BaoChunk,
    BaoTree, ChunkNum, ChunkRanges,
};

use crate::{
    constants::{BAO_BLOCK_SIZE, SLICE_LEN},
    crypto::carbonado_bao_key,
    error::CarbonadoError,
    utils::decode_bao_hash,
};

/// Blake3 chunks (1 KiB each) covered by one 4 KiB Carbonado slice / Bao leaf.
const CHUNKS_PER_SLICE: u64 = 1 << BAO_BLOCK_SIZE.chunk_log();

/// Map a contiguous run of 4 KiB slice indices to keyed-bao [`ChunkRanges`].
pub fn slice_to_chunk_ranges(index: u32, count: u32) -> ChunkRanges {
    let start = ChunkNum(u64::from(index) * CHUNKS_PER_SLICE);
    let end = ChunkNum(u64::from(index + count) * CHUNKS_PER_SLICE);
    ChunkRanges::from(start..end)
}

/// Map bao-tree [`DecodeError`] to [`CarbonadoError`] (shared by full decode and slice verify).
pub(crate) fn map_decode_error(err: DecodeError) -> CarbonadoError {
    match err {
        DecodeError::ParentHashMismatch(_) | DecodeError::LeafHashMismatch(_) => {
            CarbonadoError::AuthenticationFailed
        }
        DecodeError::ParentNotFound(node) => CarbonadoError::BaoResponseTruncated(format!(
            "parent hash pair missing at tree node {:?}",
            node
        )),
        DecodeError::LeafNotFound(chunk) => CarbonadoError::BaoResponseTruncated(format!(
            "leaf data missing at chunk offset {}",
            chunk.to_bytes()
        )),
        DecodeError::Io(e) => CarbonadoError::StdIoError(e),
    }
}

fn map_valid_ranges_read_error(err: std::io::Error) -> CarbonadoError {
    CarbonadoError::OutboardVerificationFailed(format!(
        "bao outboard data read during slice validation: {err}"
    ))
}

fn chunk_count(ranges: &ChunkRanges) -> u64 {
    ranges
        .boundaries()
        .windows(2)
        .map(|w| (w[1] - w[0]).0)
        .sum()
}

/// Returns `(slice_byte_start, slice_byte_end, actual_len)` or [`CarbonadoError::InvalidSliceIndex`].
fn slice_byte_range(
    index: u32,
    count: u32,
    content_len: u64,
) -> Result<(u64, u64, u64), CarbonadoError> {
    let slice_byte_start = u64::from(index) * u64::from(SLICE_LEN);
    if slice_byte_start >= content_len {
        return Err(CarbonadoError::InvalidSliceIndex { index, content_len });
    }
    let slice_byte_len = u64::from(count) * u64::from(SLICE_LEN);
    let slice_byte_end = slice_byte_start
        .saturating_add(slice_byte_len)
        .min(content_len);
    let actual_len = slice_byte_end.saturating_sub(slice_byte_start);
    Ok((slice_byte_start, slice_byte_end, actual_len))
}

/// In-memory [`WriteAt`] target that retains only the requested byte sub-range.
///
/// Used with a full-layout (`ChunkRanges::all()`) keyed decode over inboard responses;
/// discards writes outside the slice window so memory stays O(slice).
struct SliceRegionWriter {
    region_start: u64,
    region_end: u64,
    buf: Vec<u8>,
}

impl SliceRegionWriter {
    fn for_region(region_start: u64, region_len: u64) -> Self {
        Self {
            region_start,
            region_end: region_start.saturating_add(region_len),
            buf: vec![0u8; region_len as usize],
        }
    }
}

impl WriteAt for SliceRegionWriter {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::io::Result<usize> {
        let write_start = offset.max(self.region_start);
        let write_end = offset
            .saturating_add(data.len() as u64)
            .min(self.region_end);
        if write_start >= write_end {
            return Ok(data.len());
        }
        let skip = (write_start - offset) as usize;
        let rel = (write_start - self.region_start) as usize;
        let len = (write_end - write_start) as usize;
        self.buf[rel..rel + len].copy_from_slice(&data[skip..skip + len]);
        Ok(data.len())
    }

    fn write_all_at(&mut self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.write_at(offset, data)?;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Verified read of `count` contiguous 4 KiB slices at `index` from an inboard bao
/// response (`[u64le content_len | response_bytes]`).
///
/// **Memory:** O(slice) via [`SliceRegionWriter`].
///
/// **Time / I/O:** O(N) over the embedded bao response bytes. Inboard artifacts store a
/// full `ChunkRanges::all()` response; partial keyed decode desyncs the sequential reader,
/// so verification walks the entire encoded stream even when only one slice is requested.
pub fn verify_slice_inboard_seekable(
    input: &[u8],
    index: u32,
    count: u32,
    hash: &[u8],
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    if count == 0 {
        return Ok(vec![]);
    }
    if input.len() < 8 {
        return Err(CarbonadoError::InvalidHeaderLength);
    }
    let clen_bytes: [u8; 8] = input[0..8]
        .try_into()
        .map_err(|_| CarbonadoError::InvalidHeaderLength)?;
    let content_len = u64::from_le_bytes(clen_bytes);
    if content_len == 0 {
        return Err(CarbonadoError::InvalidSliceIndex { index, content_len });
    }
    let response = &input[8..];
    let root = decode_bao_hash(hash)?;
    let tree = BaoTree::new(content_len, BAO_BLOCK_SIZE);
    let key = carbonado_bao_key(format);
    // Inboard artifacts embed a full bao response (encode uses ChunkRanges::all()); partial
    // keyed decode ranges only match partial responses, so verify walks the full layout.
    let ranges = ChunkRanges::all();

    let (slice_byte_start, _slice_byte_end, actual_len) =
        slice_byte_range(index, count, content_len)?;

    let mut writer = SliceRegionWriter::for_region(slice_byte_start, actual_len);
    let mut ob = EmptyOutboard { tree, root };
    keyed_decode_ranges(Cursor::new(response), &ranges, &mut writer, &mut ob, &key)
        .map_err(map_decode_error)?;

    Ok(writer.buf)
}

/// Unvalidated inboard slice extraction for scrub candidate shards.
///
/// P1-SCRUB: pre-order walk over full inboard response layout is allowed here; must not
/// allocate an O(N) logical buffer (only the requested shard bytes are retained).
///
/// Walks the bao response sequentially (early-stop once the slice window is filled).
/// Does not perform keyed hash checks; RS + re-bao oracle in scrub filters bad candidates.
/// Returns [`CarbonadoError::BaoResponseTruncated`] if the response ends before the slice
/// window is fully populated.
pub(crate) fn extract_slice_inboard_for_scrub(
    input: &[u8],
    index: u32,
    count: u32,
) -> Result<Vec<u8>, CarbonadoError> {
    if count == 0 {
        return Ok(vec![]);
    }
    if input.len() < 8 {
        return Err(CarbonadoError::InvalidHeaderLength);
    }
    let clen_bytes: [u8; 8] = input[0..8]
        .try_into()
        .map_err(|_| CarbonadoError::InvalidHeaderLength)?;
    let content_len = u64::from_le_bytes(clen_bytes);
    if content_len == 0 {
        return Err(CarbonadoError::InvalidSliceIndex { index, content_len });
    }
    let response = &input[8..];
    let tree = BaoTree::new(content_len, BAO_BLOCK_SIZE);

    let (slice_byte_start, slice_byte_end, actual_len) =
        slice_byte_range(index, count, content_len)?;

    let mut out = vec![0u8; actual_len as usize];
    let mut cursor = Cursor::new(response);
    let mut logical_offset = 0u64;
    let mut filled = 0usize;
    // Inboard blobs always embed a full (ChunkRanges::all()) bao response; walk that layout
    // sequentially but only retain bytes for the requested slice (no full-stream alloc).
    let ranges = ChunkRanges::all();

    for item in tree.ranges_pre_order_chunks_iter_ref(&ranges, 0) {
        match item {
            BaoChunk::Parent { .. } => {
                let mut skip = [0u8; 64];
                cursor
                    .read_exact(&mut skip)
                    .map_err(|e| CarbonadoError::BaoResponseTruncated(e.to_string()))?;
            }
            BaoChunk::Leaf { size, .. } => {
                let mut sz = size as u64;
                let remain = content_len.saturating_sub(logical_offset);
                if sz > remain {
                    sz = remain;
                }
                let leaf_start = logical_offset;
                let leaf_end = logical_offset.saturating_add(sz);
                logical_offset = leaf_end;

                let mut leaf = vec![0u8; sz as usize];
                cursor
                    .read_exact(&mut leaf)
                    .map_err(|e| CarbonadoError::BaoResponseTruncated(e.to_string()))?;

                if leaf_end > slice_byte_start && leaf_start < slice_byte_end {
                    let copy_start = leaf_start.max(slice_byte_start);
                    let copy_end = leaf_end.min(slice_byte_end);
                    let src_off = (copy_start - leaf_start) as usize;
                    let dst_off = (copy_start - slice_byte_start) as usize;
                    let len = (copy_end - copy_start) as usize;
                    out[dst_off..dst_off + len].copy_from_slice(&leaf[src_off..src_off + len]);
                    filled += len;
                }

                if logical_offset >= slice_byte_end {
                    break;
                }
            }
        }
    }

    if filled < actual_len as usize {
        return Err(CarbonadoError::BaoResponseTruncated(format!(
            "scrub slice extract incomplete: got {filled} of {actual_len} bytes at index {index}"
        )));
    }
    Ok(out)
}

/// Verified read of `count` contiguous 4 KiB slices at `index` from bare data plus a
/// post-order outboard sidecar.
///
/// **Memory and time:** O(slice) — validates only the requested chunk ranges via
/// `keyed_valid_ranges`, then reads the corresponding bare bytes.
pub fn verify_slice_outboard<D: ReadAt>(
    data: D,
    outboard_bytes: &[u8],
    data_len: u64,
    index: u32,
    count: u32,
    hash: &[u8],
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    if count == 0 {
        return Ok(vec![]);
    }
    if data_len == 0 {
        return Err(CarbonadoError::InvalidSliceIndex {
            index,
            content_len: data_len,
        });
    }
    let root = decode_bao_hash(hash)?;
    let tree = BaoTree::new(data_len, BAO_BLOCK_SIZE);
    let ob = PostOrderMemOutboard {
        root,
        tree,
        data: outboard_bytes,
    };
    let key = carbonado_bao_key(format);
    let ranges = slice_to_chunk_ranges(index, count);
    let expected_chunks = u64::from(count) * CHUNKS_PER_SLICE;

    let mut validated = ChunkRanges::empty();
    for item in keyed_valid_ranges(&ob, &data, &ranges, &key) {
        let range = item.map_err(map_valid_ranges_read_error)?;
        validated |= ChunkRanges::from(range);
    }
    if chunk_count(&validated) < expected_chunks {
        return Err(CarbonadoError::AuthenticationFailed);
    }

    let (slice_byte_start, _slice_byte_end, actual_len) = slice_byte_range(index, count, data_len)?;

    let mut out = vec![0u8; actual_len as usize];
    data.read_exact_at(slice_byte_start, &mut out)
        .map_err(map_valid_ranges_read_error)?;
    Ok(out)
}
