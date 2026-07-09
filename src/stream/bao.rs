//! Keyed Bao streaming wrappers (`keyed_encode_ranges_validated`, `keyed_outboard`).

use std::cell::RefCell;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use bao::Hash;
use bao_tree::{
    io::{
        outboard::{EmptyOutboard, PostOrderMemOutboard, PostOrderOutboard},
        sync::{
            keyed_decode_ranges, keyed_encode_ranges_validated, keyed_outboard_post_order, ReadAt,
        },
    },
    BaoTree, ChunkRanges,
};

use crate::{
    constants::BAO_BLOCK_SIZE, crypto::carbonado_verification_key, error::CarbonadoError,
    stream::fec::write_past_content_len_error, stream::slice::map_decode_error,
};

struct CountWriter<W> {
    inner: W,
    count: u64,
}

impl<W: Write> Write for CountWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// [`WriteAt`] sink that discards decoded bytes — O(1) retained memory for verify-only paths.
///
/// Tracks `filled` (max end offset written) and requires `finish()` to confirm the full
/// `[0, content_len)` range was populated — same completeness contract as
/// [`crate::stream::fec::LogicalBufferWriteAt::into_inner`].
pub(crate) struct DiscardWriteAt {
    content_len: u64,
    filled: u64,
}

impl DiscardWriteAt {
    pub fn new(content_len: u64) -> Self {
        Self {
            content_len,
            filled: 0,
        }
    }

    pub fn finish(self) -> Result<(), CarbonadoError> {
        if self.filled != self.content_len {
            return Err(CarbonadoError::StdIoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "bao decode incomplete: got {} of {} bytes",
                    self.filled, self.content_len
                ),
            )));
        }
        Ok(())
    }
}

impl positioned_io::WriteAt for DiscardWriteAt {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if offset >= self.content_len || offset.saturating_add(data.len() as u64) > self.content_len
        {
            return Err(write_past_content_len_error());
        }
        self.filled = self.filled.max(offset + data.len() as u64);
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

/// Keyed inboard Bao verify without retaining decoded logical bytes (S5 scrub oracle).
pub(crate) fn verify_inboard_keyed(
    input: &[u8],
    hash: &[u8],
    format: u8,
) -> Result<(), CarbonadoError> {
    let content_len = inboard_bao_content_len_prefix(input)?;
    let mut sink = DiscardWriteAt::new(content_len);
    stream_verification_inboard_decode_with_len(
        Cursor::new(&input[8..]),
        content_len,
        hash,
        format,
        &mut sink,
    )?;
    sink.finish()
}

/// Bridge [`ReadAt`] → [`Read`] for `keyed_outboard_post_order`.
struct ReadAtReader<'a, D: ReadAt> {
    data: &'a D,
    pos: u64,
    len: u64,
}

impl<'a, D: ReadAt> Read for ReadAtReader<'a, D> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let max = buf.len().min((self.len - self.pos) as usize);
        let n = self.data.read_at(self.pos, &mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}

fn map_bao_io_error(err: std::io::Error) -> CarbonadoError {
    CarbonadoError::OutboardVerificationFailed(format!("bao encode: {err}"))
}

fn map_encode_error(err: bao_tree::io::EncodeError) -> CarbonadoError {
    CarbonadoError::OutboardVerificationFailed(format!("bao encode: {err}"))
}

/// [`positioned_io::ReadAt`] over a seekable [`Read`] without materializing the full body.
pub struct SeekReadAt<R> {
    inner: RefCell<R>,
    len: u64,
}

impl<R: Read + Seek> SeekReadAt<R> {
    pub fn new(inner: R, len: u64) -> Self {
        Self {
            inner: RefCell::new(inner),
            len,
        }
    }
}

impl<R: Read + Seek> positioned_io::ReadAt for SeekReadAt<R> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let mut inner = self.inner.borrow_mut();
        inner.seek(SeekFrom::Start(offset))?;
        let cap = buf.len().min((self.len - offset) as usize);
        inner.read(&mut buf[..cap])
    }
}

/// Inboard encode over [`ReadAt`]: writes `[u64le content_len | keyed response]`.
/// Returns `(root hash, total bytes written to output)`.
pub fn stream_verification_inboard<D: ReadAt, W: Write>(
    data: D,
    content_len: u64,
    format: u8,
    output: &mut W,
) -> Result<(Hash, u64), CarbonadoError> {
    let key = carbonado_verification_key(format);
    let tree = BaoTree::new(content_len, BAO_BLOCK_SIZE);
    let mut sidecar = Vec::new();
    let root = keyed_outboard_post_order(
        ReadAtReader {
            data: &data,
            pos: 0,
            len: content_len,
        },
        tree,
        &mut sidecar,
        &key,
    )
    .map_err(map_bao_io_error)?;
    let ob = PostOrderMemOutboard {
        root,
        tree,
        data: sidecar,
    };
    let mut counter = CountWriter {
        inner: output,
        count: 0,
    };
    counter
        .write_all(&content_len.to_le_bytes())
        .map_err(CarbonadoError::StdIoError)?;
    keyed_encode_ranges_validated(data, &ob, &ChunkRanges::all(), &mut counter, &key)
        .map_err(map_encode_error)?;
    Ok((root, counter.count))
}

/// Buffer convenience for inboard bao.
pub fn verification_inboard_buffer(
    input: &[u8],
    format: u8,
) -> Result<(Vec<u8>, Hash), CarbonadoError> {
    let mut out = Vec::new();
    let (hash, _) = stream_verification_inboard(input, input.len() as u64, format, &mut out)?;
    Ok((out, hash))
}

/// Outboard sidecar (post-order hash pairs) from [`Read`] + known length.
pub fn stream_verification_outboard<R: Read + Seek, W: Write>(
    mut data: R,
    content_len: u64,
    format: u8,
    output: &mut W,
) -> Result<Hash, CarbonadoError> {
    let key = carbonado_verification_key(format);
    let tree = BaoTree::new(content_len, BAO_BLOCK_SIZE);
    data.rewind().map_err(CarbonadoError::StdIoError)?;
    let root = keyed_outboard_post_order(data, tree, output, &key).map_err(map_bao_io_error)?;
    Ok(root)
}

/// Buffer convenience for outboard sidecar.
pub fn verification_outboard_buffer(
    input: &[u8],
    format: u8,
) -> Result<(Vec<u8>, Hash), CarbonadoError> {
    let key = carbonado_verification_key(format);
    let outboard = PostOrderMemOutboard::create_keyed(input, BAO_BLOCK_SIZE, &key);
    Ok((outboard.data, outboard.root))
}

/// Parse the inboard Bao `u64le` content-length prefix from the first 8 bytes.
///
/// Short input (< 8 bytes) maps to [`CarbonadoError::InvalidHeaderLength`].
pub(crate) fn inboard_bao_content_len_prefix(input: &[u8]) -> Result<u64, CarbonadoError> {
    if input.len() < 8 {
        return Err(CarbonadoError::InvalidHeaderLength);
    }
    let clen_bytes: [u8; 8] = input[0..8]
        .try_into()
        .map_err(|_| CarbonadoError::InvalidHeaderLength)?;
    Ok(u64::from_le_bytes(clen_bytes))
}

/// Read the inboard Bao `u64le` content-length prefix from a [`Read`] source.
///
/// Short input (< 8 bytes) maps to [`CarbonadoError::InvalidHeaderLength`].
pub(crate) fn read_inboard_bao_content_len_prefix<R: Read>(
    input: &mut R,
) -> Result<u64, CarbonadoError> {
    let mut clen_bytes = [0u8; 8];
    let mut got = 0usize;
    while got < 8 {
        match input.read(&mut clen_bytes[got..]) {
            Ok(0) => return Err(CarbonadoError::InvalidHeaderLength),
            Ok(n) => got += n,
            Err(e) => return Err(CarbonadoError::StdIoError(e)),
        }
    }
    inboard_bao_content_len_prefix(&clen_bytes)
}

/// Inboard decode when `content_len` is already known: `input` starts at keyed response bytes.
pub fn stream_verification_inboard_decode_with_len<R: Read, W: positioned_io::WriteAt>(
    input: R,
    content_len: u64,
    hash: &[u8],
    format: u8,
    output: W,
) -> Result<u64, CarbonadoError> {
    let root = crate::utils::decode_bao_hash(hash)?;
    let tree = BaoTree::new(content_len, BAO_BLOCK_SIZE);
    let key = carbonado_verification_key(format);
    let mut ob = EmptyOutboard { tree, root };
    keyed_decode_ranges(input, &ChunkRanges::all(), output, &mut ob, &key)
        .map_err(map_decode_error)?;
    Ok(content_len)
}

/// Inboard decode: `[u64le | response]` reader -> logical output via [`WriteAt`].
pub fn stream_verification_inboard_decode<R: Read, W: positioned_io::WriteAt>(
    mut input: R,
    hash: &[u8],
    format: u8,
    output: W,
) -> Result<u64, CarbonadoError> {
    let content_len = read_inboard_bao_content_len_prefix(&mut input)?;
    stream_verification_inboard_decode_with_len(input, content_len, hash, format, output)
}

/// Verify bare outboard main against sidecar (no output).
///
/// **Memory:** encoded output is discarded via `io::sink()`. Outboard hashes are loaded on
/// demand via [`ReadAt`] (`PostOrderOutboard`) — O(hash pair) RAM per node, not a full
/// sidecar `Vec` copy. Callers may pass a slice (`&[u8]: ReadAt`) or a disk-backed
/// [`SeekReadAt`] over a spool.
pub fn stream_verification_outboard_verify<D: ReadAt, O: ReadAt>(
    bare: D,
    bare_len: u64,
    outboard: O,
    hash: &[u8],
    format: u8,
) -> Result<(), CarbonadoError> {
    let root = crate::utils::decode_bao_hash(hash)?;
    let key = carbonado_verification_key(format);
    let tree = BaoTree::new(bare_len, BAO_BLOCK_SIZE);
    let ob = PostOrderOutboard {
        root,
        tree,
        data: outboard,
    };
    keyed_encode_ranges_validated(bare, &ob, &ChunkRanges::all(), &mut std::io::sink(), &key)
        .map_err(|e| CarbonadoError::OutboardVerificationFailed(format!("keyed bao: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoding::verification;
    use crate::stream::stream_encode_buffer;
    use positioned_io::WriteAt;

    fn assert_oracle_parity(input: &[u8], hash: &[u8], format: u8) {
        let keyed = verify_inboard_keyed(input, hash, format);
        let buffer = verification(input, hash, format);
        assert_eq!(
            keyed.is_ok(),
            buffer.is_ok(),
            "verify_inboard_keyed vs verification() parity mismatch for c{format}"
        );
        if let (Ok(()), Ok(decoded)) = (&keyed, &buffer) {
            assert_eq!(
                decoded.len(),
                inboard_bao_content_len_prefix(input).expect("prefix") as usize,
                "verification() body length must match content_len prefix"
            );
        }
    }

    #[test]
    fn discard_write_at_rejects_write_past_content_len() {
        let mut sink = DiscardWriteAt::new(64);
        let err = sink.write_at(32, &[0u8; 64]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn discard_write_at_finish_rejects_incomplete_decode() {
        let mut sink = DiscardWriteAt::new(128);
        sink.write_at(0, &[0u8; 64]).expect("partial write");
        let err = sink.finish().expect_err("incomplete decode");
        assert!(
            matches!(
                err,
                CarbonadoError::StdIoError(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof
            ),
            "expected UnexpectedEof for incomplete decode, got {err:?}"
        );
    }

    #[test]
    fn verify_inboard_keyed_oracle_parity_across_representative_payloads() {
        let master = [0u8; 32];
        for &format in &[6u8, 12, 14, 15] {
            for logical_len in [0usize, 1, 4095, 4096, 65_536] {
                let input: Vec<u8> = (0..logical_len).map(|i| (i % 251) as u8).collect();
                let (encoded, hash, _) =
                    stream_encode_buffer(&master, &input, format).expect("encode");
                assert_oracle_parity(&encoded, hash.as_bytes(), format);
            }
        }
    }

    #[test]
    fn verify_inboard_keyed_oracle_parity_malformed_prefix() {
        let master = [0u8; 32];
        let input: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let (mut encoded, hash, _) = stream_encode_buffer(&master, &input, 12).expect("encode");
        let declared = inboard_bao_content_len_prefix(&encoded).expect("prefix");
        let inflated = declared.saturating_add(4096);
        encoded[0..8].copy_from_slice(&inflated.to_le_bytes());

        let keyed_err = verify_inboard_keyed(&encoded, hash.as_bytes(), 12).unwrap_err();
        let buffer_err = verification(&encoded, hash.as_bytes(), 12).unwrap_err();
        assert!(
            matches!(keyed_err, CarbonadoError::AuthenticationFailed),
            "inflated content_len keyed oracle must fail AuthenticationFailed, got {keyed_err:?}"
        );
        assert!(
            matches!(buffer_err, CarbonadoError::AuthenticationFailed),
            "inflated content_len buffer oracle must fail AuthenticationFailed, got {buffer_err:?}"
        );
    }
}
