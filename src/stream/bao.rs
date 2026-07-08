//! Keyed Bao streaming wrappers (`keyed_encode_ranges_validated`, `keyed_outboard`).

use std::io::{Read, Seek, Write};

use bao::Hash;
use bao_tree::{
    io::{
        outboard::{EmptyOutboard, PostOrderMemOutboard},
        sync::{
            keyed_decode_ranges, keyed_encode_ranges_validated, keyed_outboard_post_order, ReadAt,
        },
    },
    BaoTree, ChunkRanges,
};

use crate::{
    constants::BAO_BLOCK_SIZE, crypto::carbonado_bao_key, error::CarbonadoError,
    stream::slice::map_decode_error,
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

/// Inboard encode over [`ReadAt`]: writes `[u64le content_len | keyed response]`.
/// Returns `(root hash, total bytes written to output)`.
pub fn stream_bao_inboard<D: ReadAt, W: Write>(
    data: D,
    content_len: u64,
    format: u8,
    output: &mut W,
) -> Result<(Hash, u64), CarbonadoError> {
    let key = carbonado_bao_key(format);
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
pub fn bao_inboard_buffer(input: &[u8], format: u8) -> Result<(Vec<u8>, Hash), CarbonadoError> {
    let mut out = Vec::new();
    let (hash, _) = stream_bao_inboard(input, input.len() as u64, format, &mut out)?;
    Ok((out, hash))
}

/// Outboard sidecar (post-order hash pairs) from [`Read`] + known length.
pub fn stream_bao_outboard<R: Read + Seek, W: Write>(
    mut data: R,
    content_len: u64,
    format: u8,
    output: &mut W,
) -> Result<Hash, CarbonadoError> {
    let key = carbonado_bao_key(format);
    let tree = BaoTree::new(content_len, BAO_BLOCK_SIZE);
    data.rewind().map_err(CarbonadoError::StdIoError)?;
    let root = keyed_outboard_post_order(data, tree, output, &key).map_err(map_bao_io_error)?;
    Ok(root)
}

/// Buffer convenience for outboard sidecar.
pub fn bao_outboard_buffer(input: &[u8], format: u8) -> Result<(Vec<u8>, Hash), CarbonadoError> {
    let key = carbonado_bao_key(format);
    let outboard = PostOrderMemOutboard::create_keyed(input, BAO_BLOCK_SIZE, &key);
    Ok((outboard.data, outboard.root))
}

/// Inboard decode: `[u64le | response]` reader -> logical output via [`WriteAt`].
pub fn stream_bao_inboard_decode<R: Read, W: positioned_io::WriteAt>(
    mut input: R,
    hash: &[u8],
    format: u8,
    output: W,
) -> Result<u64, CarbonadoError> {
    let mut clen_bytes = [0u8; 8];
    input
        .read_exact(&mut clen_bytes)
        .map_err(CarbonadoError::StdIoError)?;
    let content_len = u64::from_le_bytes(clen_bytes);
    let root = crate::utils::decode_bao_hash(hash)?;
    let tree = BaoTree::new(content_len, BAO_BLOCK_SIZE);
    let key = carbonado_bao_key(format);
    let mut ob = EmptyOutboard { tree, root };
    keyed_decode_ranges(input, &ChunkRanges::all(), output, &mut ob, &key)
        .map_err(map_decode_error)?;
    Ok(content_len)
}

/// Verify bare outboard main against sidecar (no output).
pub fn stream_bao_outboard_verify<D: ReadAt>(
    bare: D,
    bare_len: u64,
    outboard: &[u8],
    hash: &[u8],
    format: u8,
) -> Result<(), CarbonadoError> {
    let root = crate::utils::decode_bao_hash(hash)?;
    let key = carbonado_bao_key(format);
    let tree = BaoTree::new(bare_len, BAO_BLOCK_SIZE);
    let ob = PostOrderMemOutboard {
        root,
        tree,
        data: outboard.to_vec(),
    };
    let mut dummy = Vec::new();
    keyed_encode_ranges_validated(bare, &ob, &ChunkRanges::all(), &mut dummy, &key)
        .map_err(|e| CarbonadoError::OutboardVerificationFailed(format!("keyed bao: {e}")))?;
    Ok(())
}
