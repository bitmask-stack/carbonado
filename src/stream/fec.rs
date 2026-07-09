//! Reed-Solomon 4/8 FEC streaming with a 16 KiB (4×4 KiB slice) stripe accumulator.

use std::io::{Read, Write};

use reed_solomon_erasure::galois_8::Field;
use reed_solomon_erasure::ReedSolomon;

use crate::{
    constants::{FEC_K, FEC_M, SLICE_LEN},
    error::CarbonadoError,
    utils::calc_padding_len,
};

/// Result of one completed FEC stripe (8 shards × `chunk_len`).
#[derive(Clone, Debug)]
pub struct FecStripe {
    pub shards: Vec<Vec<u8>>,
    pub chunk_len: u32,
}

/// Inboard FEC encoder: consumes logical bytes, emits one concatenated stripe.
pub struct FecInboardEncoder {
    padded_len: usize,
    chunk_len: usize,
    padding_total: u32,
    pos: usize,
    shards: Vec<Vec<u8>>,
    rs: ReedSolomon<Field>,
    finished: bool,
}

impl FecInboardEncoder {
    /// `logical_len` is the pre-FEC payload length (before padding).
    pub fn new(logical_len: usize) -> Result<Self, CarbonadoError> {
        if logical_len == 0 {
            return Ok(Self {
                padded_len: 0,
                chunk_len: 0,
                padding_total: 0,
                pos: 0,
                shards: vec![],
                rs: ReedSolomon::new(FEC_K, FEC_M - FEC_K)?,
                finished: true,
            });
        }
        let (padding_total, chunk_len) = calc_padding_len(logical_len);
        let padded_len = logical_len + padding_total as usize;
        let rs = ReedSolomon::<Field>::new(FEC_K, FEC_M - FEC_K)?;
        let mut shards = Vec::with_capacity(FEC_M);
        for _ in 0..FEC_M {
            shards.push(vec![0u8; chunk_len as usize]);
        }
        Ok(Self {
            padded_len,
            chunk_len: chunk_len as usize,
            padding_total,
            pos: 0,
            shards,
            rs,
            finished: false,
        })
    }

    pub fn padding_len(&self) -> u32 {
        self.padding_total
    }

    pub fn chunk_len(&self) -> u32 {
        self.chunk_len as u32
    }

    /// Feed logical bytes from `input`. Caller must supply exactly `logical_len` bytes total
    /// (via [`Read::take`] or equivalent) before [`Self::finish`]. Excess bytes error;
    /// padding is zero-filled only in `finish`.
    pub fn feed<R: Read>(&mut self, mut input: R) -> Result<Option<FecStripe>, CarbonadoError> {
        if self.finished {
            return Ok(None);
        }
        let mut buf = [0u8; SLICE_LEN as usize];
        loop {
            let n = input.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
            if n == 0 {
                break;
            }
            self.feed_logical_bytes(&buf[..n])?;
        }
        Ok(None)
    }

    /// Finalize when the caller has fed exactly `logical_len` bytes (padding added internally).
    pub fn finish(&mut self) -> Result<Option<FecStripe>, CarbonadoError> {
        if self.finished || self.padded_len == 0 {
            return Ok(None);
        }
        let logical_len = self.logical_len();
        if self.pos < logical_len {
            return Err(CarbonadoError::StdIoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "FEC encoder: short read before finish",
            )));
        }
        if self.pos < self.padded_len {
            let zeros = vec![0u8; self.padded_len - self.pos];
            self.feed_padding_bytes(&zeros)?;
        }
        self.finished = true;
        Ok(Some(self.take_stripe()?))
    }

    fn logical_len(&self) -> usize {
        self.padded_len - self.padding_total as usize
    }

    fn feed_logical_bytes(&mut self, data: &[u8]) -> Result<(), CarbonadoError> {
        let logical_len = self.logical_len();
        let mut off = 0usize;
        while off < data.len() {
            if self.pos >= logical_len {
                return Err(CarbonadoError::StdIoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "FEC encoder: input exceeds logical length",
                )));
            }
            let shard_idx = self.pos / self.chunk_len;
            let shard_off = self.pos % self.chunk_len;
            if shard_idx >= FEC_K {
                break;
            }
            let room = self.chunk_len - shard_off;
            let cap = logical_len - self.pos;
            let take = (data.len() - off).min(room).min(cap);
            self.shards[shard_idx][shard_off..shard_off + take]
                .copy_from_slice(&data[off..off + take]);
            self.pos += take;
            off += take;
        }
        Ok(())
    }

    fn feed_padding_bytes(&mut self, data: &[u8]) -> Result<(), CarbonadoError> {
        let mut off = 0usize;
        while off < data.len() && self.pos < self.padded_len {
            let shard_idx = self.pos / self.chunk_len;
            let shard_off = self.pos % self.chunk_len;
            if shard_idx >= FEC_K {
                break;
            }
            let room = self.chunk_len - shard_off;
            let take = (data.len() - off).min(room).min(self.padded_len - self.pos);
            self.shards[shard_idx][shard_off..shard_off + take]
                .copy_from_slice(&data[off..off + take]);
            self.pos += take;
            off += take;
        }
        Ok(())
    }

    fn take_stripe(&mut self) -> Result<FecStripe, CarbonadoError> {
        #[cfg(feature = "parallel")]
        {
            crate::stream::parallel::encode_rs_parity(&self.rs, &mut self.shards, self.chunk_len)?;
        }
        #[cfg(not(feature = "parallel"))]
        {
            self.rs.encode(&mut self.shards)?;
        }
        for s in &self.shards {
            if s.len() != self.chunk_len {
                return Err(CarbonadoError::EncodeInvalidChunkLength(
                    self.chunk_len as u32,
                    s.len(),
                ));
            }
        }
        Ok(FecStripe {
            shards: std::mem::take(&mut self.shards),
            chunk_len: self.chunk_len as u32,
        })
    }
}

/// [`positioned_io::ReadAt`] view over concatenated inboard FEC stripe shards.
///
/// Avoids flattening shard data into a staging `Vec` before keyed Bao inboard encode (S3).
pub struct FecStripeReadAt<'a> {
    stripe: &'a FecStripe,
    len: u64,
}

impl<'a> FecStripeReadAt<'a> {
    pub fn new(stripe: &'a FecStripe) -> Self {
        let len = stripe
            .shards
            .iter()
            .fold(0u64, |acc, s| acc + s.len() as u64);
        Self { stripe, len }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl positioned_io::ReadAt for FecStripeReadAt<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        let mut pos = offset;
        let mut cum = 0u64;
        for shard in &self.stripe.shards {
            let shard_len = shard.len() as u64;
            let shard_end = cum + shard_len;
            if pos >= shard_end {
                cum = shard_end;
                continue;
            }
            let start = (pos - cum) as usize;
            let avail = shard.len() - start;
            let to_copy = avail.min(buf.len() - written);
            buf[written..written + to_copy].copy_from_slice(&shard[start..start + to_copy]);
            written += to_copy;
            pos += to_copy as u64;
            cum = shard_end;
            if written >= buf.len() {
                break;
            }
        }
        Ok(written)
    }
}

/// Write all shards of a stripe to `output` (inboard layout).
pub fn write_inboard_stripe<W: Write>(
    stripe: &FecStripe,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let mut n = 0u64;
    for s in &stripe.shards {
        output.write_all(s).map_err(CarbonadoError::StdIoError)?;
        n += s.len() as u64;
    }
    Ok(n)
}

/// Write parity shards only (outboard `.par` sidecar).
pub fn write_outboard_parity<W: Write>(
    stripe: &FecStripe,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let mut n = 0u64;
    for s in stripe.shards.iter().skip(FEC_K) {
        output.write_all(s).map_err(CarbonadoError::StdIoError)?;
        n += s.len() as u64;
    }
    Ok(n)
}

/// [`WriteAt`] sink for keyed Bao inboard decode into one RS stripe (S4).
///
/// Retains at most `FEC_M` shard buffers (`O(stripe)`); RS-reconstructs on [`Self::finish`].
///
/// `filled` tracks the maximum end offset written. Completion assumes `keyed_decode_ranges` with
/// `ChunkRanges::all()` populates `[0, content_len)` contiguously on success (bao-tree contract).
pub struct FecInboardWriteAt {
    content_len: u64,
    padding: u32,
    shard_len: usize,
    shards: Vec<Vec<u8>>,
    filled: u64,
    finished: bool,
}

impl FecInboardWriteAt {
    pub fn new(content_len: u64, padding: u32) -> Result<Self, CarbonadoError> {
        if content_len == 0 {
            return Ok(Self {
                content_len: 0,
                padding,
                shard_len: 0,
                shards: vec![],
                filled: 0,
                finished: false,
            });
        }
        let len = content_len as usize;
        if !len.is_multiple_of(FEC_M) {
            return Err(CarbonadoError::UnevenFecChunks);
        }
        let shard_len = len / FEC_M;
        let mut shards = Vec::with_capacity(FEC_M);
        for _ in 0..FEC_M {
            shards.push(vec![0u8; shard_len]);
        }
        Ok(Self {
            content_len,
            padding,
            shard_len,
            shards,
            filled: 0,
            finished: false,
        })
    }

    /// RS-decode and stream logical bytes (padding stripped) into `output` without a full
    /// intermediate logical `Vec`. Peak RAM remains O(FEC body) for the shard buffers
    /// (one segment-wide stripe under current geometry).
    pub fn finish_into<W: Write>(mut self, output: &mut W) -> Result<u64, CarbonadoError> {
        if self.finished {
            return Err(CarbonadoError::InternalStateError(
                "FecInboardWriteAt::finish called twice".to_string(),
            ));
        }
        self.finished = true;
        if self.content_len == 0 {
            return Ok(0);
        }
        if self.filled != self.content_len {
            return Err(CarbonadoError::StdIoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "FEC stripe incomplete: got {} of {} bytes",
                    self.filled, self.content_len
                ),
            )));
        }
        let mut shard_opts: Vec<Option<Vec<u8>>> = self.shards.drain(..).map(Some).collect();
        let rs = ReedSolomon::<Field>::new(FEC_K, FEC_M - FEC_K)?;
        rs.reconstruct(&mut shard_opts)?;
        let data_len = self.shard_len.saturating_mul(FEC_K);
        if self.padding as usize > data_len {
            return Err(CarbonadoError::ScrubbedLengthMismatch(
                data_len,
                self.padding as usize,
            ));
        }
        let logical_len = data_len - self.padding as usize;
        let mut remaining = logical_len;
        let mut written = 0u64;
        for s in shard_opts.iter().take(FEC_K).flatten() {
            if remaining == 0 {
                break;
            }
            let n = remaining.min(s.len());
            output
                .write_all(&s[..n])
                .map_err(CarbonadoError::StdIoError)?;
            remaining -= n;
            written += n as u64;
        }
        Ok(written)
    }

    /// RS-decode the accumulated stripe and return logical bytes (padding stripped).
    pub fn finish(self) -> Result<Vec<u8>, CarbonadoError> {
        let mut decoded = Vec::new();
        self.finish_into(&mut decoded)?;
        Ok(decoded)
    }
}

pub(crate) fn write_past_content_len_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "WriteAt offset exceeds declared content length",
    )
}

impl positioned_io::WriteAt for FecInboardWriteAt {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if offset >= self.content_len || offset.saturating_add(data.len() as u64) > self.content_len
        {
            return Err(write_past_content_len_error());
        }
        let mut written = 0usize;
        let mut pos = offset;
        while written < data.len() {
            let shard_idx = (pos as usize) / self.shard_len;
            let shard_off = (pos as usize) % self.shard_len;
            let room = self.shard_len - shard_off;
            let cap = (self.content_len - pos) as usize;
            let take = (data.len() - written).min(room).min(cap);
            self.shards[shard_idx][shard_off..shard_off + take]
                .copy_from_slice(&data[written..written + take]);
            self.filled = self.filled.max(pos + take as u64);
            written += take;
            pos += take as u64;
        }
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

/// In-memory [`WriteAt`] retaining exactly `content_len` logical bytes.
///
/// Production inboard non-FEC verification uses [`crate::stream::spool::SeekWriteAt`] (disk
/// spool, O(chunk) RAM). This type remains for unit tests of WriteAt completeness contracts.
///
/// `filled` tracks the maximum end offset written; relies on full-range Bao decode completion
/// (see [`FecInboardWriteAt`]).
pub struct LogicalBufferWriteAt {
    content_len: u64,
    buf: Vec<u8>,
    filled: u64,
}

impl LogicalBufferWriteAt {
    pub fn new(content_len: u64) -> Self {
        Self {
            content_len,
            buf: vec![0u8; content_len as usize],
            filled: 0,
        }
    }

    pub fn into_inner(self) -> Result<Vec<u8>, CarbonadoError> {
        if self.filled != self.content_len {
            return Err(CarbonadoError::StdIoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "bao decode incomplete: got {} of {} bytes",
                    self.filled, self.content_len
                ),
            )));
        }
        Ok(self.buf)
    }
}

impl positioned_io::WriteAt for LogicalBufferWriteAt {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if offset >= self.content_len || offset.saturating_add(data.len() as u64) > self.content_len
        {
            return Err(write_past_content_len_error());
        }
        let rel = offset as usize;
        self.buf[rel..rel + data.len()].copy_from_slice(data);
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

/// Inboard FEC decode from a reader of concatenated shards.
pub fn stream_decode_inboard<R: Read, W: Write>(
    mut input: R,
    padding: u32,
    logical_shard_len: usize,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    if logical_shard_len == 0 {
        return Ok(0);
    }
    let shard_len = logical_shard_len;
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; FEC_M];
    for shard in shards.iter_mut() {
        let mut buf = vec![0u8; shard_len];
        input
            .read_exact(&mut buf)
            .map_err(CarbonadoError::StdIoError)?;
        *shard = Some(buf);
    }
    let rs = ReedSolomon::<Field>::new(FEC_K, FEC_M - FEC_K)?;
    rs.reconstruct(&mut shards)?;
    let mut decoded = Vec::new();
    for s in shards.iter().take(FEC_K).flatten() {
        decoded.extend_from_slice(s);
    }
    if padding as usize > decoded.len() {
        return Err(CarbonadoError::ScrubbedLengthMismatch(
            decoded.len(),
            padding as usize,
        ));
    }
    decoded.truncate(decoded.len() - padding as usize);
    output
        .write_all(&decoded)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(decoded.len() as u64)
}

/// Outboard FEC decode: bare main reader + parity reader -> logical output.
///
/// **Degraded / truncated main:** prefer [`crate::decoding::fec_with_parity`] via
/// [`crate::stream::stream_decode_outboard_buffer`], which derives stripe geometry from
/// the parity sidecar (encode-time `chunk_len`) rather than `calc_padding_len(main_len)`.
pub fn stream_decode_outboard<R: Read, W: Write>(
    mut main: R,
    mut parity: R,
    padding: u32,
    main_len: usize,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    if main_len == 0 && padding == 0 {
        return Ok(0);
    }

    // Read parity incrementally into a buffer (streamed via `copy`, not single `read_to_end`).
    let mut parity_buf = Vec::new();
    std::io::copy(&mut parity, &mut parity_buf).map_err(CarbonadoError::StdIoError)?;
    let parity_shards = FEC_M - FEC_K;
    if !parity_buf.len().is_multiple_of(parity_shards) {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let shard_len = parity_buf.len() / parity_shards;
    let padded_total = shard_len * FEC_K;
    let pad = padding as usize;
    if pad > padded_total {
        return Err(CarbonadoError::ScrubbedLengthMismatch(padded_total, pad));
    }
    let logical_len = padded_total - pad;

    let mut main_buf = Vec::new();
    if main_len > 0 {
        let mut buf = [0u8; SLICE_LEN as usize];
        let mut read_main = 0usize;
        while read_main < main_len {
            let n = main.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
            if n == 0 {
                break;
            }
            let take = n.min(main_len - read_main);
            main_buf.extend_from_slice(&buf[..take]);
            read_main += take;
        }
    }
    let copy = main_buf.len().min(logical_len);

    let mut padded = vec![0u8; padded_total];
    padded[..copy].copy_from_slice(&main_buf[..copy]);

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; FEC_M];
    for (i, shard) in shards.iter_mut().enumerate().take(FEC_K) {
        let start = i * shard_len;
        let end = start + shard_len;
        if end <= copy {
            *shard = Some(padded[start..end].to_vec());
        }
    }
    for j in 0..parity_shards {
        let start = j * shard_len;
        shards[FEC_K + j] = Some(parity_buf[start..start + shard_len].to_vec());
    }

    let rs = ReedSolomon::<Field>::new(FEC_K, FEC_M - FEC_K)?;
    rs.reconstruct(&mut shards)?;
    let mut decoded = Vec::new();
    for s in shards.iter().take(FEC_K).flatten() {
        decoded.extend_from_slice(s);
    }
    if decoded.len() < logical_len {
        return Err(CarbonadoError::ScrubbedLengthMismatch(
            decoded.len(),
            logical_len,
        ));
    }
    decoded.truncate(logical_len);
    output
        .write_all(&decoded)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(decoded.len() as u64)
}

fn fec_short_read_error() -> CarbonadoError {
    CarbonadoError::StdIoError(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "FEC encode: short read",
    ))
}

/// Feed exactly `logical_len` bytes from `input` and emit one inboard FEC stripe.
///
/// Uses [`Read::take`] so callers cannot over-feed; returns an error on short read.
pub fn feed_inboard_fec_stripe<R: Read>(
    logical_len: usize,
    input: &mut R,
) -> Result<(FecStripe, u32, u32), CarbonadoError> {
    if logical_len == 0 {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let mut enc = FecInboardEncoder::new(logical_len)?;
    let mut limited = input.take(logical_len as u64);
    enc.feed(&mut limited)?;
    if limited.limit() > 0 {
        return Err(fec_short_read_error());
    }
    let stripe = enc.finish()?.ok_or(CarbonadoError::UnevenFecChunks)?;
    Ok((stripe, enc.padding_len(), enc.chunk_len()))
}

/// Buffer-path helper: encode entire logical blob in one stripe.
fn take_stripe(enc: &mut FecInboardEncoder, input: &[u8]) -> Result<FecStripe, CarbonadoError> {
    if let Some(stripe) = enc.feed(std::io::Cursor::new(input))? {
        return Ok(stripe);
    }
    enc.finish()?.ok_or(CarbonadoError::UnevenFecChunks)
}

pub fn encode_inboard_buffer(input: &[u8]) -> Result<(Vec<u8>, u32, u32), CarbonadoError> {
    if input.is_empty() {
        return Ok((vec![], 0, 0));
    }
    let mut enc = FecInboardEncoder::new(input.len())?;
    let stripe = take_stripe(&mut enc, input)?;
    let padding_len = enc.padding_len();
    let chunk_len = enc.chunk_len();
    let mut out = Vec::new();
    write_inboard_stripe(&stripe, &mut out)?;
    Ok((out, padding_len, chunk_len))
}

/// Buffer-path helper: parity shards only for outboard FEC.
pub fn encode_outboard_parity_buffer(input: &[u8]) -> Result<(u32, u32, Vec<u8>), CarbonadoError> {
    if input.is_empty() {
        return Ok((0, 0, vec![]));
    }
    let mut enc = FecInboardEncoder::new(input.len())?;
    let stripe = take_stripe(&mut enc, input)?;
    let padding_len = enc.padding_len();
    let chunk_len = enc.chunk_len();
    let mut parity = Vec::new();
    write_outboard_parity(&stripe, &mut parity)?;
    Ok((padding_len, chunk_len, parity))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::decoding::fec;

    #[test]
    fn fec_stripe_geometry_matches_calc_padding_len() {
        for logical_len in [1usize, 4095, 4096, 4097, 16 * 1024 - 1, 16 * 1024] {
            let input: Vec<u8> = (0..logical_len).map(|i| (i % 251) as u8).collect();
            let (encoded, pl, cl) = encode_inboard_buffer(&input).expect("encode");
            let (exp_pl, exp_cl) = calc_padding_len(logical_len);
            assert_eq!(pl, exp_pl, "padding len for {logical_len}");
            assert_eq!(cl, exp_cl, "chunk len for {logical_len}");
            if logical_len == 0 {
                assert!(encoded.is_empty());
                continue;
            }
            assert_eq!(encoded.len(), FEC_M * cl as usize);
            assert_eq!(cl % SLICE_LEN, 0, "chunk_len must align to SLICE_LEN");
        }
    }

    #[test]
    fn encode_inboard_buffer_roundtrips_via_zfec() {
        for logical_len in [0usize, 1, 4096, 16_384, 32_768] {
            let input: Vec<u8> = (0..logical_len).map(|i| (i % 251) as u8).collect();
            let (encoded, pl, _) = encode_inboard_buffer(&input).expect("encode");
            if logical_len == 0 {
                assert!(encoded.is_empty());
                continue;
            }
            let decoded = fec(&encoded, pl).expect("fec");
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn fec_stripe_read_at_matches_flattened_stripe() {
        use positioned_io::ReadAt;

        let input: Vec<u8> = (0..12_288).map(|i| (i % 251) as u8).collect();
        let mut enc = FecInboardEncoder::new(input.len()).expect("new");
        let stripe = take_stripe(&mut enc, &input).expect("stripe");
        let mut flat = Vec::new();
        write_inboard_stripe(&stripe, &mut flat).expect("flatten");

        let view = FecStripeReadAt::new(&stripe);
        assert_eq!(view.len(), flat.len() as u64);

        let mut via_read_at = vec![0u8; flat.len()];
        let n = view
            .read_at(0, &mut via_read_at)
            .expect("read_at full stripe");
        assert_eq!(n, flat.len());
        assert_eq!(via_read_at, flat);

        let mut tail = [0u8; 64];
        let n = view
            .read_at(flat.len() as u64 - 32, &mut tail)
            .expect("read_at tail");
        assert_eq!(n, 32);
        assert_eq!(&tail[..32], &flat[flat.len() - 32..]);
    }

    #[test]
    fn fec_feed_rejects_excess_logical_bytes() {
        let input: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let mut enc = FecInboardEncoder::new(input.len()).expect("new");
        let mut padded = input.clone();
        padded.push(0xFF);
        let err = enc.feed(Cursor::new(&padded)).expect_err("excess");
        assert!(
            matches!(
                err,
                CarbonadoError::StdIoError(ref e) if e.kind() == std::io::ErrorKind::InvalidData
            ),
            "expected InvalidData for excess input, got {err:?}"
        );
    }

    #[test]
    fn feed_inboard_fec_stripe_errors_on_short_read() {
        let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let short = &input[..4096];
        let err = feed_inboard_fec_stripe(input.len(), &mut Cursor::new(short)).expect_err("short");
        assert!(
            matches!(
                err,
                CarbonadoError::StdIoError(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof
            ),
            "expected UnexpectedEof for short read, got {err:?}"
        );
    }

    #[test]
    fn fec_incremental_feed_matches_single_buffer_feed() {
        let input: Vec<u8> = (0..12_288).map(|i| (i % 251) as u8).collect();
        let (buf_encoded, _, _) = encode_inboard_buffer(&input).expect("buffer");

        let mut enc = FecInboardEncoder::new(input.len()).expect("new");
        let mut off = 0usize;
        while off < input.len() {
            let step = 512.min(input.len() - off);
            let _ = enc
                .feed(Cursor::new(&input[off..off + step]))
                .expect("feed");
            off += step;
        }
        let stripe = enc.finish().expect("finish").expect("final stripe");
        let mut incremental = Vec::new();
        write_inboard_stripe(&stripe, &mut incremental).expect("write");
        assert_eq!(incremental, buf_encoded);
    }

    #[test]
    fn outboard_parity_reconstructs_with_bare_main() {
        use crate::decoding::fec_with_parity;

        let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let (pl, chunk_len, parity) = encode_outboard_parity_buffer(&input).expect("parity");
        // Outboard bare main is the pre-FEC logical body; parity sidecar holds RS parity shards.
        let decoded = fec_with_parity(&input, &parity, pl).expect("fec outboard");
        assert_eq!(decoded, input);
        assert_eq!(chunk_len % SLICE_LEN, 0);
    }

    #[test]
    fn fec_with_parity_recovers_erased_trailing_shards() {
        use crate::decoding::fec_with_parity;

        let input: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
        let (pl, chunk_len, parity) = encode_outboard_parity_buffer(&input).expect("parity");
        let chunk = chunk_len as usize;
        let truncated = &input[..input.len() - 2 * chunk];
        let decoded = fec_with_parity(truncated, &parity, pl).expect("erasure decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn fec_with_parity_recovers_fully_erased_main_from_parity() {
        use crate::decoding::fec_with_parity;

        let input: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
        let (pl, _, parity) = encode_outboard_parity_buffer(&input).expect("parity");
        let decoded = fec_with_parity(&[], &parity, pl).expect("parity-only reconstruct");
        assert_eq!(decoded, input);
    }

    #[test]
    fn fec_with_parity_rejects_malformed_parity_length() {
        use crate::decoding::fec_with_parity;
        use crate::error::CarbonadoError;

        let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let (_, _, parity) = encode_outboard_parity_buffer(&input).expect("parity");
        let bad = &parity[..parity.len() - 1];
        let err = fec_with_parity(&input, bad, 0).unwrap_err();
        assert!(matches!(err, CarbonadoError::UnevenFecChunks));
    }

    #[test]
    fn fec_with_parity_rejects_padding_beyond_stripe() {
        use crate::decoding::fec_with_parity;
        use crate::error::CarbonadoError;

        let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let (_, _, parity) = encode_outboard_parity_buffer(&input).expect("parity");
        let padded_total = (parity.len() / (FEC_M - FEC_K)) * FEC_K;
        let err = fec_with_parity(&input, &parity, (padded_total + 1) as u32).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::ScrubbedLengthMismatch(a, b) if a == padded_total && b == padded_total + 1
        ));
    }

    #[test]
    fn fec_with_parity_corrupt_parity_does_not_recover_original() {
        use crate::decoding::fec_with_parity;

        let input: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
        let (pl, chunk_len, parity) = encode_outboard_parity_buffer(&input).expect("parity");
        let chunk = chunk_len as usize;
        let mut bad_parity = parity.clone();
        for j in 0..3 {
            bad_parity[j * chunk..(j + 1) * chunk].fill(0xFF);
        }
        // RS reconstruct treats present-but-corrupt shards as valid; output must differ.
        let decoded = fec_with_parity(&[], &bad_parity, pl).expect("reconstruct returns Ok");
        assert_ne!(decoded, input);
    }

    #[test]
    fn fec_with_parity_empty_parity_with_nonempty_input_errors() {
        use crate::decoding::fec_with_parity;
        use crate::error::CarbonadoError;

        let input: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let (pl, _, _) = encode_outboard_parity_buffer(&input).expect("parity");
        let err = fec_with_parity(&input, &[], pl).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::UnevenFecChunks
                | CarbonadoError::FecError(_)
                | CarbonadoError::ScrubbedLengthMismatch(0, _)
        ));
    }

    #[test]
    fn fec_inboard_write_at_roundtrip_matches_decoding_fec() {
        use positioned_io::WriteAt;

        let input: Vec<u8> = (0..12_288).map(|i| (i % 251) as u8).collect();
        let (encoded, pl, _) = encode_inboard_buffer(&input).expect("encode");
        let content_len = encoded.len() as u64;
        let expected = fec(&encoded, pl).expect("buffer fec");

        let mut sink = FecInboardWriteAt::new(content_len, pl).expect("new");
        // Out-of-order shard-sized writes (mirrors Bao leaf ordering).
        let shard_len = encoded.len() / FEC_M;
        for (i, shard) in encoded.chunks(shard_len).enumerate() {
            let off = (i * shard_len) as u64;
            sink.write_at(off, shard).expect("write_at shard");
        }
        let got = sink.finish().expect("finish");
        assert_eq!(got, expected);
    }

    #[test]
    fn fec_inboard_write_at_finish_rejects_incomplete_stripe() {
        use positioned_io::WriteAt;

        let input: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let (encoded, pl, _) = encode_inboard_buffer(&input).expect("encode");
        let content_len = encoded.len() as u64;
        let shard_len = encoded.len() / FEC_M;

        let mut sink = FecInboardWriteAt::new(content_len, pl).expect("new");
        sink.write_at(0, &encoded[..shard_len])
            .expect("partial shard");
        let err = sink.finish().expect_err("incomplete stripe");
        assert!(
            matches!(
                err,
                CarbonadoError::StdIoError(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof
            ),
            "expected UnexpectedEof for incomplete stripe, got {err:?}"
        );
    }

    #[test]
    fn fec_inboard_write_at_rejects_write_past_content_len() {
        use positioned_io::WriteAt;

        let mut sink = FecInboardWriteAt::new(8 * 4096, 0).expect("new");
        let err = sink.write_at(8 * 4096, &[0xFF]).expect_err("past end");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn logical_buffer_write_at_out_of_order_matches_sequential() {
        use positioned_io::WriteAt;

        let data: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let len = data.len() as u64;
        let mid = (len / 2) as usize;

        let mut out_of_order = LogicalBufferWriteAt::new(len);
        out_of_order
            .write_at(len / 2, &data[mid..])
            .expect("second half");
        out_of_order.write_at(0, &data[..mid]).expect("first half");
        let ooo = out_of_order.into_inner().expect("ooo inner");

        let mut sequential = LogicalBufferWriteAt::new(len);
        sequential.write_at(0, &data).expect("sequential");
        let seq = sequential.into_inner().expect("seq inner");

        assert_eq!(ooo, seq);
        assert_eq!(ooo, data);
    }

    #[test]
    fn logical_buffer_write_at_finish_rejects_incomplete() {
        use positioned_io::WriteAt;

        let mut sink = LogicalBufferWriteAt::new(1024);
        sink.write_at(0, &[0u8; 512]).expect("half");
        let err = sink.into_inner().expect_err("incomplete");
        assert!(
            matches!(
                err,
                CarbonadoError::StdIoError(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof
            ),
            "expected UnexpectedEof for incomplete logical buffer, got {err:?}"
        );
    }

    #[test]
    fn logical_buffer_write_at_rejects_write_past_content_len() {
        use positioned_io::WriteAt;

        let mut sink = LogicalBufferWriteAt::new(64);
        let err = sink.write_at(32, &[0u8; 64]).expect_err("overflow");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
