//! Reed-Solomon 4/8 FEC as 16 KiB logical stripes of eight 4 KiB leaves.

use std::io::{Read, Write};

use reed_solomon_erasure::ReedSolomon;
use reed_solomon_erasure::galois_8::Field;

use crate::{
    constants::{FEC_K, FEC_M, FEC_STRIPE_INBOARD_LEN, FEC_STRIPE_LOGICAL_LEN, SLICE_LEN},
    error::CarbonadoError,
    utils::calc_padding_len,
};

/// Result of one completed FEC stripe (8 shards × 4 KiB).
#[derive(Clone, Debug)]
pub struct FecStripe {
    pub shards: Vec<Vec<u8>>,
    pub chunk_len: u32,
}

impl FecStripe {
    fn empty_shards() -> Vec<Vec<u8>> {
        (0..FEC_M).map(|_| vec![0u8; SLICE_LEN as usize]).collect()
    }
}

/// Split one stripe into data leaves (4 × 4 KiB) and parity leaves (4 × 4 KiB).
///
/// Outboard main is the concatenation of data leaves across stripes (padded
/// logical body). Parity leaves are the stream Adamantine stores in the bundle.
pub fn stripe_data_and_parity_leaves(stripe: &FecStripe) -> (&[Vec<u8>], &[Vec<u8>]) {
    stripe.shards.split_at(FEC_K)
}

/// Concatenate data leaves of every stripe (padded logical body, stripe order).
pub fn concat_data_leaves(stripes: &[FecStripe]) -> Vec<u8> {
    let mut out = Vec::with_capacity(stripes.len() * FEC_STRIPE_LOGICAL_LEN as usize);
    for stripe in stripes {
        let (data, _) = stripe_data_and_parity_leaves(stripe);
        for leaf in data {
            out.extend_from_slice(leaf);
        }
    }
    out
}

/// Concatenate parity leaves of every stripe (Adamantine / `.par` stream).
pub fn concat_parity_leaves(stripes: &[FecStripe]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        stripes.len() * (FEC_STRIPE_INBOARD_LEN - FEC_STRIPE_LOGICAL_LEN) as usize,
    );
    for stripe in stripes {
        let (_, parity) = stripe_data_and_parity_leaves(stripe);
        for leaf in parity {
            out.extend_from_slice(leaf);
        }
    }
    out
}

/// Inboard FEC encoder: consumes logical bytes, emits one 32 KiB stripe per 16 KiB.
pub struct FecInboardEncoder {
    logical_len: usize,
    padded_len: usize,
    padding_total: u32,
    pos: usize,
    current: Vec<u8>,
    rs: ReedSolomon<Field>,
    finished: bool,
}

impl FecInboardEncoder {
    /// `logical_len` is the pre-FEC payload length (before padding).
    pub fn new(logical_len: usize) -> Result<Self, CarbonadoError> {
        if logical_len == 0 {
            return Ok(Self {
                logical_len: 0,
                padded_len: 0,
                padding_total: 0,
                pos: 0,
                current: Vec::new(),
                rs: ReedSolomon::new(FEC_K, FEC_M - FEC_K)?,
                finished: true,
            });
        }
        let (padding_total, _chunk_len) = calc_padding_len(logical_len);
        let padded_len = logical_len + padding_total as usize;
        Ok(Self {
            logical_len,
            padded_len,
            padding_total,
            pos: 0,
            current: Vec::with_capacity(FEC_STRIPE_LOGICAL_LEN as usize),
            rs: ReedSolomon::<Field>::new(FEC_K, FEC_M - FEC_K)?,
            finished: false,
        })
    }

    pub fn padding_len(&self) -> u32 {
        self.padding_total
    }

    /// RS symbol size: one 4 KiB Bao leaf (not `padded_len / 4`).
    pub fn chunk_len(&self) -> u32 {
        if self.padded_len == 0 { 0 } else { SLICE_LEN }
    }

    /// Feed logical bytes from `input`. Completed 16 KiB stripes are returned.
    /// Caller must supply exactly `logical_len` bytes total before [`Self::finish`].
    pub fn feed<R: Read>(&mut self, mut input: R) -> Result<Vec<FecStripe>, CarbonadoError> {
        if self.finished {
            return Ok(vec![]);
        }
        let mut completed = Vec::new();
        let mut buf = [0u8; SLICE_LEN as usize];
        loop {
            let n = input.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
            if n == 0 {
                break;
            }
            self.feed_logical_bytes(&buf[..n], &mut completed)?;
        }
        Ok(completed)
    }

    /// Finalize when the caller has fed exactly `logical_len` bytes (padding added internally).
    pub fn finish(&mut self) -> Result<Vec<FecStripe>, CarbonadoError> {
        if self.finished {
            return Ok(vec![]);
        }
        if self.pos < self.logical_len {
            return Err(CarbonadoError::StdIoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "FEC encoder: short read before finish",
            )));
        }
        let mut completed = Vec::new();
        if self.pos < self.padded_len {
            let zeros = vec![0u8; self.padded_len - self.pos];
            self.feed_padding_bytes(&zeros, &mut completed)?;
        }
        if !self.current.is_empty() {
            return Err(CarbonadoError::InternalStateError(
                "FEC encoder: unfinished stripe after padding".to_string(),
            ));
        }
        self.finished = true;
        Ok(completed)
    }

    fn feed_logical_bytes(
        &mut self,
        data: &[u8],
        completed: &mut Vec<FecStripe>,
    ) -> Result<(), CarbonadoError> {
        let mut off = 0usize;
        while off < data.len() {
            if self.pos >= self.logical_len {
                return Err(CarbonadoError::StdIoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "FEC encoder: input exceeds logical length",
                )));
            }
            let cap = self.logical_len - self.pos;
            let room = FEC_STRIPE_LOGICAL_LEN as usize - self.current.len();
            let take = (data.len() - off).min(room).min(cap);
            self.current.extend_from_slice(&data[off..off + take]);
            self.pos += take;
            off += take;
            if self.current.len() == FEC_STRIPE_LOGICAL_LEN as usize {
                completed.push(self.take_stripe()?);
            }
        }
        Ok(())
    }

    fn feed_padding_bytes(
        &mut self,
        data: &[u8],
        completed: &mut Vec<FecStripe>,
    ) -> Result<(), CarbonadoError> {
        let mut off = 0usize;
        while off < data.len() && self.pos < self.padded_len {
            let room = FEC_STRIPE_LOGICAL_LEN as usize - self.current.len();
            let take = (data.len() - off).min(room).min(self.padded_len - self.pos);
            self.current.extend_from_slice(&data[off..off + take]);
            self.pos += take;
            off += take;
            if self.current.len() == FEC_STRIPE_LOGICAL_LEN as usize {
                completed.push(self.take_stripe()?);
            }
        }
        Ok(())
    }

    fn take_stripe(&mut self) -> Result<FecStripe, CarbonadoError> {
        let mut shards = FecStripe::empty_shards();
        let leaf = SLICE_LEN as usize;
        for (i, shard) in shards.iter_mut().enumerate().take(FEC_K) {
            shard.copy_from_slice(&self.current[i * leaf..(i + 1) * leaf]);
        }
        self.current.clear();
        encode_stripe_parity(&self.rs, &mut shards)?;
        Ok(FecStripe {
            shards,
            chunk_len: SLICE_LEN,
        })
    }
}

fn encode_stripe_parity(
    rs: &ReedSolomon<Field>,
    shards: &mut [Vec<u8>],
) -> Result<(), CarbonadoError> {
    #[cfg(feature = "parallel")]
    {
        crate::stream::parallel::encode_rs_parity(rs, shards, SLICE_LEN as usize)?;
    }
    #[cfg(not(feature = "parallel"))]
    {
        rs.encode(shards)?;
    }
    for s in shards.iter() {
        if s.len() != SLICE_LEN as usize {
            return Err(CarbonadoError::EncodeInvalidChunkLength(SLICE_LEN, s.len()));
        }
    }
    Ok(())
}

/// [`positioned_io::ReadAt`] view over concatenated inboard FEC stripe shards.
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
        read_at_shards(&self.stripe.shards, self.len, offset, buf)
    }
}

/// [`ReadAt`] over every stripe of an inboard FEC body, in stripe order.
pub struct FecStripesReadAt<'a> {
    stripes: &'a [FecStripe],
    len: u64,
}

impl<'a> FecStripesReadAt<'a> {
    pub fn new(stripes: &'a [FecStripe]) -> Self {
        let len = stripes.len() as u64 * u64::from(FEC_STRIPE_INBOARD_LEN);
        Self { stripes, len }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl positioned_io::ReadAt for FecStripesReadAt<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let stripe_len = u64::from(FEC_STRIPE_INBOARD_LEN);
        let mut written = 0usize;
        let mut pos = offset;
        while written < buf.len() && pos < self.len {
            let stripe_idx = (pos / stripe_len) as usize;
            let stripe_off = pos % stripe_len;
            let view = FecStripeReadAt::new(&self.stripes[stripe_idx]);
            let n = view.read_at(stripe_off, &mut buf[written..])?;
            if n == 0 {
                break;
            }
            written += n;
            pos += n as u64;
        }
        Ok(written)
    }
}

fn read_at_shards(
    shards: &[Vec<u8>],
    len: u64,
    offset: u64,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    if offset >= len || buf.is_empty() {
        return Ok(0);
    }
    let mut written = 0usize;
    let mut pos = offset;
    let mut cum = 0u64;
    for shard in shards {
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

/// Write parity shards only (outboard `.par` sidecar / Adamantine bundle).
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

/// Write data leaves only (outboard main = data leaves in stripe order).
pub fn write_data_leaves<W: Write>(
    stripe: &FecStripe,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let mut n = 0u64;
    for s in stripe.shards.iter().take(FEC_K) {
        output.write_all(s).map_err(CarbonadoError::StdIoError)?;
        n += s.len() as u64;
    }
    Ok(n)
}

/// Reconstruct one stripe from up to 8 optional 4 KiB symbols (erasures are `None`).
pub fn reconstruct_stripe(shards: &mut [Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>, CarbonadoError> {
    if shards.len() != FEC_M {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let good = shards.iter().filter(|s| s.is_some()).count();
    if good < FEC_K {
        return Err(CarbonadoError::InvalidScrubbedHash);
    }
    let leaf = SLICE_LEN as usize;
    for s in shards.iter().flatten() {
        if s.len() != leaf {
            return Err(CarbonadoError::UnevenFecChunks);
        }
    }
    let rs = ReedSolomon::<Field>::new(FEC_K, FEC_M - FEC_K)?;
    rs.reconstruct(shards)?;
    let mut out = Vec::with_capacity(FEC_M);
    for s in shards.iter_mut() {
        out.push(s.take().ok_or(CarbonadoError::UnevenFecChunks)?);
    }
    Ok(out)
}

fn reconstruct_stripe_logical(
    shards: &mut [Option<Vec<u8>>],
    logical_out: &mut Vec<u8>,
) -> Result<(), CarbonadoError> {
    let rebuilt = reconstruct_stripe(shards)?;
    for leaf in rebuilt.iter().take(FEC_K) {
        logical_out.extend_from_slice(leaf);
    }
    Ok(())
}

/// [`WriteAt`] sink for keyed Bao inboard decode of a multi-stripe FEC body.
///
/// Retains the FEC body (`O(FEC body)` shard bytes) then RS-reconstructs per 16 KiB
/// stripe on [`Self::finish_into`].
pub struct FecInboardWriteAt {
    content_len: u64,
    padding: u32,
    buf: Vec<u8>,
    filled: u64,
    finished: bool,
}

impl FecInboardWriteAt {
    pub fn new(content_len: u64, padding: u32) -> Result<Self, CarbonadoError> {
        if content_len == 0 {
            return Ok(Self {
                content_len: 0,
                padding,
                buf: vec![],
                filled: 0,
                finished: false,
            });
        }
        let len = content_len as usize;
        if !len.is_multiple_of(FEC_STRIPE_INBOARD_LEN as usize) {
            return Err(CarbonadoError::UnevenFecChunks);
        }
        Ok(Self {
            content_len,
            padding,
            buf: vec![0u8; len],
            filled: 0,
            finished: false,
        })
    }

    /// RS-decode each stripe and stream logical bytes (padding stripped) into `output`.
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
        let decoded = decode_inboard_stripes(&self.buf, self.padding)?;
        output
            .write_all(&decoded)
            .map_err(CarbonadoError::StdIoError)?;
        Ok(decoded.len() as u64)
    }

    /// RS-decode the accumulated body and return logical bytes (padding stripped).
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

/// In-memory [`WriteAt`] retaining exactly `content_len` logical bytes.
///
/// Production inboard non-FEC verification uses [`crate::stream::spool::SeekWriteAt`] (disk
/// spool, O(chunk) RAM). This type remains for unit tests of WriteAt completeness contracts.
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

fn decode_inboard_stripes(input: &[u8], padding: u32) -> Result<Vec<u8>, CarbonadoError> {
    if input.is_empty() {
        return Ok(vec![]);
    }
    const STRIPE: usize = FEC_STRIPE_INBOARD_LEN as usize;
    const LEAF: usize = SLICE_LEN as usize;
    let (stripes, remainder) = input.as_chunks::<STRIPE>();
    if !remainder.is_empty() {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let mut logical = Vec::with_capacity(input.len() / 2);
    for stripe in stripes {
        let (leaves, leaf_rem) = stripe.as_chunks::<LEAF>();
        debug_assert!(leaf_rem.is_empty());
        let mut shards: Vec<Option<Vec<u8>>> = leaves.iter().map(|c| Some(c.to_vec())).collect();
        reconstruct_stripe_logical(&mut shards, &mut logical)?;
    }
    if padding as usize > logical.len() {
        return Err(CarbonadoError::ScrubbedLengthMismatch(
            logical.len(),
            padding as usize,
        ));
    }
    logical.truncate(logical.len() - padding as usize);
    Ok(logical)
}

/// Inboard FEC decode from a reader of concatenated 32 KiB stripes.
pub fn stream_decode_inboard<R: Read, W: Write>(
    mut input: R,
    padding: u32,
    _logical_shard_len: usize,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    let stripe_len = FEC_STRIPE_INBOARD_LEN as usize;
    let mut body = Vec::new();
    let mut buf = vec![0u8; stripe_len];
    loop {
        let mut got = 0usize;
        while got < stripe_len {
            let n = input
                .read(&mut buf[got..])
                .map_err(CarbonadoError::StdIoError)?;
            if n == 0 {
                break;
            }
            got += n;
        }
        if got == 0 {
            break;
        }
        if got != stripe_len {
            return Err(CarbonadoError::UnevenFecChunks);
        }
        body.extend_from_slice(&buf);
    }
    let decoded = decode_inboard_stripes(&body, padding)?;
    output
        .write_all(&decoded)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(decoded.len() as u64)
}

/// Outboard FEC decode: bare main reader + parity reader -> logical output.
///
/// Parity is the concatenated 4 KiB parity leaves (4 per stripe). Main is the
/// logical body (data leaves with padding stripped, or a prefix thereof).
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
    let mut parity_buf = Vec::new();
    std::io::copy(&mut parity, &mut parity_buf).map_err(CarbonadoError::StdIoError)?;
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
    let decoded = decode_outboard_stripes(&main_buf, &parity_buf, padding)?;
    output
        .write_all(&decoded)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(decoded.len() as u64)
}

pub(crate) fn decode_outboard_stripes(
    main: &[u8],
    parity: &[u8],
    padding: u32,
) -> Result<Vec<u8>, CarbonadoError> {
    if main.is_empty() && parity.is_empty() {
        return Ok(vec![]);
    }
    const LEAF: usize = SLICE_LEN as usize;
    const PARITY_STRIPE: usize = (FEC_M - FEC_K) * LEAF;
    const LOGICAL_STRIPE: usize = FEC_STRIPE_LOGICAL_LEN as usize;
    let (parity_stripes, remainder) = parity.as_chunks::<PARITY_STRIPE>();
    if !remainder.is_empty() {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let n_stripes = parity_stripes.len();
    let padded_total = n_stripes * LOGICAL_STRIPE;
    let pad = padding as usize;
    if pad > padded_total {
        return Err(CarbonadoError::ScrubbedLengthMismatch(padded_total, pad));
    }
    let logical_len = padded_total - pad;
    let mut padded = vec![0u8; padded_total];
    let copy = main.len().min(logical_len);
    padded[..copy].copy_from_slice(&main[..copy]);

    let mut decoded = Vec::with_capacity(logical_len);
    let (logical_stripes, logical_rem) = padded.as_chunks::<LOGICAL_STRIPE>();
    debug_assert!(logical_rem.is_empty());
    for (stripe_idx, (logical_stripe, parity_stripe)) in
        logical_stripes.iter().zip(parity_stripes).enumerate()
    {
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; FEC_M];
        let data_off = stripe_idx * LOGICAL_STRIPE;
        let (data_leaves, data_rem) = logical_stripe.as_chunks::<LEAF>();
        debug_assert!(data_rem.is_empty());
        for (i, (shard, chunk)) in shards.iter_mut().take(FEC_K).zip(data_leaves).enumerate() {
            let start = data_off + i * LEAF;
            let end = start + LEAF;
            if end <= copy {
                *shard = Some(chunk.to_vec());
            } else if start < copy {
                // Partial last data leaf: treat as erasure.
                *shard = None;
            }
        }
        let (parity_leaves, par_rem) = parity_stripe.as_chunks::<LEAF>();
        debug_assert!(par_rem.is_empty());
        for (shard, chunk) in shards[FEC_K..].iter_mut().zip(parity_leaves) {
            *shard = Some(chunk.to_vec());
        }
        reconstruct_stripe_logical(&mut shards, &mut decoded)?;
    }
    if decoded.len() < logical_len {
        return Err(CarbonadoError::ScrubbedLengthMismatch(
            decoded.len(),
            logical_len,
        ));
    }
    decoded.truncate(logical_len);
    Ok(decoded)
}

fn fec_short_read_error() -> CarbonadoError {
    CarbonadoError::StdIoError(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "FEC encode: short read",
    ))
}

/// Feed exactly `logical_len` bytes and emit every inboard FEC stripe.
pub fn feed_inboard_fec_stripes<R: Read>(
    logical_len: usize,
    input: &mut R,
) -> Result<(Vec<FecStripe>, u32, u32), CarbonadoError> {
    if logical_len == 0 {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    let mut enc = FecInboardEncoder::new(logical_len)?;
    let mut limited = input.take(logical_len as u64);
    let mut stripes = enc.feed(&mut limited)?;
    if limited.limit() > 0 {
        return Err(fec_short_read_error());
    }
    stripes.extend(enc.finish()?);
    if stripes.is_empty() {
        return Err(CarbonadoError::UnevenFecChunks);
    }
    Ok((stripes, enc.padding_len(), enc.chunk_len()))
}

/// Back-compat alias: same as [`feed_inboard_fec_stripes`].
pub fn feed_inboard_fec_stripe<R: Read>(
    logical_len: usize,
    input: &mut R,
) -> Result<(Vec<FecStripe>, u32, u32), CarbonadoError> {
    feed_inboard_fec_stripes(logical_len, input)
}

/// Encode logical bytes into inboard stripes (4 KiB leaves, stripe order).
pub fn encode_stripes(input: &[u8]) -> Result<(Vec<FecStripe>, u32, u32), CarbonadoError> {
    if input.is_empty() {
        return Ok((vec![], 0, 0));
    }
    let mut enc = FecInboardEncoder::new(input.len())?;
    let mut stripes = enc.feed(std::io::Cursor::new(input))?;
    stripes.extend(enc.finish()?);
    Ok((stripes, enc.padding_len(), enc.chunk_len()))
}

pub fn encode_inboard_buffer(input: &[u8]) -> Result<(Vec<u8>, u32, u32), CarbonadoError> {
    if input.is_empty() {
        return Ok((vec![], 0, 0));
    }
    let (stripes, padding_len, chunk_len) = encode_stripes(input)?;
    let mut out = Vec::new();
    for stripe in &stripes {
        write_inboard_stripe(stripe, &mut out)?;
    }
    Ok((out, padding_len, chunk_len))
}

/// Buffer-path helper: parity leaves only for outboard FEC / Adamantine.
pub fn encode_outboard_parity_buffer(input: &[u8]) -> Result<(u32, u32, Vec<u8>), CarbonadoError> {
    if input.is_empty() {
        return Ok((0, 0, vec![]));
    }
    let (stripes, padding_len, chunk_len) = encode_stripes(input)?;
    Ok((padding_len, chunk_len, concat_parity_leaves(&stripes)))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::decoding::fec;

    #[test]
    fn fec_stripe_geometry_is_4kib_leaves() {
        for logical_len in [1usize, 4095, 4096, 4097, 16 * 1024 - 1, 16 * 1024, 32_768] {
            let input: Vec<u8> = (0..logical_len).map(|i| (i % 251) as u8).collect();
            let (encoded, pl, cl) = encode_inboard_buffer(&input).expect("encode");
            let (exp_pl, _exp_cl) = calc_padding_len(logical_len);
            assert_eq!(pl, exp_pl, "padding len for {logical_len}");
            assert_eq!(cl, SLICE_LEN, "chunk_len is 4 KiB for {logical_len}");
            let padded = logical_len + pl as usize;
            let n_stripes = padded / FEC_STRIPE_LOGICAL_LEN as usize;
            assert_eq!(encoded.len(), n_stripes * FEC_STRIPE_INBOARD_LEN as usize);
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
    fn two_stripes_place_second_data_after_first_parity() {
        let input: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
        let (encoded, _, cl) = encode_inboard_buffer(&input).expect("encode");
        assert_eq!(cl, SLICE_LEN);
        assert_eq!(encoded.len(), 2 * FEC_STRIPE_INBOARD_LEN as usize);
        assert_eq!(&encoded[0..4096], &input[0..4096]);
        assert_ne!(&encoded[16_384..20_480], &input[16_384..20_480]);
        assert_eq!(&encoded[32_768..36_864], &input[16_384..20_480]);
    }

    #[test]
    fn fec_stripe_read_at_matches_flattened_stripe() {
        use positioned_io::ReadAt;

        let input: Vec<u8> = (0..12_288).map(|i| (i % 251) as u8).collect();
        let (stripes, _, _) = encode_stripes(&input).expect("stripes");
        assert_eq!(stripes.len(), 1);
        let mut flat = Vec::new();
        write_inboard_stripe(&stripes[0], &mut flat).expect("flatten");

        let view = FecStripeReadAt::new(&stripes[0]);
        assert_eq!(view.len(), flat.len() as u64);

        let mut via_read_at = vec![0u8; flat.len()];
        let n = view
            .read_at(0, &mut via_read_at)
            .expect("read_at full stripe");
        assert_eq!(n, flat.len());
        assert_eq!(via_read_at, flat);
    }

    #[test]
    fn fec_stripes_read_at_matches_concatenated_body() {
        use positioned_io::ReadAt;

        let input: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
        let (stripes, _, _) = encode_stripes(&input).expect("stripes");
        let (flat, _, _) = encode_inboard_buffer(&input).expect("flat");
        let view = FecStripesReadAt::new(&stripes);
        let mut got = vec![0u8; flat.len()];
        let n = view.read_at(0, &mut got).expect("read_at");
        assert_eq!(n, flat.len());
        assert_eq!(got, flat);
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
        let err =
            feed_inboard_fec_stripes(input.len(), &mut Cursor::new(short)).expect_err("short");
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
        let input: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
        let (buf_encoded, _, _) = encode_inboard_buffer(&input).expect("buffer");

        let mut enc = FecInboardEncoder::new(input.len()).expect("new");
        let mut off = 0usize;
        let mut stripes = Vec::new();
        while off < input.len() {
            let step = 512.min(input.len() - off);
            stripes.extend(
                enc.feed(Cursor::new(&input[off..off + step]))
                    .expect("feed"),
            );
            off += step;
        }
        stripes.extend(enc.finish().expect("finish"));
        let mut incremental = Vec::new();
        for stripe in &stripes {
            write_inboard_stripe(stripe, &mut incremental).expect("write");
        }
        assert_eq!(incremental, buf_encoded);
        assert_eq!(stripes.len(), 2);
    }

    #[test]
    fn outboard_parity_reconstructs_with_bare_main() {
        use crate::decoding::fec_with_parity;

        let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let (pl, chunk_len, parity) = encode_outboard_parity_buffer(&input).expect("parity");
        let decoded = fec_with_parity(&input, &parity, pl).expect("fec outboard");
        assert_eq!(decoded, input);
        assert_eq!(chunk_len, SLICE_LEN);
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
    fn stripe_data_and_parity_lens() {
        let input: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
        let (stripes, _, _) = encode_stripes(&input).expect("stripes");
        assert_eq!(stripes.len(), 2);
        for stripe in &stripes {
            let (data, parity) = stripe_data_and_parity_leaves(stripe);
            assert_eq!(data.len(), FEC_K);
            assert_eq!(parity.len(), FEC_M - FEC_K);
            assert!(data.iter().all(|l| l.len() == SLICE_LEN as usize));
            assert!(parity.iter().all(|l| l.len() == SLICE_LEN as usize));
        }
        let data = concat_data_leaves(&stripes);
        assert_eq!(data, input);
        assert_eq!(
            concat_parity_leaves(&stripes).len(),
            2 * (FEC_M - FEC_K) * SLICE_LEN as usize
        );
    }

    #[test]
    fn fec_inboard_write_at_roundtrip_matches_decoding_fec() {
        use positioned_io::WriteAt;

        let input: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
        let (encoded, pl, _) = encode_inboard_buffer(&input).expect("encode");
        let content_len = encoded.len() as u64;
        let expected = fec(&encoded, pl).expect("buffer fec");

        let mut sink = FecInboardWriteAt::new(content_len, pl).expect("new");
        let shard_len = SLICE_LEN as usize;
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
        let shard_len = SLICE_LEN as usize;

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
