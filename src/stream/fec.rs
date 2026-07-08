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

    /// Feed logical bytes from `input`. Returns `Some(stripe)` when the stripe is complete.
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
            if self.feed_bytes(&buf[..n])? {
                return Ok(Some(self.take_stripe()?));
            }
        }
        if self.pos >= self.padded_len && !self.finished {
            self.finished = true;
            return Ok(Some(self.take_stripe()?));
        }
        Ok(None)
    }

    /// Finalize when the caller has fed exactly `logical_len` bytes (padding added internally).
    pub fn finish(&mut self) -> Result<Option<FecStripe>, CarbonadoError> {
        if self.finished || self.padded_len == 0 {
            return Ok(None);
        }
        if self.pos < self.padded_len {
            let zeros = vec![0u8; self.padded_len - self.pos];
            self.feed_bytes(&zeros)?;
        }
        self.finished = true;
        Ok(Some(self.take_stripe()?))
    }

    fn feed_bytes(&mut self, data: &[u8]) -> Result<bool, CarbonadoError> {
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
        Ok(self.pos >= self.padded_len)
    }

    fn take_stripe(&mut self) -> Result<FecStripe, CarbonadoError> {
        self.rs.encode(&mut self.shards)?;
        for s in &self.shards {
            if s.len() != self.chunk_len {
                return Err(CarbonadoError::EncodeInvalidChunkLength(
                    self.chunk_len as u32,
                    s.len(),
                ));
            }
        }
        Ok(FecStripe {
            shards: self.shards.clone(),
            chunk_len: self.chunk_len as u32,
        })
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
pub fn stream_decode_outboard<R: Read, W: Write>(
    mut main: R,
    mut parity: R,
    padding: u32,
    main_len: usize,
    output: &mut W,
) -> Result<u64, CarbonadoError> {
    if main_len == 0 {
        return Ok(0);
    }
    let (calc_pad, chunk_len) = calc_padding_len(main_len);
    let pad = if padding != 0 { padding } else { calc_pad };
    let shard_len = chunk_len as usize;

    let mut padded = Vec::with_capacity(main_len + pad as usize);
    let mut buf = [0u8; SLICE_LEN as usize];
    let mut read_main = 0usize;
    while read_main < main_len {
        let n = main.read(&mut buf).map_err(CarbonadoError::StdIoError)?;
        if n == 0 {
            break;
        }
        let take = n.min(main_len - read_main);
        padded.extend_from_slice(&buf[..take]);
        read_main += take;
    }
    padded.resize(main_len + pad as usize, 0);

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; FEC_M];
    for (i, shard) in shards.iter_mut().enumerate().take(FEC_K) {
        let start = i * shard_len;
        let end = start + shard_len;
        *shard = Some(padded[start..end].to_vec());
    }
    for j in 0..(FEC_M - FEC_K) {
        let mut pbuf = vec![0u8; shard_len];
        parity
            .read_exact(&mut pbuf)
            .map_err(CarbonadoError::StdIoError)?;
        shards[FEC_K + j] = Some(pbuf);
    }

    let rs = ReedSolomon::<Field>::new(FEC_K, FEC_M - FEC_K)?;
    rs.reconstruct(&mut shards)?;
    let mut decoded = Vec::new();
    for s in shards.iter().take(FEC_K).flatten() {
        decoded.extend_from_slice(s);
    }
    if (decoded.len() as u32) < pad {
        return Err(CarbonadoError::ScrubbedLengthMismatch(
            decoded.len(),
            pad as usize,
        ));
    }
    decoded.truncate(decoded.len() - pad as usize);
    output
        .write_all(&decoded)
        .map_err(CarbonadoError::StdIoError)?;
    Ok(decoded.len() as u64)
}

/// Buffer-path helper: encode entire logical blob in one stripe.
fn take_stripe(enc: &mut FecInboardEncoder, input: &[u8]) -> Result<FecStripe, CarbonadoError> {
    if let Some(stripe) = enc.feed(std::io::Cursor::new(input))? {
        return Ok(stripe);
    }
    enc.finish()?.ok_or(CarbonadoError::UnevenZfecChunks)
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
    use crate::decoding::zfec;

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
            let decoded = zfec(&encoded, pl).expect("zfec");
            assert_eq!(decoded, input);
        }
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
        use crate::decoding::zfec_with_parity;

        let input: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let (pl, chunk_len, parity) = encode_outboard_parity_buffer(&input).expect("parity");
        // Outboard bare main is the pre-FEC logical body; parity sidecar holds RS parity shards.
        let decoded = zfec_with_parity(&input, &parity, pl).expect("zfec outboard");
        assert_eq!(decoded, input);
        assert_eq!(chunk_len % SLICE_LEN, 0);
    }
}
