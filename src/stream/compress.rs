//! Zstd level-20 streaming compression over [`Read`] / [`Write`].

use std::io::{Read, Write};

use crate::{error::CarbonadoError, filepack_manifest::MAX_SEGMENT_MAIN_LEN};

const ZSTD_LEVEL: i32 = 20;

struct CountWriter<W> {
    inner: W,
    count: u64,
    max: Option<u64>,
}

impl<W: Write> Write for CountWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next = self.count.saturating_add(buf.len() as u64);
        if let Some(max) = self.max {
            if next > max {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "decompressed output exceeds maximum allowed size",
                ));
            }
        }
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Stream-compress `input` into `output` at level 20. Returns compressed bytes written.
///
/// Under `backend-lean`, materializes the input and uses the zstd **buffer** API
/// (`ZSTD_compress` / `zstd::bulk`) so frames match Lean AOT (`Carbonado.Compress`).
/// Streaming `copy_encode` frames differ byte-for-byte from the buffer API at the same
/// level — that mismatch broke stream-vs-buffer parity under dual-engine (R5).
///
/// **W4c permanent residual:** buffer-only under lean (no dual-safe multi-chunk streaming
/// frames). Cross-engine compress re-encode remains non-bit-identical (**W2a**); do not
/// invent streaming-frame bit-match claims. Peak: **O(logical)** RAM for compress under
/// lean — public outboard formats with the Compression bit (c2/c6/c10/c14) are **not**
/// W1b E2 under lean; E2 MVP is **non-compress** public outboard (c0/c4/c8/c12).
/// See docs/LIMITS.md Stream E1/E2 matrix.
pub fn stream_compress<R: Read, W: Write>(mut input: R, output: W) -> Result<u64, CarbonadoError> {
    #[cfg(feature = "backend-lean")]
    {
        let mut plaintext = Vec::new();
        input
            .read_to_end(&mut plaintext)
            .map_err(CarbonadoError::StdIoError)?;
        let compressed = zstd::bulk::Compressor::new(ZSTD_LEVEL)
            .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?
            .compress(&plaintext)
            .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
        let mut counter = CountWriter {
            inner: output,
            count: 0,
            max: None,
        };
        counter
            .write_all(&compressed)
            .map_err(CarbonadoError::StdIoError)?;
        Ok(counter.count)
    }
    #[cfg(feature = "backend-rust")]
    {
        let mut counter = CountWriter {
            inner: output,
            count: 0,
            max: None,
        };
        zstd::stream::copy_encode(&mut input, &mut counter, ZSTD_LEVEL)
            .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
        Ok(counter.count)
    }
}

/// Stream-decompress `input` into `output`. Returns decompressed bytes written.
pub fn stream_decompress<R: Read, W: Write>(
    mut input: R,
    output: W,
) -> Result<u64, CarbonadoError> {
    let mut counter = CountWriter {
        inner: output,
        count: 0,
        max: Some(MAX_SEGMENT_MAIN_LEN),
    };
    zstd::stream::copy_decode(&mut input, &mut counter)
        .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
    Ok(counter.count)
}

/// Buffer convenience: compress `input` via the streaming helper.
pub fn compress_buffer(input: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    let mut out = Vec::new();
    stream_compress(input, &mut out)?;
    Ok(out)
}

/// Buffer convenience: decompress `input` via the streaming helper.
pub fn decompress_buffer(input: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    let mut out = Vec::new();
    stream_decompress(input, &mut out)?;
    Ok(out)
}
