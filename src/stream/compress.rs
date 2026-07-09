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
pub fn stream_compress<R: Read, W: Write>(mut input: R, output: W) -> Result<u64, CarbonadoError> {
    let mut counter = CountWriter {
        inner: output,
        count: 0,
        max: None,
    };
    zstd::stream::copy_encode(&mut input, &mut counter, ZSTD_LEVEL)
        .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
    Ok(counter.count)
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
