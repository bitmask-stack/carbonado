//! Zstd streaming compression over [`Read`] / [`Write`].
//!
//! Compression **level is encoder input**. There is no silent library default.

use std::io::{BufReader, Read, Write};

use crate::{
    constants::ZSTD_DICTIONARY_MAGIC, error::CarbonadoError,
    filepack_manifest::MAX_SEGMENT_MAIN_LEN,
};

/// Caller-supplied zstd parameters. `level` is required when the Compression bit is set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZstdEncode {
    /// Compression level. `None` with the Compression bit set is [`CarbonadoError::MissingZstdLevel`].
    pub level: Option<i32>,
    /// RFC 8878 dictionary bytes (optional). Stored in the Adamantine dict section when encoding files.
    pub dict: Option<Vec<u8>>,
}

impl ZstdEncode {
    /// Explicit level, no dictionary.
    pub fn level(level: i32) -> Self {
        Self {
            level: Some(level),
            dict: None,
        }
    }

    /// Explicit level and dictionary.
    pub fn with_dict(level: i32, dict: Vec<u8>) -> Self {
        Self {
            level: Some(level),
            dict: Some(dict),
        }
    }
}

/// Resolve level when the Compression bit is set. Missing level is an error even if `dict` is present.
pub fn require_zstd_level(zstd: &ZstdEncode) -> Result<i32, CarbonadoError> {
    zstd.level.ok_or(CarbonadoError::MissingZstdLevel)
}

/// RFC 8878 dictionary ID (little-endian u32 after magic), if `dict` is a trained zstd dict.
pub fn zstd_dictionary_id(dict: &[u8]) -> Option<u32> {
    if dict.len() < 8 || dict[0..4] != ZSTD_DICTIONARY_MAGIC {
        return None;
    }
    Some(u32::from_le_bytes(dict[4..8].try_into().ok()?))
}

/// Dictionary_ID from a zstd frame header, if present.
pub fn zstd_frame_dictionary_id(frame: &[u8]) -> Result<Option<u32>, CarbonadoError> {
    if frame.len() < 5 {
        return Err(CarbonadoError::ZstdError(
            "truncated zstd frame header".into(),
        ));
    }
    if frame[0..4] != crate::constants::ZSTD_MAGIC {
        return Ok(None);
    }
    let descriptor = frame[4];
    if (descriptor & 0x08) != 0 {
        return Err(CarbonadoError::ZstdError("zstd reserved bit set".into()));
    }
    let dictionary_id_flag = descriptor & 0x03;
    let single_segment = (descriptor & 0x20) != 0;
    let need_win = if single_segment { 0 } else { 1 };
    let did_sz = match dictionary_id_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => 0,
    };
    let header_len = 5 + need_win + did_sz;
    if frame.len() < header_len {
        return Err(CarbonadoError::ZstdError(
            "truncated zstd frame header".into(),
        ));
    }
    let did_off = 5 + need_win;
    let id = match did_sz {
        0 => None,
        1 => Some(u32::from(frame[did_off])),
        2 => Some(u32::from(u16::from_le_bytes([
            frame[did_off],
            frame[did_off + 1],
        ]))),
        4 => Some(u32::from_le_bytes(
            frame[did_off..did_off + 4]
                .try_into()
                .map_err(|_| CarbonadoError::ZstdError("truncated dictionary id".into()))?,
        )),
        _ => None,
    };
    Ok(id)
}

struct CountWriter<W> {
    inner: W,
    count: u64,
    max: Option<u64>,
}

impl<W: Write> Write for CountWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next = self.count.saturating_add(buf.len() as u64);
        if let Some(max) = self.max
            && next > max
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed output exceeds maximum allowed size",
            ));
        }
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Stream-compress `input` into `output` at the caller-supplied `level`.
/// Returns compressed bytes written.
pub fn stream_compress<R: Read, W: Write>(
    input: R,
    output: W,
    level: i32,
) -> Result<u64, CarbonadoError> {
    stream_compress_with_dict(input, output, level, None)
}

/// Stream-compress with an optional RFC 8878 dictionary.
pub fn stream_compress_with_dict<R: Read, W: Write>(
    mut input: R,
    output: W,
    level: i32,
    dict: Option<&[u8]>,
) -> Result<u64, CarbonadoError> {
    let mut counter = CountWriter {
        inner: output,
        count: 0,
        max: None,
    };
    if let Some(dict) = dict.filter(|d| !d.is_empty()) {
        let mut encoder = zstd::stream::Encoder::with_dictionary(&mut counter, level, dict)
            .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
        encoder
            .include_checksum(false)
            .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
        std::io::copy(&mut input, &mut encoder).map_err(CarbonadoError::StdIoError)?;
        encoder
            .finish()
            .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
    } else {
        zstd::stream::copy_encode(&mut input, &mut counter, level)
            .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
    }
    Ok(counter.count)
}

/// Stream-decompress `input` into `output`. Returns decompressed bytes written.
pub fn stream_decompress<R: Read, W: Write>(input: R, output: W) -> Result<u64, CarbonadoError> {
    stream_decompress_with_dict(input, output, None)
}

/// Stream-decompress, using `dict` when the frame names a Dictionary_ID.
pub fn stream_decompress_with_dict<R: Read, W: Write>(
    input: R,
    output: W,
    dict: Option<&[u8]>,
) -> Result<u64, CarbonadoError> {
    let mut counter = CountWriter {
        inner: output,
        count: 0,
        max: Some(MAX_SEGMENT_MAIN_LEN),
    };
    let mut prefixed = PrefixRead {
        prefix: Vec::new(),
        inner: input,
        pos: 0,
    };
    let mut hdr = [0u8; 16];
    let n = prefixed
        .fill_prefix(&mut hdr)
        .map_err(CarbonadoError::StdIoError)?;
    let frame_id = zstd_frame_dictionary_id(&hdr[..n])?;
    if let Some(id) = frame_id {
        let dict_bytes = dict
            .filter(|d| !d.is_empty())
            .ok_or(CarbonadoError::MissingZstdDictionary { dictionary_id: id })?;
        let mut decoder =
            zstd::stream::Decoder::with_dictionary(BufReader::new(&mut prefixed), dict_bytes)
                .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
        std::io::copy(&mut decoder, &mut counter).map_err(CarbonadoError::StdIoError)?;
    } else {
        zstd::stream::copy_decode(&mut prefixed, &mut counter)
            .map_err(|e| CarbonadoError::ZstdError(e.to_string()))?;
    }
    Ok(counter.count)
}

/// Buffer convenience: compress `input` at `level` with no dictionary.
pub fn compress_buffer(input: &[u8], level: i32) -> Result<Vec<u8>, CarbonadoError> {
    let mut out = Vec::new();
    stream_compress(input, &mut out, level)?;
    Ok(out)
}

/// Buffer convenience: compress `input` at `level` with an RFC 8878 dictionary.
pub fn compress_buffer_with_dict(
    input: &[u8],
    level: i32,
    dict: &[u8],
) -> Result<Vec<u8>, CarbonadoError> {
    let mut out = Vec::new();
    stream_compress_with_dict(input, &mut out, level, Some(dict))?;
    Ok(out)
}

/// Buffer convenience: decompress `input`.
pub fn decompress_buffer(input: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    decompress_buffer_with_dict(input, None)
}

/// Buffer convenience: decompress `input`, with optional dictionary.
pub fn decompress_buffer_with_dict(
    input: &[u8],
    dict: Option<&[u8]>,
) -> Result<Vec<u8>, CarbonadoError> {
    let mut out = Vec::new();
    stream_decompress_with_dict(input, &mut out, dict)?;
    Ok(out)
}

/// Replay a short prefix then the rest of `inner` (for frame-header peek).
struct PrefixRead<R> {
    prefix: Vec<u8>,
    inner: R,
    pos: usize,
}

impl<R: Read> PrefixRead<R> {
    fn fill_prefix(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.prefix.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl<R: Read> Read for PrefixRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}
