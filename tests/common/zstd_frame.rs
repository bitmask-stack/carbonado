//! RFC 8878 / `ref/zstd/doc/zstd_compression_format.md` frame-header parser.
//!
//! Mirrors Lean `Carbonado.Compress.parseZstdFrameHeader` so Rust tests can
//! assert the same parameter bits the spec names.

use carbonado::constants::ZSTD_MAGIC;

/// Frame-header parse errors (RFC reserved-bit + framing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZstdFrameError {
    TruncatedHeader,
    BadMagic,
    ReservedBitSet,
}

/// Parsed zstd `Frame_Header` (magic included in `header_len`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedZstdFrameHeader {
    pub descriptor: u8,
    pub content_size_flag: u8,
    pub single_segment: bool,
    pub unused_bit: bool,
    pub reserved_bit: bool,
    pub content_checksum: bool,
    pub dictionary_id_flag: u8,
    pub window_descriptor: Option<u8>,
    pub window_log: Option<u32>,
    pub window_size: Option<u64>,
    pub dictionary_id: Option<u32>,
    pub content_size: Option<u64>,
    pub header_len: usize,
}

fn did_field_size(flag: u8) -> usize {
    match flag {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => 0,
    }
}

fn fcs_field_size(fcs_flag: u8, single_segment: bool) -> usize {
    match (fcs_flag, single_segment) {
        (1, _) => 2,
        (2, _) => 4,
        (3, _) => 8,
        (0, true) => 1,
        (0, false) => 0,
        _ => 0,
    }
}

fn read_le_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn read_le_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn read_le_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

fn window_log_from_descriptor(wd: u8) -> u32 {
    10 + u32::from(wd >> 3)
}

fn window_size_from_descriptor(wd: u8) -> u64 {
    let exponent = u32::from(wd >> 3);
    let mantissa = u64::from(wd & 7);
    let window_log = 10 + exponent;
    let window_base = 1u64 << window_log;
    window_base + (window_base / 8) * mantissa
}

/// Parse magic + `Frame_Header`. Rejects RFC reserved bit.
pub fn parse_zstd_frame_header(bytes: &[u8]) -> Result<ParsedZstdFrameHeader, ZstdFrameError> {
    if bytes.len() < 5 {
        return Err(ZstdFrameError::TruncatedHeader);
    }
    if bytes[0..4] != ZSTD_MAGIC {
        return Err(ZstdFrameError::BadMagic);
    }
    let descriptor = bytes[4];
    let content_size_flag = descriptor >> 6;
    let single_segment = (descriptor & 0x20) != 0;
    let unused_bit = (descriptor & 0x10) != 0;
    let reserved_bit = (descriptor & 0x08) != 0;
    let content_checksum = (descriptor & 0x04) != 0;
    let dictionary_id_flag = descriptor & 0x03;
    if reserved_bit {
        return Err(ZstdFrameError::ReservedBitSet);
    }
    let need_win = if single_segment { 0 } else { 1 };
    let did_sz = did_field_size(dictionary_id_flag);
    let fcs_sz = fcs_field_size(content_size_flag, single_segment);
    let header_len = 5 + need_win + did_sz + fcs_sz;
    if bytes.len() < header_len {
        return Err(ZstdFrameError::TruncatedHeader);
    }
    let window_descriptor = if single_segment { None } else { Some(bytes[5]) };
    let (window_log, window_size) = if let Some(wd) = window_descriptor {
        (
            Some(window_log_from_descriptor(wd)),
            Some(window_size_from_descriptor(wd)),
        )
    } else {
        (None, None)
    };
    let did_off = 5 + need_win;
    let dictionary_id = match did_sz {
        0 => None,
        1 => Some(u32::from(bytes[did_off])),
        2 => Some(u32::from(read_le_u16(bytes, did_off))),
        4 => Some(read_le_u32(bytes, did_off)),
        _ => None,
    };
    let fcs_off = did_off + did_sz;
    let content_size = match fcs_sz {
        0 => None,
        1 => Some(u64::from(bytes[fcs_off])),
        2 => Some(u64::from(read_le_u16(bytes, fcs_off)) + 256),
        4 => Some(u64::from(read_le_u32(bytes, fcs_off))),
        8 => Some(read_le_u64(bytes, fcs_off)),
        _ => None,
    };
    let window_size = if single_segment {
        content_size
    } else {
        window_size
    };
    Ok(ParsedZstdFrameHeader {
        descriptor,
        content_size_flag,
        single_segment,
        unused_bit,
        reserved_bit,
        content_checksum,
        dictionary_id_flag,
        window_descriptor,
        window_log,
        window_size,
        dictionary_id,
        content_size,
        header_len,
    })
}
