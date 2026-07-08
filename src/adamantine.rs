//! Adamantine 1.0 wire envelope for directory catalog payloads.
//!
//! Version is encoded in the magic string only (like `CARBONADO20\n` for Carbonado 2.0).
//! The Adamantine header wraps the [`adamantine_payload`](crate::adamantine_payload) body
//! (rkyv manifest + centralized segment Bao bundle) before the inboard Carbonado catalog
//! pipeline (format c14 or c15).
//!
//! ## Byte layout (little-endian, v1.0)
//!
//! ```text
//! Offset  Size  Field
//! 0       13    magic            ADAMANTINE10\n   (version 1.0 in magic)
//! 13      1     carbonado_fmt    0x0E | 0x0F (catalog only)
//! 14      1     flags            u8 (bit0 REQUIRE_OTS = per-entry proofs required at decode; bits 1–7 reserved, must be 0)
//! 15      4     payload_len      u32 LE
//! 19      N     payload          rkyv + Bao bundle (see adamantine_payload)
//! ```
//!
//! Dev `ADAMANTINE2\n` and separate version bytes are rejected.

/// Magic bytes for Adamantine 1.0 (`ADAMANTINE10\n`, version 1.0 encoded in magic).
pub const ADAMANTINE_MAGIC: &[u8; 13] = b"ADAMANTINE10\n";

/// Deprecated dev v2 magic — decode rejects explicitly.
const ADAMANTINE_MAGIC_DEV_V2: &[u8; 12] = b"ADAMANTINE2\n";

/// Deprecated v1 magic — decode rejects explicitly.
const ADAMANTINE_MAGIC_V1: &[u8; 12] = b"ADAMANTINE1\n";

/// Total Adamantine header length in bytes.
pub const ADAMANTINE_HEADER_LEN: usize = 19;

/// Carbonado format byte for public directory catalogs (c14).
pub const ADAMANTINE_CARBONADO_FMT_PUBLIC: u8 = 0x0E;

/// Carbonado format byte for encrypted directory catalogs (c15).
pub const ADAMANTINE_CARBONADO_FMT_ENCRYPTED: u8 = 0x0F;

/// Adamantine flag bit 0: per-entry OpenTimestamps proofs required at decode (`ots` feature).
pub const ADAMANTINE_FLAG_REQUIRE_OTS: u8 = 1;

/// Allowed Adamantine flag bits in v1.0 (bits 1–7 reserved, must be zero).
const ADAMANTINE_FLAGS_MASK: u8 = ADAMANTINE_FLAG_REQUIRE_OTS;

use crate::adamantine_payload::MAX_ADAMANTINE_PAYLOAD_LEN;
use crate::error::CarbonadoError;

/// Parsed Adamantine 1.0 header fields (excluding payload bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdamantineHeader {
    pub carbonado_fmt: u8,
    pub flags: u8,
}

/// Prepend the Adamantine 1.0 header to an adamantine payload (rkyv + Bao bundle).
pub fn encode_adamantine(payload: &[u8], carbonado_fmt: u8, flags: u8) -> Vec<u8> {
    let payload_len = payload.len();
    debug_assert!(payload_len <= u32::MAX as usize);

    let mut out = Vec::with_capacity(ADAMANTINE_HEADER_LEN + payload_len);
    out.extend_from_slice(ADAMANTINE_MAGIC);
    out.push(carbonado_fmt);
    out.push(flags);
    out.extend_from_slice(&(payload_len as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Strip and validate the Adamantine 1.0 header, returning payload bytes and header fields.
pub fn decode_adamantine(bytes: &[u8]) -> Result<(Vec<u8>, AdamantineHeader), CarbonadoError> {
    if bytes.len() < ADAMANTINE_HEADER_LEN {
        return Err(CarbonadoError::InvalidAdamantineHeader);
    }

    let magic = &bytes[0..13];
    if magic == ADAMANTINE_MAGIC {
        // supported v1.0
    } else if bytes.len() >= 12 {
        let legacy = &bytes[0..12];
        if legacy == ADAMANTINE_MAGIC_V1 {
            return Err(CarbonadoError::UnsupportedAdamantineVersion { major: 1, minor: 0 });
        }
        if legacy == ADAMANTINE_MAGIC_DEV_V2 {
            return Err(CarbonadoError::UnsupportedAdamantineVersion { major: 2, minor: 0 });
        }
        if let Some((major, minor)) = parse_unsupported_magic_version(magic) {
            return Err(CarbonadoError::UnsupportedAdamantineVersion { major, minor });
        }
        return Err(CarbonadoError::InvalidAdamantineMagic);
    } else {
        return Err(CarbonadoError::InvalidAdamantineMagic);
    }

    let carbonado_fmt = bytes[13];
    validate_carbonado_fmt(carbonado_fmt)?;

    let flags = bytes[14];
    validate_flags(flags)?;

    let payload_len = u32::from_le_bytes(
        bytes[15..19]
            .try_into()
            .map_err(|_| CarbonadoError::InvalidAdamantineHeader)?,
    );
    if payload_len as usize > MAX_ADAMANTINE_PAYLOAD_LEN {
        return Err(CarbonadoError::InvalidAdamantinePayloadTooLarge {
            declared: payload_len,
            max: MAX_ADAMANTINE_PAYLOAD_LEN,
        });
    }
    let payload_end = ADAMANTINE_HEADER_LEN
        .checked_add(payload_len as usize)
        .ok_or(CarbonadoError::InvalidAdamantineHeader)?;

    if bytes.len() < payload_end {
        return Err(CarbonadoError::InvalidAdamantinePayloadLength {
            expected: payload_len,
            available: bytes.len().saturating_sub(ADAMANTINE_HEADER_LEN),
        });
    }

    if bytes.len() != payload_end {
        return Err(CarbonadoError::InvalidAdamantineHeader);
    }

    Ok((
        bytes[ADAMANTINE_HEADER_LEN..payload_end].to_vec(),
        AdamantineHeader {
            carbonado_fmt,
            flags,
        },
    ))
}

/// Parse `ADAMANTINE{digit}{digit}\n` or `ADAMANTINE{digit}\n` version from unsupported magic.
fn parse_unsupported_magic_version(magic: &[u8]) -> Option<(u8, u8)> {
    if magic.len() < 12 {
        return None;
    }
    if &magic[0..10] != b"ADAMANTINE" {
        return None;
    }
    let b10 = magic[10];
    let b11 = magic.get(11).copied().unwrap_or(b'\n');
    if b11 == b'\n' {
        if b10.is_ascii_digit() {
            return Some((b10 - b'0', 0));
        }
        return None;
    }
    if b11.is_ascii_digit() && magic.get(12) == Some(&b'\n') && b10.is_ascii_digit() {
        return Some((b10 - b'0', b11 - b'0'));
    }
    None
}

fn validate_carbonado_fmt(fmt: u8) -> Result<(), CarbonadoError> {
    if fmt != ADAMANTINE_CARBONADO_FMT_PUBLIC && fmt != ADAMANTINE_CARBONADO_FMT_ENCRYPTED {
        return Err(CarbonadoError::InvalidAdamantineCarbonadoFormat(fmt));
    }
    Ok(())
}

fn validate_flags(flags: u8) -> Result<(), CarbonadoError> {
    if flags & !ADAMANTINE_FLAGS_MASK != 0 {
        return Err(CarbonadoError::InvalidAdamantineFlags(flags));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip_public() {
        let payload = b"rkyv-bytes-placeholder".to_vec();
        let wrapped = encode_adamantine(&payload, ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        assert_eq!(wrapped.len(), ADAMANTINE_HEADER_LEN + payload.len());
        assert_eq!(&wrapped[0..13], ADAMANTINE_MAGIC);
        assert_eq!(wrapped[13], ADAMANTINE_CARBONADO_FMT_PUBLIC);
        assert_eq!(wrapped[14], 0);
        let (decoded, hdr) = decode_adamantine(&wrapped).expect("decode");
        assert_eq!(decoded, payload);
        assert_eq!(hdr.carbonado_fmt, ADAMANTINE_CARBONADO_FMT_PUBLIC);
        assert_eq!(hdr.flags, 0);
    }

    #[test]
    fn encode_decode_roundtrip_encrypted() {
        let payload = b"encrypted-catalog".to_vec();
        let flags = 0u8;
        let wrapped = encode_adamantine(&payload, ADAMANTINE_CARBONADO_FMT_ENCRYPTED, flags);
        let (decoded, hdr) = decode_adamantine(&wrapped).expect("decode");
        assert_eq!(decoded, payload);
        assert_eq!(hdr.carbonado_fmt, ADAMANTINE_CARBONADO_FMT_ENCRYPTED);
        assert_eq!(hdr.flags, flags);
    }

    #[test]
    fn encode_decode_roundtrip_require_ots_flag() {
        let payload = b"ots-catalog".to_vec();
        let wrapped = encode_adamantine(
            &payload,
            ADAMANTINE_CARBONADO_FMT_PUBLIC,
            ADAMANTINE_FLAG_REQUIRE_OTS,
        );
        let (decoded, hdr) = decode_adamantine(&wrapped).expect("decode");
        assert_eq!(decoded, payload);
        assert_eq!(hdr.flags, ADAMANTINE_FLAG_REQUIRE_OTS);
    }

    #[test]
    fn reject_v1_magic() {
        let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        bytes[0..12].copy_from_slice(ADAMANTINE_MAGIC_V1);
        let err = decode_adamantine(&bytes).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::UnsupportedAdamantineVersion { major: 1, minor: 0 }
        ));
    }

    #[test]
    fn reject_dev_v2_magic() {
        let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        bytes[0..12].copy_from_slice(ADAMANTINE_MAGIC_DEV_V2);
        let err = decode_adamantine(&bytes).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::UnsupportedAdamantineVersion { major: 2, minor: 0 }
        ));
    }

    #[test]
    fn reject_bad_magic() {
        let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        bytes[0] = b'X';
        let err = decode_adamantine(&bytes).unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidAdamantineMagic));
    }

    #[test]
    fn reject_unsupported_future_version() {
        let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        bytes[10] = b'2';
        bytes[11] = b'0';
        let err = decode_adamantine(&bytes).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::UnsupportedAdamantineVersion { major: 2, minor: 0 }
        ));
    }

    #[test]
    fn reject_truncated_payload_len() {
        let wrapped = encode_adamantine(b"hello", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        let truncated = &wrapped[..ADAMANTINE_HEADER_LEN + 2];
        let err = decode_adamantine(truncated).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::InvalidAdamantinePayloadLength { .. }
        ));
    }

    #[test]
    fn reject_truncated_header() {
        let err = decode_adamantine(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidAdamantineHeader));
    }

    #[test]
    fn reject_unknown_flags() {
        let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        bytes[14] = 2;
        let err = decode_adamantine(&bytes).unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidAdamantineFlags(2)));
    }

    #[test]
    fn reject_invalid_carbonado_fmt() {
        let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        bytes[13] = 6;
        let err = decode_adamantine(&bytes).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::InvalidAdamantineCarbonadoFormat(6)
        ));
    }

    #[test]
    fn reject_trailing_bytes_after_payload() {
        let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        bytes.push(0xFF);
        let err = decode_adamantine(&bytes).unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidAdamantineHeader));
    }

    #[test]
    fn reject_oversized_payload_len() {
        let mut bytes = encode_adamantine(b"x", ADAMANTINE_CARBONADO_FMT_PUBLIC, 0);
        let declared = (MAX_ADAMANTINE_PAYLOAD_LEN + 1) as u32;
        bytes[15..19].copy_from_slice(&declared.to_le_bytes());
        let err = decode_adamantine(&bytes).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::InvalidAdamantinePayloadTooLarge {
                declared: d,
                max: m
            } if d == declared && m == MAX_ADAMANTINE_PAYLOAD_LEN
        ));
    }
}
