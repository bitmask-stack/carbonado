//! Per-segment Carbonado format selection for directory archives.
//!
//! Directory catalogs are always inboard c14 (public) or c15 (encrypted). Individual file
//! segments use heterogeneous c12/c14 (public) or c13/c15 (encrypted) chosen by
//! [`SegmentFormatPolicy`] and the `infer` crate heuristic.

use crate::constants::Format;
use crate::error::CarbonadoError;
use crate::filepack_manifest::{
    FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED, FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
};

/// Public incompressible segment format (Verification + FEC, no compression).
pub const SEGMENT_FORMAT_PUBLIC_RAW: u8 = 0x0C;

/// Public compressible segment format (Zstd + Verification + FEC).
pub const SEGMENT_FORMAT_PUBLIC_COMPRESSED: u8 = 0x0E;

/// Encrypted incompressible segment format (Encryption + Verification + FEC).
pub const SEGMENT_FORMAT_ENCRYPTED_RAW: u8 = 0x0D;

/// Encrypted compressible segment format (Encryption + Zstd + Verification + FEC).
pub const SEGMENT_FORMAT_ENCRYPTED_COMPRESSED: u8 = 0x0F;

/// Policy for selecting per-file segment format levels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SegmentFormatPolicy {
    /// `infer` heuristic: likely incompressible media/archives → c12/c13, else c14/c15.
    #[default]
    Auto,
    /// Force incompressible public c12 / encrypted c13.
    ForceRaw,
    /// Force compressible public c14 / encrypted c15.
    ForceCompressed,
    /// Force public c12 regardless of catalog encryption (encode error if catalog encrypted).
    ForceC12,
    /// Force public c14.
    ForceC14,
    /// Force encrypted c13.
    ForceC13,
    /// Force encrypted c15.
    ForceC15,
    /// Deprecated: use [`SegmentFormatPolicy::ForceC12`].
    #[deprecated(since = "2.1.0", note = "directory segments are c12–c15; use ForceC12")]
    ForceC4,
    /// Deprecated: use [`SegmentFormatPolicy::ForceC14`].
    #[deprecated(since = "2.1.0", note = "directory segments are c12–c15; use ForceC14")]
    ForceC6,
    /// Deprecated: use [`SegmentFormatPolicy::ForceC13`].
    #[deprecated(since = "2.1.0", note = "directory segments are c12–c15; use ForceC13")]
    ForceC5,
    /// Deprecated: use [`SegmentFormatPolicy::ForceC15`].
    #[deprecated(since = "2.1.0", note = "directory segments are c12–c15; use ForceC15")]
    ForceC7,
}

impl SegmentFormatPolicy {
    /// Resolve the segment format for one file's plaintext bytes.
    pub fn resolve_segment_format(
        self,
        catalog_encrypted: bool,
        data: &[u8],
    ) -> Result<u8, CarbonadoError> {
        #[allow(deprecated)]
        let fmt = match self {
            SegmentFormatPolicy::Auto => {
                if catalog_encrypted {
                    if is_likely_incompressible(data) {
                        SEGMENT_FORMAT_ENCRYPTED_RAW
                    } else {
                        SEGMENT_FORMAT_ENCRYPTED_COMPRESSED
                    }
                } else if is_likely_incompressible(data) {
                    SEGMENT_FORMAT_PUBLIC_RAW
                } else {
                    SEGMENT_FORMAT_PUBLIC_COMPRESSED
                }
            }
            SegmentFormatPolicy::ForceRaw => {
                if catalog_encrypted {
                    SEGMENT_FORMAT_ENCRYPTED_RAW
                } else {
                    SEGMENT_FORMAT_PUBLIC_RAW
                }
            }
            SegmentFormatPolicy::ForceCompressed => {
                if catalog_encrypted {
                    SEGMENT_FORMAT_ENCRYPTED_COMPRESSED
                } else {
                    SEGMENT_FORMAT_PUBLIC_COMPRESSED
                }
            }
            SegmentFormatPolicy::ForceC12 | SegmentFormatPolicy::ForceC4 => {
                SEGMENT_FORMAT_PUBLIC_RAW
            }
            SegmentFormatPolicy::ForceC14 | SegmentFormatPolicy::ForceC6 => {
                SEGMENT_FORMAT_PUBLIC_COMPRESSED
            }
            SegmentFormatPolicy::ForceC13 | SegmentFormatPolicy::ForceC5 => {
                SEGMENT_FORMAT_ENCRYPTED_RAW
            }
            SegmentFormatPolicy::ForceC15 | SegmentFormatPolicy::ForceC7 => {
                SEGMENT_FORMAT_ENCRYPTED_COMPRESSED
            }
        };
        validate_segment_format_for_catalog(fmt, catalog_encrypted)?;
        Ok(fmt)
    }
}

/// Whether plaintext is likely incompressible (already compressed media/archives).
pub fn is_likely_incompressible(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    infer::is_archive(data)
        || infer::is_image(data)
        || infer::is_video(data)
        || infer::is_audio(data)
        || infer::is_font(data)
}

/// Validate segment format is one of c12–c15, requires FEC, and matches catalog encryption.
pub fn validate_segment_format_for_catalog(
    segment_format: u8,
    catalog_encrypted: bool,
) -> Result<(), CarbonadoError> {
    if (0x04..=0x07).contains(&segment_format) {
        return Err(CarbonadoError::SegmentFormatMismatch(format!(
            "legacy segment format 0x{segment_format:02x} (c4–c7) rejected; directory segments require c12–c15 with FEC"
        )));
    }
    let valid = matches!(
        segment_format,
        SEGMENT_FORMAT_PUBLIC_RAW
            | SEGMENT_FORMAT_PUBLIC_COMPRESSED
            | SEGMENT_FORMAT_ENCRYPTED_RAW
            | SEGMENT_FORMAT_ENCRYPTED_COMPRESSED
    );
    if !valid {
        return Err(CarbonadoError::SegmentFormatMismatch(format!(
            "unsupported segment format 0x{segment_format:02x}"
        )));
    }
    let fmt = Format::from(segment_format);
    if !fmt.contains(Format::Verification) {
        return Err(CarbonadoError::SegmentFormatMismatch(format!(
            "segment format 0x{segment_format:02x} must include Verification"
        )));
    }
    if !fmt.contains(Format::Fec) {
        return Err(CarbonadoError::SegmentFormatMismatch(format!(
            "segment format 0x{segment_format:02x} must include FEC"
        )));
    }
    let seg_encrypted = segment_format & 1 != 0;
    if seg_encrypted != catalog_encrypted {
        return Err(CarbonadoError::SegmentFormatMismatch(format!(
            "segment format 0x{segment_format:02x} does not match catalog encryption={catalog_encrypted}"
        )));
    }
    Ok(())
}

/// Resolve catalog format (c14 public or c15 encrypted) from the encrypted flag.
pub fn resolve_catalog_format(encrypted: bool) -> u8 {
    if encrypted {
        FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED
    } else {
        FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_selects_c14_for_text() {
        let fmt = SegmentFormatPolicy::Auto
            .resolve_segment_format(false, b"hello world source code\n")
            .expect("c14");
        assert_eq!(fmt, SEGMENT_FORMAT_PUBLIC_COMPRESSED);
    }

    #[test]
    fn auto_selects_c12_for_jpeg_magic() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let fmt = SegmentFormatPolicy::Auto
            .resolve_segment_format(false, &jpeg)
            .expect("c12");
        assert_eq!(fmt, SEGMENT_FORMAT_PUBLIC_RAW);
    }

    #[test]
    fn force_c13_rejects_public_catalog() {
        let err = SegmentFormatPolicy::ForceC13
            .resolve_segment_format(false, b"x")
            .unwrap_err();
        assert!(matches!(err, CarbonadoError::SegmentFormatMismatch(_)));
    }

    #[test]
    fn rejects_legacy_c4_segment_format() {
        let err = validate_segment_format_for_catalog(0x04, false).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::SegmentFormatMismatch(ref m) if m.contains("c4–c7")),
            "got {err:?}"
        );
    }

    #[test]
    fn resolve_catalog_format_levels() {
        assert_eq!(resolve_catalog_format(false), 0x0E);
        assert_eq!(resolve_catalog_format(true), 0x0F);
    }
}
