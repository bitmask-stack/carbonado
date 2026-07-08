//! Per-segment Carbonado format selection for directory archives.
//!
//! Directory catalogs are always inboard c14 (public) or c15 (encrypted). Individual file
//! segments use heterogeneous c4/c6 (public) or c5/c7 (encrypted) chosen by
//! [`SegmentFormatPolicy`] and the `infer` crate heuristic.

use crate::error::CarbonadoError;
use crate::filepack_manifest::{
    FILEPACK_MANIFEST_FORMAT_LEVEL_ENCRYPTED, FILEPACK_MANIFEST_FORMAT_LEVEL_PUBLIC,
};

/// Public incompressible segment format (Bao verifiable, no compression).
pub const SEGMENT_FORMAT_PUBLIC_RAW: u8 = 0x04;

/// Public compressible segment format (Zstd + Bao).
pub const SEGMENT_FORMAT_PUBLIC_COMPRESSED: u8 = 0x06;

/// Encrypted incompressible segment format.
pub const SEGMENT_FORMAT_ENCRYPTED_RAW: u8 = 0x05;

/// Encrypted compressible segment format.
pub const SEGMENT_FORMAT_ENCRYPTED_COMPRESSED: u8 = 0x07;

/// Policy for selecting per-file segment format levels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SegmentFormatPolicy {
    /// `infer` heuristic: likely incompressible media/archives → c4/c5, else c6/c7.
    #[default]
    Auto,
    /// Force incompressible public c4 / encrypted c5.
    ForceRaw,
    /// Force compressible public c6 / encrypted c7.
    ForceCompressed,
    /// Force public c4 regardless of catalog encryption (encode error if catalog encrypted).
    ForceC4,
    /// Force public c6.
    ForceC6,
    /// Force encrypted c5.
    ForceC5,
    /// Force encrypted c7.
    ForceC7,
}

impl SegmentFormatPolicy {
    /// Resolve the segment format for one file's plaintext bytes.
    pub fn resolve_segment_format(
        self,
        catalog_encrypted: bool,
        data: &[u8],
    ) -> Result<u8, CarbonadoError> {
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
            SegmentFormatPolicy::ForceC4 => SEGMENT_FORMAT_PUBLIC_RAW,
            SegmentFormatPolicy::ForceC6 => SEGMENT_FORMAT_PUBLIC_COMPRESSED,
            SegmentFormatPolicy::ForceC5 => SEGMENT_FORMAT_ENCRYPTED_RAW,
            SegmentFormatPolicy::ForceC7 => SEGMENT_FORMAT_ENCRYPTED_COMPRESSED,
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

/// Validate segment format is one of c4/c5/c6/c7 and matches catalog encryption.
pub fn validate_segment_format_for_catalog(
    segment_format: u8,
    catalog_encrypted: bool,
) -> Result<(), CarbonadoError> {
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
    fn auto_selects_c6_for_text() {
        let fmt = SegmentFormatPolicy::Auto
            .resolve_segment_format(false, b"hello world source code\n")
            .expect("c6");
        assert_eq!(fmt, SEGMENT_FORMAT_PUBLIC_COMPRESSED);
    }

    #[test]
    fn auto_selects_c4_for_jpeg_magic() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let fmt = SegmentFormatPolicy::Auto
            .resolve_segment_format(false, &jpeg)
            .expect("c4");
        assert_eq!(fmt, SEGMENT_FORMAT_PUBLIC_RAW);
    }

    #[test]
    fn force_c5_rejects_public_catalog() {
        let err = SegmentFormatPolicy::ForceC5
            .resolve_segment_format(false, b"x")
            .unwrap_err();
        assert!(matches!(err, CarbonadoError::SegmentFormatMismatch(_)));
    }

    #[test]
    fn resolve_catalog_format_levels() {
        assert_eq!(resolve_catalog_format(false), 0x0E);
        assert_eq!(resolve_catalog_format(true), 0x0F);
    }
}
