//! Adamantine 1.0 payload body: rkyv manifest + centralized segment Bao outboard bundle.
//!
//! Wire layout after the 19-byte Adamantine header:
//!
//! ```text
//! [u32 LE rkyv_len]
//! [rkyv FilepackManifestWire bytes]
//! [u32 LE bundle_len]
//! [concatenated segment bao_outboard blobs]
//! ```
//!
//! Catalog OpenTimestamps proofs (when present) are appended after the inboard
//! Carbonado catalog bytes on disk — see [`crate::file::append_catalog_ots_trailer`] /
//! [`crate::file::split_catalog_file_ots_trailer`].
//!
//! An optional leading `u8` bundle version byte may be added in a future streaming revision;
//! v1 omits it (bundle starts immediately after `bundle_len`).
//!
//! Segment [`SegmentRef::bao_outboard_offset`](crate::filepack_manifest::SegmentRef) /
//! [`bao_outboard_len`](crate::filepack_manifest::SegmentRef) index into the bundle region.

use crate::error::CarbonadoError;
use crate::filepack_manifest::MAX_RKYV_PAYLOAD_LEN;

/// Maximum bytes for the concatenated Bao outboard bundle (DoS guard).
pub const MAX_BAO_BUNDLE_LEN: usize = 256 * 1024 * 1024;

/// Maximum total Adamantine payload (rkyv + bundle length prefix + bundle bytes).
pub const MAX_ADAMANTINE_PAYLOAD_LEN: usize = MAX_RKYV_PAYLOAD_LEN
    .saturating_add(4)
    .saturating_add(MAX_BAO_BUNDLE_LEN);

/// Split payload into rkyv manifest bytes and the Bao bundle.
pub fn split_adamantine_payload(payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CarbonadoError> {
    if payload.len() > MAX_ADAMANTINE_PAYLOAD_LEN {
        return Err(CarbonadoError::InvalidAdamantinePayloadTooLarge {
            declared: payload.len() as u32,
            max: MAX_ADAMANTINE_PAYLOAD_LEN,
        });
    }
    if payload.len() < 8 {
        return Err(CarbonadoError::InvalidAdamantinePayloadLength {
            expected: 8,
            available: payload.len(),
        });
    }
    let rkyv_len = u32::from_le_bytes(
        payload[0..4]
            .try_into()
            .map_err(|_| CarbonadoError::InvalidAdamantineHeader)?,
    ) as usize;
    if rkyv_len > MAX_RKYV_PAYLOAD_LEN {
        return Err(CarbonadoError::InvalidAdamantinePayloadTooLarge {
            declared: rkyv_len as u32,
            max: MAX_RKYV_PAYLOAD_LEN,
        });
    }
    let bundle_len_offset = 4usize
        .checked_add(rkyv_len)
        .ok_or(CarbonadoError::InvalidAdamantineHeader)?;
    if payload.len() < bundle_len_offset + 4 {
        return Err(CarbonadoError::InvalidAdamantinePayloadLength {
            expected: (bundle_len_offset + 4) as u32,
            available: payload.len(),
        });
    }
    let bundle_len = u32::from_le_bytes(
        payload[bundle_len_offset..bundle_len_offset + 4]
            .try_into()
            .map_err(|_| CarbonadoError::InvalidAdamantineHeader)?,
    ) as usize;
    if bundle_len > MAX_BAO_BUNDLE_LEN {
        return Err(CarbonadoError::InvalidAdamantinePayloadTooLarge {
            declared: bundle_len as u32,
            max: MAX_BAO_BUNDLE_LEN,
        });
    }
    let rkyv = payload[4..bundle_len_offset].to_vec();
    let bundle_start = bundle_len_offset + 4;
    let bundle_end = bundle_start
        .checked_add(bundle_len)
        .ok_or(CarbonadoError::InvalidAdamantineHeader)?;
    if bundle_end > payload.len() {
        return Err(CarbonadoError::InvalidAdamantinePayloadLength {
            expected: bundle_end as u32,
            available: payload.len(),
        });
    }
    let bundle = payload[bundle_start..bundle_end].to_vec();

    if payload.len() != bundle_end {
        return Err(CarbonadoError::InvalidAdamantinePayloadLength {
            expected: bundle_end as u32,
            available: payload.len(),
        });
    }
    Ok((rkyv, bundle))
}

/// Build payload from rkyv manifest bytes and concatenated Bao outboard blobs.
pub fn build_adamantine_payload(rkyv: &[u8], bao_bundle: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    if rkyv.len() > MAX_RKYV_PAYLOAD_LEN {
        return Err(CarbonadoError::InvalidAdamantinePayloadTooLarge {
            declared: rkyv.len() as u32,
            max: MAX_RKYV_PAYLOAD_LEN,
        });
    }
    if bao_bundle.len() > MAX_BAO_BUNDLE_LEN {
        return Err(CarbonadoError::InvalidAdamantinePayloadTooLarge {
            declared: bao_bundle.len() as u32,
            max: MAX_BAO_BUNDLE_LEN,
        });
    }
    let total = 4usize
        .checked_add(rkyv.len())
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(bao_bundle.len()))
        .ok_or(CarbonadoError::InvalidAdamantineHeader)?;
    if total > MAX_ADAMANTINE_PAYLOAD_LEN {
        return Err(CarbonadoError::InvalidAdamantinePayloadTooLarge {
            declared: total as u32,
            max: MAX_ADAMANTINE_PAYLOAD_LEN,
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(rkyv.len() as u32).to_le_bytes());
    out.extend_from_slice(rkyv);
    out.extend_from_slice(&(bao_bundle.len() as u32).to_le_bytes());
    out.extend_from_slice(bao_bundle);
    Ok(out)
}

/// Extract one segment's Bao outboard slice from the bundle using manifest offsets.
pub fn bao_slice_from_bundle(
    bundle: &[u8],
    offset: u32,
    len: u32,
) -> Result<&[u8], CarbonadoError> {
    let off = offset as usize;
    let ln = len as usize;
    let end = off
        .checked_add(ln)
        .ok_or(CarbonadoError::InvalidFilepackManifest(
            "bao_outboard offset overflow".into(),
        ))?;
    if end > bundle.len() {
        return Err(CarbonadoError::InvalidFilepackManifest(format!(
            "bao_outboard range {off}..{end} exceeds bundle length {}",
            bundle.len()
        )));
    }
    Ok(&bundle[off..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_split_roundtrip_empty_bundle() {
        let rkyv = b"manifest-bytes".to_vec();
        let payload = build_adamantine_payload(&rkyv, &[]).expect("build");
        let (got_rkyv, got_bundle) = split_adamantine_payload(&payload).expect("split");
        assert_eq!(got_rkyv, rkyv);
        assert!(got_bundle.is_empty());
    }

    #[test]
    fn build_split_roundtrip_with_bundle() {
        let rkyv = b"manifest".to_vec();
        let bundle = b"bao-outboard-data".to_vec();
        let payload = build_adamantine_payload(&rkyv, &bundle).expect("build");
        let (got_rkyv, got_bundle) = split_adamantine_payload(&payload).expect("split");
        assert_eq!(got_rkyv, rkyv);
        assert_eq!(got_bundle, bundle);
    }

    #[test]
    fn reject_bundle_len_longer_than_payload() {
        let mut payload = 3u32.to_le_bytes().to_vec();
        payload.extend_from_slice(b"abc");
        payload.extend_from_slice(&100u32.to_le_bytes());
        let err = split_adamantine_payload(&payload).unwrap_err();
        assert!(matches!(
            err,
            CarbonadoError::InvalidAdamantinePayloadLength { .. }
        ));
    }

    #[test]
    fn bao_slice_bounds_check() {
        let bundle = b"0123456789";
        let slice = bao_slice_from_bundle(bundle, 2, 3).expect("slice");
        assert_eq!(slice, b"234");
        let err = bao_slice_from_bundle(bundle, 8, 4).unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidFilepackManifest(_)));
    }
}
