//! OpenTimestamps integration for Bao-root binding (stub for offline/test use).
//!
//! Production deployments may replace the stub stamper with network-backed OpenTimestamps
//! attestations. The wire format is a deterministic DER-like envelope that embeds the
//! stamped 32-byte Bao root for offline verification in tests and CI.

use crate::error::CarbonadoError;
use crate::filepack_manifest::MAX_OTS_PROOF_LEN;

/// Policy controlling which artifacts receive OpenTimestamps proofs on encode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OtsPolicy {
    /// Stamp each file entry's primary segment Bao root into `FilepackEntry.ots_proof`.
    pub stamp_entries: bool,
    /// Write a catalog `.ots` sidecar next to `.adam.c14`/`.adam.c15`.
    pub stamp_catalog: bool,
}

/// Result of verifying an OpenTimestamps proof against an expected Bao root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtsVerification {
    /// Whether the proof attests the expected root.
    pub valid: bool,
}

/// Magic prefix for stub OTS proofs (not a real OpenTimestamps calendar attestation).
const STUB_MAGIC: &[u8; 8] = b"CBOTSv1\0";

/// Produce a testable OTS proof binding `root` (stub: no network calendar).
///
/// Limitation: does not submit to public OpenTimestamps calendars; produces a
/// deterministic offline envelope for roundtrip and MAX_OTS_PROOF_LEN compliance tests.
pub fn stamp_bao_root(root: &[u8; 32]) -> Result<Vec<u8>, CarbonadoError> {
    let proof = build_stub_proof(root);
    if proof.len() > MAX_OTS_PROOF_LEN {
        return Err(CarbonadoError::InvalidOtsProof(format!(
            "ots_proof exceeds {MAX_OTS_PROOF_LEN} bytes"
        )));
    }
    Ok(proof)
}

/// Verify a stub (or fixture) proof against the expected Bao root.
pub fn verify_stamp(proof: &[u8], root: &[u8; 32]) -> Result<OtsVerification, CarbonadoError> {
    if proof.len() > MAX_OTS_PROOF_LEN {
        return Err(CarbonadoError::InvalidOtsProof(format!(
            "ots_proof exceeds {MAX_OTS_PROOF_LEN} bytes"
        )));
    }
    let valid = parse_stub_proof(proof).is_some_and(|stamped| stamped == *root);
    Ok(OtsVerification { valid })
}

fn build_stub_proof(root: &[u8; 32]) -> Vec<u8> {
    // DER-like SEQUENCE { OCTET STRING magic, OCTET STRING root }
    let mut out = Vec::with_capacity(2 + STUB_MAGIC.len() + 2 + root.len());
    out.push(0x30); // SEQUENCE
    out.push((STUB_MAGIC.len() + 2 + root.len()) as u8);
    out.push(0x04); // OCTET STRING
    out.push(STUB_MAGIC.len() as u8);
    out.extend_from_slice(STUB_MAGIC);
    out.push(0x04);
    out.push(root.len() as u8);
    out.extend_from_slice(root);
    out
}

fn parse_stub_proof(proof: &[u8]) -> Option<[u8; 32]> {
    if proof.len() < 2 + STUB_MAGIC.len() + 2 + 32 {
        return None;
    }
    if proof[0] != 0x30 || proof[2] != 0x04 {
        return None;
    }
    let magic_len = proof[3] as usize;
    let magic_start: usize = 4;
    let magic_end = magic_start.checked_add(magic_len)?;
    if proof.get(magic_start..magic_end)? != STUB_MAGIC {
        return None;
    }
    if proof.get(magic_end)? != &0x04 {
        return None;
    }
    let root_len = *proof.get(magic_end + 1)? as usize;
    if root_len != 32 {
        return None;
    }
    let root_start = magic_end + 2;
    let root_bytes = proof.get(root_start..root_start + 32)?;
    let mut root = [0u8; 32];
    root.copy_from_slice(root_bytes);
    Some(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_stamp_verify_roundtrip() {
        let root = [0xABu8; 32];
        let proof = stamp_bao_root(&root).expect("stamp");
        let v = verify_stamp(&proof, &root).expect("verify");
        assert!(v.valid);
    }

    #[test]
    fn stub_verify_rejects_wrong_root() {
        let root = [1u8; 32];
        let proof = stamp_bao_root(&root).expect("stamp");
        let other = [2u8; 32];
        let v = verify_stamp(&proof, &other).expect("verify");
        assert!(!v.valid);
    }

    #[test]
    fn stub_verify_rejects_garbage() {
        let root = [0u8; 32];
        let v = verify_stamp(b"not-a-proof", &root).expect("verify");
        assert!(!v.valid);
    }

    #[test]
    fn stub_verify_rejects_oversized_proof() {
        let root = [0u8; 32];
        let oversized = vec![0u8; MAX_OTS_PROOF_LEN + 1];
        let err = verify_stamp(&oversized, &root).unwrap_err();
        assert!(matches!(err, CarbonadoError::InvalidOtsProof(_)));
    }
}
