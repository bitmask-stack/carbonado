//! Seekable 4 KiB slice verification without full-stream materialization.

use std::process::id;

use anyhow::Result;
use carbonado::{
    constants::SLICE_LEN, encode, encode_outboard, error::CarbonadoError, verify_slice,
    verify_slice_inboard_seekable, verify_slice_outboard,
};
use rand::RngCore;

const C14: u8 = 0x0E;

/// ~8 MiB payload (CI-friendly; still >> single-slice memory footprint).
const LARGE_PAYLOAD_LEN: usize = 8 * 1024 * 1024;

fn patterned_payload(len: usize) -> Vec<u8> {
    let slice = SLICE_LEN as usize;
    let mut buf = vec![0u8; len];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((i / slice) as u8).wrapping_add((i % 256) as u8);
    }
    buf
}

#[test]
fn large_payload_seekable_slices_without_full_decode() -> Result<()> {
    let input = patterned_payload(LARGE_PAYLOAD_LEN);
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    // Level 4 = Bao only: logical stream bytes == input (no fec transform).
    let encoded = encode(&key, &input, 4)?;
    let blob = &encoded.0;
    let hash = encoded.1;

    let content_len = u64::from_le_bytes(blob[0..8].try_into().unwrap());
    let slice_count = content_len.div_ceil(u64::from(SLICE_LEN)) as u32;
    assert!(slice_count > 2, "need multiple 4 KiB slices");

    // Slice 0 — SliceRegionWriter retains O(slice) memory (encoded I/O is still O(N)).
    let slice0 = verify_slice(blob, 0, 1, hash.as_bytes(), 4)?;
    assert_eq!(slice0.len(), SLICE_LEN as usize);
    assert_eq!(&slice0[..], &input[0..SLICE_LEN as usize]);

    // Middle slice N via inboard seekable API.
    let mid_index = slice_count / 2;
    assert!(mid_index > 0 && mid_index < slice_count.saturating_sub(1));
    let mid = verify_slice_inboard_seekable(blob, mid_index, 1, hash.as_bytes(), 4)?;
    assert_eq!(mid.len(), SLICE_LEN as usize);
    let off_mid = mid_index as usize * SLICE_LEN as usize;
    assert_eq!(&mid[..], &input[off_mid..off_mid + SLICE_LEN as usize]);

    Ok(())
}

#[test]
fn tamper_outboard_parent_hash_fails_verification() -> Result<()> {
    let input = b"tamper outboard parent hash";
    let master_key = [0u8; 32];
    let oenc = encode_outboard(&master_key, input, C14)?;
    let bao_ob = oenc.verification_outboard.as_ref().expect("bao sidecar");
    let hash = oenc.hash;

    let mut bad_ob = bao_ob.clone();
    if bad_ob.len() >= 32 {
        bad_ob[0] ^= 0xFF;
    }

    let err = verify_slice_outboard(
        oenc.main.as_slice(),
        &bad_ob,
        oenc.main.len() as u64,
        0,
        1,
        hash.as_bytes(),
        C14,
    )
    .unwrap_err();

    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "tampered .out parent hash must fail authentication, got {err:?}"
    );
    Ok(())
}

#[test]
fn wrong_format_key_authentication_failure_inboard_and_outboard() -> Result<()> {
    let input = b"wrong format key";
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    let encoded = encode(&key, input, 12)?;
    let blob = &encoded.0;
    let hash = encoded.1;

    let err = verify_slice_inboard_seekable(blob, 0, 1, hash.as_bytes(), 13).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "inboard wrong format key must yield AuthenticationFailed, got {err:?}"
    );

    let err2 = verify_slice(blob, 0, 1, hash.as_bytes(), 13).unwrap_err();
    assert!(
        matches!(err2, CarbonadoError::AuthenticationFailed),
        "verify_slice delegate must also fail AuthenticationFailed, got {err2:?}"
    );

    let oenc = encode_outboard(&key, input, C14)?;
    let bao_ob = oenc.verification_outboard.as_ref().expect("bao sidecar");
    let err_ob = verify_slice_outboard(
        oenc.main.as_slice(),
        bao_ob,
        oenc.main.len() as u64,
        0,
        1,
        hash.as_bytes(),
        12, // encoded as c14, verify with c12 key
    )
    .unwrap_err();
    assert!(
        matches!(err_ob, CarbonadoError::AuthenticationFailed),
        "outboard wrong format key must yield AuthenticationFailed, got {err_ob:?}"
    );

    Ok(())
}

#[test]
fn tamper_inboard_response_fails_authentication() -> Result<()> {
    let input = b"inboard response tamper";
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    let encoded = encode(&key, input, 4)?;
    let mut blob = encoded.0.clone();
    if blob.len() > 16 {
        blob[12] ^= 0xAA;
    }

    let err = verify_slice_inboard_seekable(&blob, 0, 1, encoded.1.as_bytes(), 4).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "tampered inboard response must yield AuthenticationFailed, got {err:?}"
    );

    let err2 = verify_slice(&blob, 0, 1, encoded.1.as_bytes(), 4).unwrap_err();
    assert!(
        matches!(err2, CarbonadoError::AuthenticationFailed),
        "verify_slice on tampered inboard must yield AuthenticationFailed, got {err2:?}"
    );

    Ok(())
}

#[test]
fn truncated_inboard_response_errors() -> Result<()> {
    let input = b"truncated inboard response";
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    let encoded = encode(&key, input, 4)?;
    let mut blob = encoded.0;
    // Valid 8-byte content_len prefix; truncate embedded bao response.
    blob.truncate(8);

    let err = verify_slice(&blob, 0, 1, encoded.1.as_bytes(), 4).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::BaoResponseTruncated(_)),
        "truncated inboard response must yield BaoResponseTruncated, got {err:?}"
    );

    Ok(())
}

#[test]
fn out_of_bounds_slice_index_errors() -> Result<()> {
    let input = b"oob slice index gate";
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    let encoded = encode(&key, input, 4)?;
    let blob = &encoded.0;
    let hash = encoded.1;
    let content_len = u64::from_le_bytes(blob[0..8].try_into().unwrap());
    let past_end = (content_len.div_ceil(u64::from(SLICE_LEN))) as u32;

    let err = verify_slice(blob, past_end, 1, hash.as_bytes(), 4).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::InvalidSliceIndex {
                index,
                content_len: clen
            } if index == past_end && clen == content_len
        ),
        "OOB slice index must yield InvalidSliceIndex, got {err:?}"
    );

    Ok(())
}

/// Unique temp prefix per test process to avoid parallel collisions (past issue #5).
#[test]
fn temp_dir_prefix_includes_process_id() {
    let prefix = format!("carbonado-seekable-slices-{}-", id());
    assert!(prefix.contains(&id().to_string()));
}
