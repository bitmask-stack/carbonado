//! Phase 1B: header authentication hardening — tamper matrix, chunk_index, guards, mismatch.

mod common;

use carbonado::{
    constants::Format,
    encode,
    error::CarbonadoError,
    file::{self, Header},
    structs::Encoded,
};
use common::header_layout::{self, offsets};
use rand::RngCore;

fn random_master() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

fn valid_headered_archive(level: u8) -> ([u8; 32], Vec<u8>) {
    let key = random_master();
    let input = b"header tamper matrix payload";
    let (encoded, _) = file::encode(&key, input, level, None).expect("encode");
    (key, encoded)
}

const INBOARD_TAMPER_CASES: &[(&str, usize)] = &[
    ("header_mac", offsets::HEADER_MAC),
    ("hash", offsets::HASH),
    ("format", offsets::FORMAT),
    ("payload_nonce", offsets::PAYLOAD_NONCE),
    ("encoded_len", offsets::ENCODED_LEN),
    ("padding_len", offsets::PADDING_LEN),
    ("slh_public_key", offsets::SLH_PUBLIC_KEY),
    ("chunk_index", offsets::CHUNK_INDEX),
    ("metadata", offsets::METADATA),
];

#[test]
fn test_header_tamper_matrix() {
    let (key, encoded) = valid_headered_archive(14);

    // MAGIC is in header_mac auth_data but fails structural parse before MAC verify.
    let mut magic_tampered = encoded.clone();
    header_layout::flip_byte(&mut magic_tampered, offsets::MAGIC);
    let err_magic = file::decode(&key, &magic_tampered).unwrap_err();
    assert!(
        matches!(err_magic, CarbonadoError::InvalidMagicNumber(_)),
        "tampered magic must yield InvalidMagicNumber (pre-MAC structural), got {err_magic:?}"
    );

    for (field, offset) in INBOARD_TAMPER_CASES {
        let mut tampered = encoded.clone();
        header_layout::flip_byte(&mut tampered, *offset);
        let err = file::decode(&key, &tampered).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::AuthenticationFailed),
            "tampered {field} must yield AuthenticationFailed, got {err:?}"
        );
    }

    // Non-zero metadata path: tamper must still fail MAC verify.
    let (encoded_meta, _) =
        file::encode(&key, b"metadata tamper matrix", 14, Some(*b"metameta")).unwrap();
    let mut meta_tampered = encoded_meta.clone();
    header_layout::flip_byte(&mut meta_tampered, offsets::METADATA);
    let err_meta = file::decode(&key, &meta_tampered).unwrap_err();
    assert!(
        matches!(err_meta, CarbonadoError::AuthenticationFailed),
        "tampered Some(metadata) must yield AuthenticationFailed, got {err_meta:?}"
    );

    // Wrong master key on otherwise valid archive.
    let wrong_key = random_master();
    let err_key = file::decode(&wrong_key, &encoded).unwrap_err();
    assert!(
        matches!(err_key, CarbonadoError::AuthenticationFailed),
        "wrong master key must yield AuthenticationFailed, got {err_key:?}"
    );

    // Roundtrip via try_to_vec path: build header, serialize, tamper, decode.
    let Encoded(body, hash, info) = encode(&key, b"try_to_vec tamper path", 14).unwrap();
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let hdr = Header::new(
        &key,
        nonce,
        hash.as_bytes(),
        [0u8; 32],
        Format::from(14),
        0,
        info.bytes_verifiable,
        info.padding_len,
        None,
    )
    .unwrap();
    let mut hdr_bytes = hdr.try_to_vec().unwrap();
    header_layout::flip_byte(&mut hdr_bytes, offsets::HASH);
    let mut combined = hdr_bytes;
    combined.extend_from_slice(&body);
    let err = file::decode(&key, &combined).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "try_to_vec tampered hash must fail auth, got {err:?}"
    );
}

#[test]
fn test_decode_outboard_header_tamper_matrix() {
    let key = random_master();
    let input = b"decode_outboard header tamper matrix";
    let (hdr_opt, oenc) = file::encode_outboard(&key, input, 14, Some(*b"metameta")).unwrap();
    let hdr = hdr_opt.unwrap();
    let hdr_bytes = hdr.try_to_vec().unwrap();

    let decode_with_hdr = |hbytes: &[u8]| {
        file::decode_outboard(
            &key,
            hdr.hash.as_bytes(),
            Some(hbytes),
            &oenc.main,
            oenc.verification_outboard.as_deref(),
            oenc.fec_parity.as_deref(),
            oenc.info.padding_len,
            14,
        )
    };

    let mut magic_tampered = hdr_bytes.clone();
    header_layout::flip_byte(&mut magic_tampered, offsets::MAGIC);
    let err_magic = decode_with_hdr(&magic_tampered).unwrap_err();
    assert!(
        matches!(err_magic, CarbonadoError::InvalidMagicNumber(_)),
        "outboard tampered magic must yield InvalidMagicNumber, got {err_magic:?}"
    );

    for (field, offset) in INBOARD_TAMPER_CASES {
        let mut tampered = hdr_bytes.clone();
        header_layout::flip_byte(&mut tampered, *offset);
        let err = decode_with_hdr(&tampered).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::AuthenticationFailed),
            "decode_outboard tampered {field} must yield AuthenticationFailed, got {err:?}"
        );
    }

    let wrong_key = random_master();
    let err_key = file::decode_outboard(
        &wrong_key,
        hdr.hash.as_bytes(),
        Some(&hdr_bytes),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        14,
    )
    .unwrap_err();
    assert!(
        matches!(err_key, CarbonadoError::AuthenticationFailed),
        "decode_outboard wrong master key must yield AuthenticationFailed, got {err_key:?}"
    );
}

#[test]
fn test_chunk_index_nonzero_roundtrip_and_tamper() {
    let key = random_master();
    let input = b"chunk index binding test";
    let Encoded(body, hash, info) = encode(&key, input, 14).unwrap();

    for chunk_index in [1u32, 42u32] {
        let hdr = Header::new(
            &key,
            [0u8; 16],
            hash.as_bytes(),
            [0u8; 32],
            Format::from(14),
            chunk_index,
            info.bytes_verifiable,
            info.padding_len,
            None,
        )
        .unwrap();
        assert_eq!(hdr.chunk_index, chunk_index);

        let mut archive = hdr.try_to_vec().unwrap();
        archive.extend_from_slice(&body);
        let (decoded_hdr, recovered) = file::decode(&key, &archive).unwrap();
        assert_eq!(decoded_hdr.chunk_index, chunk_index);
        assert_eq!(recovered, input);
    }

    // Tampering chunk_index in a valid archive must fail header_mac verify.
    let hdr = Header::new(
        &key,
        [0u8; 16],
        hash.as_bytes(),
        [0u8; 32],
        Format::from(14),
        1,
        info.bytes_verifiable,
        info.padding_len,
        None,
    )
    .unwrap();
    let mut archive = hdr.try_to_vec().unwrap();
    archive.extend_from_slice(&body);
    header_layout::flip_byte(&mut archive, offsets::CHUNK_INDEX);
    let err = file::decode(&key, &archive).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "tampered chunk_index must fail auth, got {err:?}"
    );
}

/// Short-header guard for `file::decode_outboard` (header path).
/// Consolidated short-input cases also live in `tests/adversarial_proptest.rs`.
#[test]
fn decode_outboard_short_header_returns_invalid_header_length_not_panic() {
    let key = random_master();
    let (hdr_opt, oenc) = file::encode_outboard(&key, b"short header guard", 14, None).unwrap();
    let hdr = hdr_opt.unwrap();
    let short = [0u8; 10];

    let err = file::decode_outboard(
        &key,
        hdr.hash.as_bytes(),
        Some(&short),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        14,
    )
    .unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidHeaderLength),
        "short header to decode_outboard must give InvalidHeaderLength, got {err:?}"
    );

    let almost = vec![0u8; Header::LEN - 1];
    let err2 = file::decode_outboard(
        &key,
        hdr.hash.as_bytes(),
        Some(&almost),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        14,
    )
    .unwrap_err();
    assert!(
        matches!(err2, CarbonadoError::InvalidHeaderLength),
        "almost-header to decode_outboard must give InvalidHeaderLength"
    );
}

/// Caller-supplied hash/format/padding must match authenticated header after MAC verify.
#[test]
fn decode_outboard_caller_header_mismatch_after_valid_mac() {
    let key = random_master();
    let input = b"caller vs header mismatch";
    let (hdr_opt, oenc) = file::encode_outboard(&key, input, 14, None).unwrap();
    let hdr = hdr_opt.unwrap();
    let hbytes = hdr.try_to_vec().unwrap();

    // Wrong hash param (header MAC still valid) -> AuthenticationFailed.
    let wrong_hash = [0xABu8; 32];
    let err_hash = file::decode_outboard(
        &key,
        &wrong_hash,
        Some(&hbytes),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        14,
    )
    .unwrap_err();
    assert!(
        matches!(err_hash, CarbonadoError::AuthenticationFailed),
        "wrong hash after valid mac must be AuthenticationFailed, got {err_hash:?}"
    );

    // Wrong format param -> InvalidHeaderLength.
    let err_fmt = file::decode_outboard(
        &key,
        hdr.hash.as_bytes(),
        Some(&hbytes),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        12, // header says 14
    )
    .unwrap_err();
    assert!(
        matches!(err_fmt, CarbonadoError::InvalidHeaderLength),
        "wrong format after valid mac must be InvalidHeaderLength, got {err_fmt:?}"
    );

    // Wrong padding param -> InvalidHeaderLength.
    let bad_pad = oenc.info.padding_len.wrapping_add(1);
    let err_pad = file::decode_outboard(
        &key,
        hdr.hash.as_bytes(),
        Some(&hbytes),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        bad_pad,
        14,
    )
    .unwrap_err();
    assert!(
        matches!(err_pad, CarbonadoError::InvalidHeaderLength),
        "wrong padding after valid mac must be InvalidHeaderLength, got {err_pad:?}"
    );

    // Correct params still roundtrip.
    let rec = file::decode_outboard(
        &key,
        hdr.hash.as_bytes(),
        Some(&hbytes),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        14,
    )
    .unwrap();
    assert_eq!(rec, input);
}
