//! Phase 2 allowlist for `backend-lean` (docs/TEST_CONTRACT.md).
//!
//! Covers outboard roundtrip, scrub happy/error paths, verify_slice, stream buffer
//! composition, and G9 cross-backend body/headered buffers (Rust encode → Lean decode
//! requires both engines available — under pure `backend-lean` we check Lean self
//! parity and document G9 via lean-encode / lean-decode identity against fixed vectors).
//!
//! ```bash
//! nix build .#libcarbonado -o result-libcarbonado
//! export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib
//! export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include
//! export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB
//! cargo test --no-default-features --features "backend-lean,pqc,ots" --test lean_backend_phase2
//! # or: just test-lean-phase2
//! ```
//! Only compiled under `backend-lean` (avoids breaking default/`backend-rust` clippy of all targets).

#![cfg(feature = "backend-lean")]

use carbonado::{
    decode, decode_outboard, encode, encode_outboard, error::CarbonadoError, extract_slice, file,
    scrub, scrub_outboard, stream_decode_buffer, stream_encode_buffer, structs::Encoded,
    verify_slice, OutboardEncoded,
};

const MASTER: [u8; 32] = [
    0x0c, 0xa1, 0xb0, 0xda, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
];

const NONCE: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

fn require_lean_lib() {
    if std::env::var_os("CARBONADO_LEAN_LIB").is_none() {
        panic!(
            "CARBONADO_LEAN_LIB unset. Build and export first:\n  \
             nix build .#libcarbonado -o result-libcarbonado\n  \
             export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib\n  \
             export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include\n  \
             export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB\n  \
             # or: just test-lean-phase2"
        );
    }
}

#[test]
fn abi_version_is_one() {
    require_lean_lib();
    assert_eq!(carbonado::backend::lean::abi_version(), 1);
}

#[test]
fn outboard_roundtrip_public_c4_c12_c14() {
    require_lean_lib();
    let plaintext = b"phase2 outboard public smoke";
    for format in [4u8, 12, 14] {
        let oenc = encode_outboard(&MASTER, plaintext, format)
            .unwrap_or_else(|e| panic!("encode_outboard c{format}: {e}"));
        assert_eq!(oenc.info.input_len, plaintext.len() as u32);
        if format & 0x4 != 0 {
            assert!(
                oenc.verification_outboard.is_some(),
                "c{format}: Verification formats always yield Some(outboard) (may be empty single-leaf)"
            );
        }
        if format & 0x8 != 0 {
            assert!(
                oenc.fec_parity.is_some(),
                "c{format}: Fec formats always yield Some(parity)"
            );
            assert_eq!(
                oenc.info.bytes_ecc,
                oenc.fec_parity
                    .as_ref()
                    .map(|p| p.len() as u32)
                    .unwrap_or(0),
                "c{format}: bytes_ecc must equal parity sidecar length"
            );
            // plaintext is non-empty smoke payload → FEC parity sidecar must be non-empty.
            assert!(
                oenc.fec_parity.as_ref().is_some_and(|p| !p.is_empty()),
                "c{format}: expected non-empty FEC parity for non-empty plaintext"
            );
        }
        let decoded = decode_outboard(
            &MASTER,
            oenc.hash.as_bytes(),
            &oenc.main,
            oenc.verification_outboard.as_deref(),
            oenc.fec_parity.as_deref(),
            oenc.info.padding_len,
            format,
        )
        .unwrap_or_else(|e| panic!("decode_outboard c{format}: {e}"));
        assert_eq!(decoded, plaintext, "c{format} outboard plaintext mismatch");
    }
}

#[test]
fn outboard_encrypted_fixed_nonce_roundtrip_c5() {
    require_lean_lib();
    let plaintext = b"encrypted outboard fixed nonce";
    // c5 = Encryption | Verification — low-level embedded-nonce layout
    let oenc =
        carbonado::backend::lean::encode_outboard(&MASTER, plaintext, 5, Some(&NONCE), false)
            .expect("lean encode_outboard c5 embedded");
    // Embedded layout embeds 16-byte nonce in main.
    assert!(
        oenc.main.len() >= 16 + 64,
        "embedded main must hold nonce+tag"
    );
    let decoded = carbonado::backend::lean::decode_outboard(
        &MASTER,
        oenc.hash.as_bytes(),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        5,
        None,
        false,
    )
    .expect("lean decode_outboard c5 embedded");
    assert_eq!(decoded, plaintext);
}

#[test]
fn outboard_header_path_encrypted_matches_file_layout() {
    require_lean_lib();
    let plaintext = b"header-path outboard encrypted";
    // c5 with header_path=true → bare main is [tag|ct] (matches file::encode_outboard).
    let oenc = carbonado::backend::lean::encode_outboard(&MASTER, plaintext, 5, Some(&NONCE), true)
        .expect("lean encode_outboard c5 header_path");
    // Header-path main starts with tag (64 B), not a random-looking nonce prefix alone.
    assert!(oenc.main.len() >= 64, "header-path main has at least tag");
    // Embedded would be 16 longer for same pt (nonce prefix); header_path is shorter by 16.
    let oenc_emb =
        carbonado::backend::lean::encode_outboard(&MASTER, plaintext, 5, Some(&NONCE), false)
            .expect("embedded");
    assert_eq!(
        oenc_emb.main.len(),
        oenc.main.len() + 16,
        "header-path main omits 16-byte embedded nonce"
    );
    let decoded = carbonado::backend::lean::decode_outboard(
        &MASTER,
        oenc.hash.as_bytes(),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        5,
        Some(&NONCE),
        true,
    )
    .expect("lean decode_outboard c5 header_path");
    assert_eq!(decoded, plaintext);

    // High-level file::encode_outboard under lean uses header_path (Some(payload_nonce)).
    let (hdr, fo) =
        file::encode_outboard(&MASTER, plaintext, 5, None).expect("file encode_outboard");
    let hdr = hdr.expect("encrypted outboard returns Header");
    let hdr_bytes = hdr.try_to_vec().expect("hdr vec");
    let d2 = file::decode_outboard(
        &MASTER,
        fo.hash.as_bytes(),
        Some(&hdr_bytes),
        &fo.main,
        fo.verification_outboard.as_deref(),
        fo.fec_parity.as_deref(),
        fo.info.padding_len,
        5,
    )
    .expect("file decode_outboard");
    assert_eq!(d2, plaintext);
}

#[test]
fn inboard_scrub_pristine_unnecessary() {
    require_lean_lib();
    let plaintext = b"scrub pristine";
    // c12 = Verification | Fec (public)
    let Encoded(body, hash, info) = encode(&MASTER, plaintext, 12).expect("encode c12");
    let err = scrub(&body, hash.as_bytes(), &info, 12).expect_err("pristine scrub");
    assert!(
        matches!(err, CarbonadoError::UnnecessaryScrub),
        "expected UnnecessaryScrub, got {err:?}"
    );
}

#[test]
fn inboard_scrub_requires_verification() {
    require_lean_lib();
    let plaintext = b"no verification bit";
    let Encoded(body, hash, info) = encode(&MASTER, plaintext, 0).expect("encode c0");
    let err = scrub(&body, hash.as_bytes(), &info, 0).expect_err("scrub c0");
    assert!(
        matches!(err, CarbonadoError::ScrubRequiresVerification),
        "expected ScrubRequiresVerification, got {err:?}"
    );
}

#[test]
fn inboard_scrub_recovers_bitflip_in_fec_body() {
    require_lean_lib();
    let plaintext = b"scrub recover bitflip phase2";
    let Encoded(mut body, hash, info) = encode(&MASTER, plaintext, 12).expect("encode c12");
    // Flip a byte deep in the inboard (past 8-byte length prefix) to taint ≤1 shard.
    if body.len() > 64 {
        let i = body.len() / 2;
        body[i] ^= 0xff;
    } else if !body.is_empty() {
        let i = body.len() - 1;
        body[i] ^= 0x01;
    }
    let recovered =
        scrub(&body, hash.as_bytes(), &info, 12).unwrap_or_else(|e| panic!("scrub recover: {e}"));
    assert_eq!(
        recovered.len(),
        encode(&MASTER, plaintext, 12).unwrap().0.len()
    );
    // Decode recovered body
    let decoded = decode(&MASTER, hash.as_bytes(), &recovered, info.padding_len, 12)
        .expect("decode recovered");
    assert_eq!(decoded, plaintext);
}

#[test]
fn outboard_scrub_pristine_unnecessary() {
    require_lean_lib();
    let plaintext = b"outboard scrub pristine";
    let oenc = encode_outboard(&MASTER, plaintext, 12).expect("encode_outboard c12");
    let err = scrub_outboard(
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        &oenc.info,
        12,
        oenc.hash.as_bytes(),
    )
    .expect_err("pristine outboard scrub");
    assert!(
        matches!(err, CarbonadoError::UnnecessaryScrub),
        "expected UnnecessaryScrub, got {err:?}"
    );
}

#[test]
fn outboard_scrub_recovers_main_damage() {
    require_lean_lib();
    let plaintext = b"outboard scrub damage recover";
    let oenc = encode_outboard(&MASTER, plaintext, 12).expect("encode_outboard c12");
    let mut damaged = oenc.main.clone();
    if damaged.len() > 8 {
        damaged[0] ^= 0xff;
        damaged[1] ^= 0xaa;
    }
    let recovered = scrub_outboard(
        &damaged,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        &oenc.info,
        12,
        oenc.hash.as_bytes(),
    )
    .unwrap_or_else(|e| panic!("scrub_outboard recover: {e}"));
    let decoded = decode_outboard(
        &MASTER,
        oenc.hash.as_bytes(),
        &recovered,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        12,
    )
    .expect("decode recovered bare");
    assert_eq!(decoded, plaintext);
}

#[test]
fn verify_slice_c4_content() {
    require_lean_lib();
    let plaintext = b"slice verify content match!!";
    let Encoded(body, hash, info) = encode(&MASTER, plaintext, 4).expect("encode c4");
    // For non-FEC, verifiable_slice_count is 0; use count=1 for first leaf.
    let _ = info.verifiable_slice_count;
    let got = verify_slice(&body, 0, 1, hash.as_bytes(), 4).expect("verify_slice");
    let n = got.len().min(plaintext.len());
    assert_eq!(&got[..n], &plaintext[..n]);
    let extracted = extract_slice(&body, 0, hash.as_bytes(), 4).expect("extract_slice");
    assert_eq!(extracted, got);
}

#[test]
fn stream_buffer_composes_over_lean_body() {
    require_lean_lib();
    // Under backend-lean, stream_encode_buffer / stream_decode_buffer compose over Lean C ABI.
    let plaintext = b"stream buffer compose";
    let (body, hash, info) =
        stream_encode_buffer(&MASTER, plaintext, 4).expect("stream_encode_buffer");
    let decoded = stream_decode_buffer(&MASTER, hash.as_bytes(), &body, info.padding_len, 4)
        .expect("stream_decode_buffer");
    assert_eq!(decoded, plaintext);
    // Same engine as crate::encode
    let Encoded(body2, hash2, _) = encode(&MASTER, plaintext, 4).expect("encode");
    assert_eq!(body, body2);
    assert_eq!(hash, hash2);
}

#[test]
fn g9_headered_public_roundtrip_matrix() {
    require_lean_lib();
    // G9 start: lean encode → lean decode for headered public formats (same ABI).
    // Full Rust↔Lean cross process needs both engines; buffer identity under lean is
    // the Phase 2 G9 seed. Cross-process G9 continues as residual until CI freezes both.
    let plaintext = b"g9 headered public";
    for level in [0u8, 4, 12, 14] {
        let (archive, info) = file::encode(&MASTER, plaintext, level, None)
            .unwrap_or_else(|e| panic!("headered encode c{level}: {e}"));
        assert!(archive.len() >= file::Header::LEN);
        assert_eq!(info.input_len, plaintext.len() as u32);
        let (header, decoded) = file::decode(&MASTER, &archive)
            .unwrap_or_else(|e| panic!("headered decode c{level}: {e}"));
        assert_eq!(header.format.bits(), level);
        assert_eq!(decoded, plaintext, "c{level}");
    }
}

#[test]
fn g9_body_public_formats_deterministic() {
    require_lean_lib();
    let plaintext = b"g9 body deterministic";
    for format in [0u8, 4, 12, 14] {
        let Encoded(b1, h1, i1) = encode(&MASTER, plaintext, format).expect("e1");
        let Encoded(b2, h2, i2) = encode(&MASTER, plaintext, format).expect("e2");
        assert_eq!(b1, b2, "c{format} body deterministic");
        assert_eq!(h1, h2);
        assert_eq!(i1.padding_len, i2.padding_len);
        assert_eq!(i1.chunk_len, i2.chunk_len);
        let d = decode(&MASTER, h1.as_bytes(), &b1, i1.padding_len, format).expect("decode");
        assert_eq!(d, plaintext);
    }
}

#[test]
fn g9_fixed_nonce_encrypted_body() {
    require_lean_lib();
    // Encrypted body with fixed nonce via lean helper (public encode uses random).
    let plaintext = b"g9 enc fixed nonce";
    let Encoded(body, hash, info) =
        carbonado::backend::lean::encode(&MASTER, plaintext, 5, Some(&NONCE)).expect("enc c5");
    let decoded =
        carbonado::backend::lean::decode(&MASTER, hash.as_bytes(), &body, info.padding_len, 5)
            .expect("dec c5");
    assert_eq!(decoded, plaintext);
    // Second encode with same nonce matches (deterministic).
    let Encoded(body2, hash2, _) =
        carbonado::backend::lean::encode(&MASTER, plaintext, 5, Some(&NONCE)).expect("enc2");
    assert_eq!(body, body2);
    assert_eq!(hash, hash2);
}

#[test]
fn encode_info_fec_fields_populated() {
    require_lean_lib();
    let plaintext = b"encode info meta";
    let Encoded(body, _hash, info) = encode(&MASTER, plaintext, 12).expect("encode c12");
    assert_eq!(info.bytes_verifiable as usize, body.len());
    assert!(info.chunk_len > 0, "chunk_len must be set for FEC");
    assert!(info.bytes_ecc > 0, "bytes_ecc must be set for FEC");
    assert!(
        info.verifiable_slice_count > 0,
        "verifiable_slice_count must be set for FEC+V"
    );
}

#[test]
fn outboard_missing_verification_maps() {
    require_lean_lib();
    let plaintext = b"missing ob";
    let OutboardEncoded {
        main,
        verification_outboard: _,
        fec_parity,
        hash,
        info,
    } = encode_outboard(&MASTER, plaintext, 12).expect("encode");
    let err = scrub_outboard(
        &main,
        None,
        fec_parity.as_deref(),
        &info,
        12,
        hash.as_bytes(),
    )
    .expect_err("missing outboard");
    assert!(
        matches!(err, CarbonadoError::MissingVerificationOutboard),
        "expected MissingVerificationOutboard, got {err:?}"
    );
}

#[test]
fn inboard_scrub_invalid_scrubbed_hash_excess_damage() {
    require_lean_lib();
    let plaintext = b"scrub fail excess damage";
    let Encoded(mut body, hash, info) = encode(&MASTER, plaintext, 12).expect("encode c12");
    // Zero most of the body past the length prefix so >4 shards are wiped.
    if body.len() > 8 {
        for b in &mut body[8..] {
            *b = 0;
        }
    }
    let err = scrub(&body, hash.as_bytes(), &info, 12).expect_err("irrecoverable");
    assert!(
        matches!(err, CarbonadoError::InvalidScrubbedHash),
        "expected InvalidScrubbedHash, got {err:?}"
    );
}

#[test]
fn outboard_scrub_requires_verification() {
    require_lean_lib();
    // c0 has no Verification bit
    let plaintext = b"outboard scrub no V";
    let oenc = encode_outboard(&MASTER, plaintext, 0).expect("encode c0");
    let err = scrub_outboard(
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        &oenc.info,
        0,
        oenc.hash.as_bytes(),
    )
    .expect_err("scrub without V");
    assert!(
        matches!(err, CarbonadoError::ScrubRequiresVerification),
        "expected ScrubRequiresVerification, got {err:?}"
    );
}

#[test]
fn outboard_scrub_missing_fec_parity() {
    require_lean_lib();
    let plaintext = b"outboard scrub missing parity";
    let oenc = encode_outboard(&MASTER, plaintext, 12).expect("encode c12");
    let mut damaged = oenc.main.clone();
    if !damaged.is_empty() {
        damaged[0] ^= 0xff;
    }
    let err = scrub_outboard(
        &damaged,
        oenc.verification_outboard.as_deref(),
        None, // missing parity after verify fail
        &oenc.info,
        12,
        oenc.hash.as_bytes(),
    )
    .expect_err("missing parity");
    assert!(
        matches!(err, CarbonadoError::MissingFecParity),
        "expected MissingFecParity, got {err:?}"
    );
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// G9: Rust-engine goldens (generated under default `backend-rust`) decoded by Lean AOT.
///
/// Vectors from `encode` / `file::encode` with MASTER + public formats (deterministic).
#[test]
fn g9_rust_encode_lean_decode_body_c0_c4() {
    require_lean_lib();
    // c0: body == plaintext (no verification)
    let c0_body = from_hex("67392063726f73732d6261636b656e6420626f6479206330");
    let c0_hash = [0u8; 32];
    let pt0 = b"g9 cross-backend body c0";
    assert_eq!(c0_body, pt0);
    let d0 = decode(&MASTER, &c0_hash, &c0_body, 0, 0).expect("lean decode rust c0");
    assert_eq!(d0, pt0);

    // c4: bao inboard over plaintext
    let c4_body = from_hex("180000000000000067392063726f73732d6261636b656e6420626f6479206334");
    let c4_hash = from_hex("4174c6c3b5a0cf2d734a243b9cf3766afaf2c0e0e913fb09944bbcc9a8556c48");
    let pt4 = b"g9 cross-backend body c4";
    let d4 = decode(&MASTER, &c4_hash, &c4_body, 0, 4).expect("lean decode rust c4");
    assert_eq!(d4, pt4);

    // Lean re-encode of same input must match the Rust body (wire identity).
    let Encoded(lean_body, lean_hash, _) = encode(&MASTER, pt4, 4).expect("lean encode c4");
    assert_eq!(lean_body, c4_body, "lean encode must bit-match rust body");
    assert_eq!(lean_hash.as_bytes(), c4_hash.as_slice());
}

#[test]
fn g9_rust_encode_lean_decode_headered_c4() {
    require_lean_lib();
    let arch = from_hex(
        "434152424f4e41444f32300a00000000000000000000000000000000fa7760aa360e9c232b9d7b544f8172f5dc64d99404fd77f94a7a934906034bdcf82b5662847ab76c4f45594cee2faeb45d97bc2ebed05e2e9df3936b4ff9c5f94174c6c3b5a0cf2d734a243b9cf3766afaf2c0e0e913fb09944bbcc9a8556c480000000000000000000000000000000000000000000000000000000000000000040000000020000000000000000000000000000000180000000000000067392063726f73732d6261636b656e6420626f6479206334",
    );
    let pt = b"g9 cross-backend body c4";
    let (header, decoded) = file::decode(&MASTER, &arch).expect("lean decode rust headered c4");
    assert_eq!(header.format.bits(), 4);
    assert_eq!(decoded, pt);
}
