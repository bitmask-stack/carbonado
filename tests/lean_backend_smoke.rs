//! Phase 1 allowlist smoke for `backend-lean` (docs/TEST_CONTRACT.md).
//!
//! ```bash
//! nix build .#libcarbonado -o result-libcarbonado
//! export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib
//! export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include
//! export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB
//! cargo test --no-default-features --features "backend-lean,pqc,ots" --test lean_backend_smoke
//! # or: just test-lean-smoke
//! ```
//!
//! Primary allowlist: public (even) formats c0, c4, c12. Fixed master keys.
//! R2 also smokes encrypted headered + non-zero SLH with a fixed nonce (no RNG).
//! Only compiled under `backend-lean` (avoids breaking default/`backend-rust` clippy of all targets).

#![cfg(feature = "backend-lean")]

mod common;

use carbonado::{
    carbonado_verification_key, constants::Format, decode, encode, error::CarbonadoError, file,
    file::Header, structs::Encoded,
};
use common::header_layout::offsets;

/// Fixed 32-byte master (public formats may use zeros; we use a non-zero pattern).
const MASTER: [u8; 32] = [
    0x0c, 0xa1, 0xb0, 0xda, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
];

fn require_lean_lib() {
    if std::env::var_os("CARBONADO_LEAN_LIB").is_none() {
        panic!(
            "CARBONADO_LEAN_LIB unset. Build and export first:\n  \
             nix build .#libcarbonado -o result-libcarbonado\n  \
             export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib\n  \
             export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include\n  \
             export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB\n  \
             # or: just test-lean-smoke"
        );
    }
}

#[test]
fn abi_version_is_one() {
    require_lean_lib();
    let v = carbonado::backend::lean::abi_version();
    assert_eq!(v, 1, "CARBONADO_ABI_VERSION");
}

#[test]
fn verification_key_lean_abi_matches_blake3_formula() {
    require_lean_lib();
    // Public API is pure blake3; parity is via the Lean C ABI helper.
    for format in [0u8, 4, 6, 12, 14, 15] {
        let lean = carbonado::backend::lean::verification_key(format)
            .unwrap_or_else(|e| panic!("lean verification_key c{format}: {e}"));
        let rust_formula = carbonado_verification_key(format);
        assert_eq!(
            lean, rust_formula,
            "Lean AOT verification key mismatch for format {format}"
        );
        assert_eq!(
            rust_formula,
            blake3::derive_key("carbonado-v2/verification", &[format])
        );
    }
}

#[test]
fn headered_roundtrip_public_formats() {
    require_lean_lib();
    let plaintext = b"carbonado phase1 lean headered smoke";
    // c0 raw, c4 bao, c12 bao+fec (padding lives in Header)
    for level in [0u8, 4, 12] {
        let (archive, info) = file::encode(&MASTER, plaintext, level, None)
            .unwrap_or_else(|e| panic!("encode c{level}: {e}"));
        assert!(
            archive.len() >= file::Header::LEN,
            "c{level}: archive shorter than header"
        );
        assert_eq!(info.input_len, plaintext.len() as u32);
        let (header, decoded) =
            file::decode(&MASTER, &archive).unwrap_or_else(|e| panic!("decode c{level}: {e}"));
        assert_eq!(header.format.bits(), level);
        assert_eq!(decoded, plaintext, "c{level} plaintext mismatch");
    }
}

#[test]
fn low_level_roundtrip_c0_c4() {
    require_lean_lib();
    let plaintext = b"low-level body smoke c0/c4";
    for format in [0u8, 4] {
        let Encoded(body, hash, info) = encode(&MASTER, plaintext, format)
            .unwrap_or_else(|e| panic!("encode body c{format}: {e}"));
        assert_eq!(info.bytes_verifiable as usize, body.len());
        let decoded = decode(&MASTER, hash.as_bytes(), &body, info.padding_len, format)
            .unwrap_or_else(|e| panic!("decode body c{format}: {e}"));
        assert_eq!(decoded, plaintext, "c{format} body plaintext mismatch");
    }
}

#[test]
fn low_level_encode_short_master_invalid_key_length() {
    require_lean_lib();
    let short = [0u8; 16];
    let err = match encode(&short, b"x", 0) {
        Ok(_) => panic!("short master low-level encode must fail"),
        Err(e) => e,
    };
    assert!(
        matches!(err, CarbonadoError::InvalidKeyLength),
        "expected InvalidKeyLength (not InternalStateError from packEncodeErr bug), got {err:?}"
    );
}

#[test]
fn low_level_decode_wrong_hash_fails() {
    require_lean_lib();
    let plaintext = b"low-level wrong hash";
    let Encoded(body, hash, info) = encode(&MASTER, plaintext, 4).expect("encode");
    let mut bad_hash = *hash.as_bytes();
    bad_hash[0] ^= 0xff;
    let err = decode(&MASTER, &bad_hash, &body, info.padding_len, 4).expect_err("bad hash");
    // R4: Bao root/auth mismatch maps to AuthenticationFailed (same as pure Rust
    // map_decode_error Parent/LeafHashMismatch). Truncation alone stays BaoResponseTruncated.
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "expected AuthenticationFailed, got {err:?}"
    );
}

#[test]
fn headered_bad_magic_fails() {
    require_lean_lib();
    let plaintext = b"tamper magic";
    let (mut archive, _) = file::encode(&MASTER, plaintext, 4, None).expect("encode");
    // Corrupt MAGICNO first byte (CARBONADO20\n)
    archive[0] ^= 0xff;
    let err = file::decode(&MASTER, &archive).expect_err("bad magic must fail");
    assert!(
        matches!(err, CarbonadoError::InvalidMagicNumber(_)),
        "expected InvalidMagicNumber, got {err:?}"
    );
}

#[test]
fn headered_auth_fail_on_header_mac_tamper() {
    require_lean_lib();
    let plaintext = b"tamper header mac";
    let (mut archive, _) = file::encode(&MASTER, plaintext, 4, None).expect("encode");
    // header_mac sits at offset 28 (12 magic + 16 nonce); flip one byte
    let mac_off = 28;
    archive[mac_off] ^= 0x01;
    let err = file::decode(&MASTER, &archive).expect_err("tampered MAC must fail");
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "expected AuthenticationFailed, got {err:?}"
    );
}

#[test]
fn invalid_key_length_rejected_headered() {
    require_lean_lib();
    let short = [0u8; 16];
    let err = file::encode(&short, b"x", 0, None).expect_err("short master");
    assert!(
        matches!(err, CarbonadoError::InvalidKeyLength),
        "expected InvalidKeyLength, got {err:?}"
    );
}

#[test]
fn headered_metadata_roundtrip_and_mac_binding() {
    require_lean_lib();
    let meta = *b"metameta";
    let (arch, _) = file::encode(&MASTER, b"meta payload", 0, Some(meta)).expect("encode meta");
    let hdr = Header::try_from(&arch[..Header::LEN]).expect("header");
    assert_eq!(hdr.metadata, Some(meta));
    let (_hdr2, pt) = file::decode(&MASTER, &arch).expect("decode");
    assert_eq!(pt, b"meta payload");

    // Tamper metadata byte → header_mac fail.
    let mut tampered = arch.clone();
    tampered[offsets::METADATA] ^= 0xff;
    let err = file::decode(&MASTER, &tampered).expect_err("tampered meta");
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "expected AuthenticationFailed, got {err:?}"
    );
}

/// R2: non-zero SLH pk via `lean::encode_headered` (file::encode leaves SLH zeroed by design).
#[test]
fn headered_slh_pk_roundtrip_and_mac_binding() {
    require_lean_lib();
    let slh = [0xABu8; 32];
    let meta = *b"slh-meta";
    let (arch, info) = carbonado::backend::lean::encode_headered(
        &MASTER,
        b"slh payload",
        0,
        None,
        Some(&slh),
        Some(&meta),
    )
    .expect("encode with slh+meta");
    assert_eq!(info.bytes_compressed, 0);
    assert_eq!(info.bytes_encrypted, 0);
    let hdr = Header::try_from(&arch[..Header::LEN]).expect("header");
    assert_eq!(hdr.slh_public_key, slh);
    assert_eq!(hdr.metadata, Some(meta));
    let (hdr2, pt) = file::decode(&MASTER, &arch).expect("decode");
    assert_eq!(pt, b"slh payload");
    assert_eq!(hdr2.slh_public_key, slh);
    assert_eq!(hdr2.metadata, Some(meta));

    // Tamper SLH pk byte → header_mac fail.
    let mut tampered = arch.clone();
    tampered[offsets::SLH_PUBLIC_KEY] ^= 0xff;
    let err = file::decode(&MASTER, &tampered).expect_err("tampered slh");
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "expected AuthenticationFailed, got {err:?}"
    );
}

/// R2: non-zero SLH + metadata on encrypted headered path (fixed nonce; no RNG).
#[test]
fn headered_encrypted_slh_pk_and_metadata_roundtrip() {
    require_lean_lib();
    let slh = [0xCDu8; 32];
    let meta = *b"enc-meta";
    let nonce = [0x11u8; 16];
    let format = Format::Encryption.bits(); // c1
    let (arch, info) = carbonado::backend::lean::encode_headered(
        &MASTER,
        b"enc slh payload",
        format,
        Some(&nonce),
        Some(&slh),
        Some(&meta),
    )
    .expect("encrypted encode with slh+meta");
    assert_eq!(info.bytes_compressed, 0);
    assert!(info.bytes_encrypted > 0);
    let hdr = Header::try_from(&arch[..Header::LEN]).expect("header");
    assert_eq!(hdr.slh_public_key, slh);
    assert_eq!(hdr.metadata, Some(meta));
    assert_eq!(hdr.payload_nonce, nonce);
    let (hdr2, pt) = file::decode(&MASTER, &arch).expect("decode");
    assert_eq!(pt, b"enc slh payload");
    assert_eq!(hdr2.slh_public_key, slh);
    assert_eq!(hdr2.metadata, Some(meta));

    let mut tampered = arch.clone();
    tampered[offsets::SLH_PUBLIC_KEY] ^= 0xff;
    let err = file::decode(&MASTER, &tampered).expect_err("tampered slh on encrypted");
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "expected AuthenticationFailed, got {err:?}"
    );
}

#[test]
fn format_bits_even_are_public() {
    // Sanity: Phase 1 allowlist uses even formats only.
    for f in [0u8, 4, 12] {
        let fmt = Format::from(f);
        assert!(
            !fmt.contains(Format::Encryption),
            "format {f} should be public (even)"
        );
    }
}
