//! Phase 1B: SLH-DSA sidecar E2E (requires `pqc` feature).
//!
//! CI must run `cargo test --all-features` (or `--features pqc`) for this crate;
//! `--no-default-features` skips all tests here (`bitcoinpqc` / `pqc` is optional).

#![cfg(feature = "pqc")]

use std::fs;

use carbonado::{
    constants::Format,
    crypto::{
        read_slh_sidecar, slh_dsa_generate_keypair, slh_dsa_sign, slh_dsa_verify,
        write_slh_sidecar, Algorithm, PublicKey, Signature, SLH1_MAGIC, SLH1_SIDECAR_LEN,
        SLH1_SIGNATURE_LEN,
    },
    error::CarbonadoError,
    file::{self, Header},
};
use getrandom::getrandom;
use rand::RngCore;

fn random_master() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

fn slh_entropy() -> [u8; 128] {
    let mut e = [0u8; 128];
    getrandom(&mut e).expect("entropy");
    e
}

fn slh_public_key_bytes(pk: &PublicKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk.bytes[..32]);
    out
}

#[test]
fn test_slh_outboard_sidecar_binds_header_public_key() {
    let key = random_master();
    let input = b"SLH-DSA outboard E2E: sign keyed Bao root, verify via Header.slh_public_key";

    let (hdr_opt, oenc) = file::encode_outboard(&key, input, 14, None).unwrap();
    let base_hdr = hdr_opt.unwrap();
    let bao_root = base_hdr.hash.as_bytes();

    let keypair = slh_dsa_generate_keypair(&slh_entropy()).unwrap();
    let slh_pk = slh_public_key_bytes(&keypair.public_key);
    let signature = slh_dsa_sign(&keypair.secret_key, bao_root).unwrap();

    // Rebuild header with SLH public key bound under header_mac.
    let signed_hdr = Header::new(
        &key,
        base_hdr.payload_nonce,
        bao_root,
        slh_pk,
        Format::from(14),
        base_hdr.chunk_index,
        base_hdr.encoded_len,
        base_hdr.padding_len,
        base_hdr.metadata,
    )
    .unwrap();
    assert_eq!(signed_hdr.slh_public_key, slh_pk);

    let hdr_bytes = signed_hdr.try_to_vec().unwrap();
    let rec = file::decode_outboard(
        &key,
        signed_hdr.hash.as_bytes(),
        Some(&hdr_bytes),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        14,
    )
    .unwrap();
    assert_eq!(rec, input);

    // Sidecar wire format: SLH1 magic + raw signature over 32-byte Bao root.
    let sidecar_path = std::env::temp_dir().join(format!(
        "carbonado_slh_test_{}_{}.slh",
        std::process::id(),
        signed_hdr.file_name()
    ));
    write_slh_sidecar(&sidecar_path, &signature.bytes).expect("write slh sidecar");
    let sig_bytes = read_slh_sidecar(&sidecar_path).expect("read slh sidecar");
    assert_eq!(sig_bytes.len(), SLH1_SIGNATURE_LEN);
    let on_disk = fs::read(&sidecar_path).expect("read raw sidecar");
    assert_eq!(on_disk.len(), SLH1_SIDECAR_LEN);
    assert_eq!(&on_disk[..4], SLH1_MAGIC);
    let _ = fs::remove_file(&sidecar_path);
    let sig = Signature {
        algorithm: Algorithm::SLH_DSA_SHA2_128S,
        bytes: sig_bytes.to_vec(),
    };
    assert!(slh_dsa_verify(&keypair.public_key, bao_root, &sig).unwrap());

    // Header public key must match sidecar verifier.
    let hdr_pk = PublicKey {
        algorithm: Algorithm::SLH_DSA_SHA2_128S,
        bytes: signed_hdr.slh_public_key.to_vec(),
    };
    assert!(slh_dsa_verify(&hdr_pk, bao_root, &sig).unwrap());

    // Tampered root must not verify.
    let mut bad_root = *bao_root;
    bad_root[0] ^= 0x01;
    assert!(!slh_dsa_verify(&hdr_pk, &bad_root, &sig).unwrap());

    // Negative: signature from key A must not verify with key B in header.
    let other_keypair = slh_dsa_generate_keypair(&slh_entropy()).unwrap();
    let wrong_hdr_pk = PublicKey {
        algorithm: Algorithm::SLH_DSA_SHA2_128S,
        bytes: slh_public_key_bytes(&other_keypair.public_key).to_vec(),
    };
    assert!(!slh_dsa_verify(&wrong_hdr_pk, bao_root, &sig).unwrap());

    // Negative: tampered slh_public_key in header must fail decode_outboard MAC.
    let mut bad_hdr_bytes = hdr_bytes.clone();
    bad_hdr_bytes[offsets::SLH_PK] ^= 0x01;
    let err_pk = file::decode_outboard(
        &key,
        signed_hdr.hash.as_bytes(),
        Some(&bad_hdr_bytes),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        14,
    )
    .unwrap_err();
    assert!(
        matches!(err_pk, CarbonadoError::AuthenticationFailed),
        "tampered slh_public_key must fail header_mac, got {err_pk:?}"
    );
}

mod offsets {
    pub const SLH_PK: usize = 124;
}
