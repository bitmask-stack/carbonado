//! Phase 4 allowlist for `backend-lean` (docs/TEST_CONTRACT.md, docs/GAPS.md).
//!
//! Dual-backend composition (G10 strategy A):
//! - **Container crypto** (outboard / headered / directory segments+catalog): Lean C ABI
//! - **SLH-DSA** (`crypto::slh_*`, SLH1 sidecar, header `slh_public_key`): Rust `bitcoinpqc`
//!   under both backends until pure Lean/libbitcoinpqc FFI lands (G10 residual)
//! - **OTS** offline CBOTS stubs: pure Rust (`ots` feature) — same path under lean
//! - **CLI dual path (honest):**
//!   - Directory library + subprocess → Lean composition (dual-engine)
//!   - Buffer APIs (`file::encode` / `encode_outboard`) → Lean
//!   - Single-file CLI streaming (`encode_stream` / `stream_*_outboard`) remains pure Rust
//!     under lean builds; lean-linked binary subprocess for single-file is link/smoke only
//!
//! ```bash
//! nix build .#libcarbonado -o result-libcarbonado
//! export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib
//! export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include
//! export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB
//! cargo test --no-default-features --features "backend-lean,pqc,ots,cli" --test lean_backend_phase4
//! # or: just test-lean-phase4
//! ```
//! Only compiled under `backend-lean` + `pqc` (avoids breaking default/`backend-rust` clippy of all targets).

#![cfg(all(feature = "backend-lean", feature = "pqc"))]

use std::fs;
use std::path::{Path, PathBuf};

use carbonado::constants::Format;
use carbonado::crypto::{
    read_slh_sidecar, slh_dsa_generate_keypair, slh_dsa_sign, slh_dsa_verify, write_slh_sidecar,
    Algorithm, PublicKey, Signature, SLH1_MAGIC, SLH1_SIDECAR_LEN, SLH1_SIGNATURE_LEN,
};
use carbonado::error::CarbonadoError;
use carbonado::file::{
    self, decode_directory, encode_directory, encode_directory_with_options, encode_stream,
    DirectoryEncodeOptions, Header, DIRECTORY_ARCHIVE_FORMAT,
};
use carbonado::{
    build_adamantine_payload, decode_adamantine, encode_adamantine, split_adamantine_payload,
    ADAMANTINE_CARBONADO_FMT_PUBLIC, ADAMANTINE_FLAG_REQUIRE_OTS,
};
use getrandom::getrandom;
use rand::RngCore;

#[cfg(feature = "ots")]
use carbonado::filepack_manifest::FilepackManifest;
#[cfg(feature = "ots")]
use carbonado::ots::{verify_stamp, OtsPolicy};

const ZERO_KEY: [u8; 32] = [0u8; 32];

const TEST_MASTER: [u8; 32] = [
    0x0c, 0xa1, 0xb0, 0xda, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
];

/// Header wire offset of `slh_public_key` (AGENTS § Header layout; 12+16+64+32 = 124).
mod offsets {
    pub const SLH_PK: usize = 124;
}

fn require_lean_lib() {
    if std::env::var_os("CARBONADO_LEAN_LIB").is_none() {
        panic!(
            "CARBONADO_LEAN_LIB unset. Build and export first:\n  \
             nix build .#libcarbonado -o result-libcarbonado\n  \
             export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib\n  \
             export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include\n  \
             export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB\n  \
             # or: just test-lean-phase4"
        );
    }
}

fn tempdir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "carbonado-lean-p4-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("tempdir");
    p
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn adam_catalog_path(enc_dir: &Path, root: &[u8; 32], format: u8) -> PathBuf {
    enc_dir.join(format!("{}.adam.c{format}", hex32(root)))
}

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
fn abi_version_is_one() {
    require_lean_lib();
    assert_eq!(carbonado::backend::lean::abi_version(), 1);
}

#[test]
fn backend_name_is_lean() {
    require_lean_lib();
    assert_eq!(carbonado::backend::lean::NAME, "lean");
}

/// G10 dual-suite: Lean outboard encode/decode + Rust bitcoinpqc SLH sidecar over Bao root.
#[test]
fn slh_outboard_sidecar_binds_header_public_key_under_lean() {
    require_lean_lib();
    let key = random_master();
    let input = b"Phase4 SLH under lean: Lean container + Rust SLH-DSA-SHA2-128s";

    let (hdr_opt, oenc) = file::encode_outboard(&key, input, 14, None).expect("encode_outboard");
    let base_hdr = hdr_opt.expect("header for outboard high-level path");
    let bao_root = base_hdr.hash.as_bytes();

    let keypair = slh_dsa_generate_keypair(&slh_entropy()).expect("slh keygen");
    let slh_pk = slh_public_key_bytes(&keypair.public_key);
    let signature = slh_dsa_sign(&keypair.secret_key, bao_root).expect("slh sign");

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
    .expect("Header::new with slh_pk");
    assert_eq!(signed_hdr.slh_public_key, slh_pk);

    let hdr_bytes = signed_hdr.try_to_vec().expect("header wire");
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
    .expect("decode_outboard lean");
    assert_eq!(rec, input);

    let sidecar_path = tempdir("slh_sc").join(format!("{}.slh", signed_hdr.file_name()));
    write_slh_sidecar(&sidecar_path, &signature.bytes).expect("write slh");
    let sig_bytes = read_slh_sidecar(&sidecar_path).expect("read slh");
    assert_eq!(sig_bytes.len(), SLH1_SIGNATURE_LEN);
    let on_disk = fs::read(&sidecar_path).expect("raw sidecar");
    assert_eq!(on_disk.len(), SLH1_SIDECAR_LEN);
    assert_eq!(&on_disk[..4], SLH1_MAGIC);

    let sig = Signature {
        algorithm: Algorithm::SLH_DSA_SHA2_128S,
        bytes: sig_bytes,
    };
    assert!(
        slh_dsa_verify(&keypair.public_key, bao_root, &sig).expect("verify"),
        "signature must verify over Bao root"
    );

    let hdr_pk = PublicKey {
        algorithm: Algorithm::SLH_DSA_SHA2_128S,
        bytes: signed_hdr.slh_public_key.to_vec(),
    };
    assert!(
        slh_dsa_verify(&hdr_pk, bao_root, &sig).expect("verify via header pk"),
        "header slh_public_key must verify sidecar"
    );

    // Fail-closed: wrong root
    let mut bad_root = *bao_root;
    bad_root[0] ^= 0x01;
    assert!(
        !slh_dsa_verify(&hdr_pk, &bad_root, &sig).expect("verify bad root"),
        "wrong Bao root must not verify"
    );

    // Fail-closed: wrong public key
    let other = slh_dsa_generate_keypair(&slh_entropy()).expect("other keygen");
    let wrong_pk = PublicKey {
        algorithm: Algorithm::SLH_DSA_SHA2_128S,
        bytes: slh_public_key_bytes(&other.public_key).to_vec(),
    };
    assert!(
        !slh_dsa_verify(&wrong_pk, bao_root, &sig).expect("verify wrong pk"),
        "wrong header pk must not verify"
    );

    // Fail-closed: tampered slh_public_key fails header_mac (lean headered path)
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

#[test]
fn slh_sidecar_bad_magic_and_length_fail_closed() {
    require_lean_lib();
    let dir = tempdir("slh_wire");

    // Bad magic, correct length
    let bad_magic = dir.join("bad_magic.slh");
    let mut wire = vec![0u8; SLH1_SIDECAR_LEN];
    wire[..4].copy_from_slice(b"XXXX");
    fs::write(&bad_magic, &wire).expect("write");
    let err = read_slh_sidecar(&bad_magic).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidMagicNumber(_)),
        "bad SLH1 magic must be InvalidMagicNumber, got {err:?}"
    );

    // Truncated (good magic prefix)
    let short = dir.join("short.slh");
    fs::write(&short, b"SLH1").expect("write");
    let err2 = read_slh_sidecar(&short).unwrap_err();
    assert!(
        matches!(err2, CarbonadoError::OutboardVerificationFailed(_)),
        "short sidecar must be OutboardVerificationFailed, got {err2:?}"
    );

    // Wrong signature length on write.
    // Taxonomy freeze (P4): short sig / short sidecar map to `OutboardVerificationFailed`
    // (pre-existing; not a dedicated SlhWire error). Update these asserts if refined later.
    let err3 = write_slh_sidecar(dir.join("short_sig.slh"), b"short").unwrap_err();
    assert!(
        matches!(err3, CarbonadoError::OutboardVerificationFailed(_)),
        "short signature write must fail, got {err3:?}"
    );
}

#[cfg(feature = "ots")]
#[test]
fn directory_ots_entry_and_catalog_under_lean() {
    require_lean_lib();
    let src = tempdir("ots_src");
    fs::write(src.join("one.txt"), b"phase4 ots lean payload").expect("write");

    let enc_dir = tempdir("ots_enc");
    let dec_dir = tempdir("ots_dec");
    let options = DirectoryEncodeOptions {
        ots_policy: Some(OtsPolicy {
            stamp_entries: true,
            stamp_catalog: true,
        }),
        ..DirectoryEncodeOptions::default()
    };
    let archive =
        encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let catalog_bytes = fs::read(&catalog_path).expect("read catalog");
    assert!(
        catalog_bytes.windows(4).any(|w| w == b"COTS"),
        "catalog must contain COTS trailer when stamp_catalog is set"
    );

    let (_, body) = carbonado::file::decode(&ZERO_KEY, &catalog_bytes).expect("headered decode");
    let (adam_payload, hdr) = decode_adamantine(&body).expect("adam");
    assert_ne!(
        hdr.flags & ADAMANTINE_FLAG_REQUIRE_OTS,
        0,
        "REQUIRE_OTS must be set when stamp_entries"
    );
    let (rkyv, _) = split_adamantine_payload(&adam_payload).expect("split");
    let index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    let proof = index.entries[0].ots_proof.as_ref().expect("entry ots");
    let primary_root = index.entries[0].segments[0].segment_bao_root;
    assert!(
        verify_stamp(proof, &primary_root)
            .expect("verify entry")
            .valid,
        "entry OTS must verify primary segment Bao root"
    );
    let catalog_ots = catalog_ots_proof_from_cots_trailer(&catalog_bytes).expect("catalog ots");
    assert!(
        verify_stamp(&catalog_ots, &archive.catalog_bao_root)
            .expect("verify catalog")
            .valid,
        "catalog OTS must verify catalog Bao root"
    );

    decode_directory(&ZERO_KEY, &catalog_path, &dec_dir).expect("decode_directory");
    assert_eq!(
        fs::read(dec_dir.join("one.txt")).expect("read"),
        b"phase4 ots lean payload"
    );
}

#[cfg(feature = "ots")]
#[test]
fn directory_ots_tampered_entry_fails_under_lean() {
    require_lean_lib();
    let src = tempdir("ots_tamper_src");
    fs::write(src.join("one.txt"), b"tamper me lean").expect("write");
    let enc_dir = tempdir("ots_tamper_enc");
    let dec_dir = tempdir("ots_tamper_dec");
    let options = DirectoryEncodeOptions {
        ots_policy: Some(OtsPolicy {
            stamp_entries: true,
            stamp_catalog: false,
        }),
        ..DirectoryEncodeOptions::default()
    };
    let archive =
        encode_directory_with_options(&ZERO_KEY, &src, &enc_dir, options).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );

    let (_, body) = carbonado::file::decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read"))
        .expect("decode");
    let (adam_payload, hdr) = decode_adamantine(&body).expect("adam");
    let (rkyv, bundle) = split_adamantine_payload(&adam_payload).expect("split");
    let mut index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    let proof = index.entries[0].ots_proof.as_mut().expect("proof");
    if let Some(byte) = proof.first_mut() {
        *byte ^= 0xFF;
    }
    let tampered_rkyv = index.to_bytes().expect("to_bytes");
    let tampered_payload = build_adamantine_payload(&tampered_rkyv, &bundle).expect("payload");
    let tampered_adam = encode_adamantine(
        &tampered_payload,
        ADAMANTINE_CARBONADO_FMT_PUBLIC,
        hdr.flags,
    );
    let (tampered_encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &tampered_adam, DIRECTORY_ARCHIVE_FORMAT, None)
            .expect("re-encode");
    let tampered_header = Header::try_from(&tampered_encoded[..Header::LEN]).expect("header");
    let tampered_root = *tampered_header.hash.as_bytes();
    let tampered_catalog = adam_catalog_path(&enc_dir, &tampered_root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&tampered_catalog, &tampered_encoded).expect("write tampered");

    let err = decode_directory(&ZERO_KEY, &tampered_catalog, &dec_dir).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::OtsVerificationFailed),
        "tampered entry OTS must be OtsVerificationFailed, got {err:?}"
    );
}

#[cfg(feature = "ots")]
#[test]
fn directory_ots_missing_when_required_fails_under_lean() {
    require_lean_lib();
    let src = tempdir("ots_req_src");
    fs::write(src.join("one.txt"), b"x").expect("write");
    let enc_dir = tempdir("ots_req_enc");
    let archive = encode_directory(&ZERO_KEY, &src, &enc_dir).expect("encode");
    let catalog_path = adam_catalog_path(
        &enc_dir,
        &archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let (_, body) = carbonado::file::decode(&ZERO_KEY, &fs::read(&catalog_path).expect("read"))
        .expect("decode");
    let (adam_payload, _) = decode_adamantine(&body).expect("adam");
    let (rkyv, bundle) = split_adamantine_payload(&adam_payload).expect("split");
    let mut index =
        FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root).expect("index");
    index.entries[0].ots_proof = None;
    let payload = build_adamantine_payload(&index.to_bytes().expect("bytes"), &bundle).expect("p");
    let adam = encode_adamantine(
        &payload,
        ADAMANTINE_CARBONADO_FMT_PUBLIC,
        ADAMANTINE_FLAG_REQUIRE_OTS,
    );
    let (encoded, _) =
        carbonado::file::encode(&ZERO_KEY, &adam, DIRECTORY_ARCHIVE_FORMAT, None).expect("enc");
    let header = Header::try_from(&encoded[..Header::LEN]).expect("hdr");
    let root = *header.hash.as_bytes();
    let bad_catalog = adam_catalog_path(&enc_dir, &root, DIRECTORY_ARCHIVE_FORMAT);
    fs::write(&bad_catalog, &encoded).expect("write");
    let err = decode_directory(&ZERO_KEY, &bad_catalog, &tempdir("ots_req_dec")).unwrap_err();
    assert!(
        matches!(
            err,
            CarbonadoError::OtsProofRequired(ref rel) if rel == "one.txt"
        ),
        "expected OtsProofRequired(one.txt), got {err:?}"
    );
}

/// CLI-shaped library paths under lean — engines called out per half.
#[test]
fn cli_library_encode_decode_paths_under_lean() {
    require_lean_lib();

    // --- Cross-engine (mirrors CLI single-file inboard wire assembly) ---
    // Encode: pure-Rust `encode_stream` (same as bin/carbonado; no stream→Lean dispatch).
    // Decode: Lean headered `file::decode` (G9-style rust-encode → lean-decode).
    let input = b"phase4 cli library single-file lean";
    let mut body_bytes = Vec::new();
    let (enc_hdr, _info) = encode_stream(&ZERO_KEY, &mut &input[..], 14, None, &mut body_bytes)
        .expect("encode_stream");
    assert_eq!(enc_hdr.hash.as_bytes().len(), 32);
    assert!(!body_bytes.is_empty());
    let mut archive = enc_hdr.try_to_vec().expect("header wire");
    archive.extend_from_slice(&body_bytes);

    let (hdr, body) = carbonado::file::decode(&ZERO_KEY, &archive).expect("lean headered decode");
    assert_eq!(hdr.hash, enc_hdr.hash);
    assert_eq!(body, input);

    // --- Same-engine dual path (buffer API the CLI does *not* use for streaming) ---
    // `file::encode` under backend-lean → Lean `carbonado_encode_headered`.
    let (lean_archive, _) =
        carbonado::file::encode(&ZERO_KEY, input, 14, None).expect("lean file::encode");
    let (lean_hdr, lean_body) =
        carbonado::file::decode(&ZERO_KEY, &lean_archive).expect("lean file::decode");
    assert_eq!(lean_hdr.format.bits(), 14);
    assert_eq!(lean_body, input);

    // --- Directory path (CLI `encode <dir>` / `decode .adam.c14`) — dual-engine ---
    let src = tempdir("cli_lib_src");
    fs::write(src.join("hi.txt"), b"cli dir lean").expect("write");
    let enc = tempdir("cli_lib_enc");
    let dir_archive = encode_directory(&ZERO_KEY, &src, &enc).expect("encode_directory");
    let catalog = adam_catalog_path(
        &enc,
        &dir_archive.catalog_bao_root,
        DIRECTORY_ARCHIVE_FORMAT,
    );
    let dec = tempdir("cli_lib_dec");
    decode_directory(&ZERO_KEY, &catalog, &dec).expect("decode_directory");
    assert_eq!(fs::read(dec.join("hi.txt")).expect("read"), b"cli dir lean");
}

/// Encrypted directory under lean (CLI `--encrypted --master`).
#[test]
fn cli_library_encrypted_directory_under_lean() {
    require_lean_lib();
    let src = tempdir("cli_enc_src");
    fs::write(src.join("secret.txt"), b"encrypted cli lean").expect("write");
    let enc = tempdir("cli_enc_enc");
    let options = DirectoryEncodeOptions {
        encrypted: true,
        ..Default::default()
    };
    let archive = encode_directory_with_options(&TEST_MASTER, &src, &enc, options).expect("enc");
    let catalog = adam_catalog_path(&enc, &archive.catalog_bao_root, 0x0F);
    let dec = tempdir("cli_enc_dec");
    decode_directory(&TEST_MASTER, &catalog, &dec).expect("dec");
    assert_eq!(
        fs::read(dec.join("secret.txt")).expect("read"),
        b"encrypted cli lean"
    );
}

/// Lean-linked binary: single-file `--outboard` is **link/smoke only** (pure Rust streaming).
/// Does **not** exercise Lean C ABI — see `cli_subprocess_directory_roundtrip_under_lean`.
#[cfg(feature = "cli")]
#[test]
fn cli_subprocess_single_file_link_smoke_under_lean() {
    require_lean_lib();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_carbonado"));
    assert!(
        bin.is_file(),
        "carbonado binary missing at {} — build with features backend-lean,cli",
        bin.display()
    );

    let work = tempdir("cli_sub_sf");
    let input = work.join("input.txt");
    let outdir = work.join("enc");
    let recovered = work.join("recovered.bin");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(&input, b"phase4 subprocess single-file link smoke").expect("write");

    let enc = std::process::Command::new(&bin)
        .args([
            "encode",
            input.to_str().unwrap(),
            "--format",
            "14",
            "--outboard",
            "--output",
            outdir.to_str().unwrap(),
        ])
        .env(
            "LD_LIBRARY_PATH",
            std::env::var_os("LD_LIBRARY_PATH").unwrap_or_default(),
        )
        .output()
        .expect("spawn encode");
    assert!(
        enc.status.success(),
        "encode failed: status={:?} stderr={}",
        enc.status,
        String::from_utf8_lossy(&enc.stderr)
    );

    // One bare main archive (not .out/.par)
    let archive = fs::read_dir(&outdir)
        .expect("read")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| !n.ends_with(".out") && !n.ends_with(".par"))
        })
        .expect("archive main missing");

    let dec = std::process::Command::new(&bin)
        .args([
            "decode",
            archive.to_str().unwrap(),
            "--output",
            recovered.to_str().unwrap(),
        ])
        .env(
            "LD_LIBRARY_PATH",
            std::env::var_os("LD_LIBRARY_PATH").unwrap_or_default(),
        )
        .output()
        .expect("spawn decode");
    assert!(
        dec.status.success(),
        "decode failed: status={:?} stderr={}",
        dec.status,
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(
        fs::read(&recovered).expect("read recovered"),
        b"phase4 subprocess single-file link smoke"
    );
}

/// Dual-engine CLI subprocess: directory encode/decode hits Lean segment/catalog crypto.
#[cfg(feature = "cli")]
#[test]
fn cli_subprocess_directory_roundtrip_under_lean() {
    require_lean_lib();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_carbonado"));
    assert!(
        bin.is_file(),
        "carbonado binary missing at {} — build with features backend-lean,cli",
        bin.display()
    );

    let work = tempdir("cli_sub_dir");
    let src = work.join("src");
    let outdir = work.join("enc");
    let recovered = work.join("recovered");
    fs::create_dir_all(&src).expect("src");
    fs::create_dir_all(&outdir).expect("outdir");
    fs::write(src.join("hi.txt"), b"phase4 subprocess directory lean").expect("write");

    let enc = std::process::Command::new(&bin)
        .args([
            "encode",
            src.to_str().unwrap(),
            "--output",
            outdir.to_str().unwrap(),
        ])
        .env(
            "LD_LIBRARY_PATH",
            std::env::var_os("LD_LIBRARY_PATH").unwrap_or_default(),
        )
        .output()
        .expect("spawn directory encode");
    assert!(
        enc.status.success(),
        "directory encode failed: status={:?} stderr={}",
        enc.status,
        String::from_utf8_lossy(&enc.stderr)
    );

    let catalog = fs::read_dir(&outdir)
        .expect("read enc")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.is_file()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".adam.c14"))
        })
        .expect("catalog .adam.c14 missing");

    let dec = std::process::Command::new(&bin)
        .args([
            "decode",
            catalog.to_str().unwrap(),
            "--output",
            recovered.to_str().unwrap(),
        ])
        .env(
            "LD_LIBRARY_PATH",
            std::env::var_os("LD_LIBRARY_PATH").unwrap_or_default(),
        )
        .output()
        .expect("spawn directory decode");
    assert!(
        dec.status.success(),
        "directory decode failed: status={:?} stderr={}",
        dec.status,
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(
        fs::read(recovered.join("hi.txt")).expect("read recovered"),
        b"phase4 subprocess directory lean"
    );
}

#[cfg(feature = "ots")]
fn catalog_ots_proof_from_cots_trailer(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < Header::LEN + 8 {
        return None;
    }
    let max_scan = carbonado::filepack_manifest::MAX_OTS_PROOF_LEN + 8;
    let scan_start = bytes.len().saturating_sub(max_scan).max(Header::LEN);
    for i in (scan_start..=bytes.len().saturating_sub(8)).rev() {
        if bytes.get(i..i + 4)? != b"COTS" {
            continue;
        }
        let ots_len = u32::from_le_bytes(bytes[i + 4..i + 8].try_into().ok()?) as usize;
        if ots_len > carbonado::filepack_manifest::MAX_OTS_PROOF_LEN {
            return None;
        }
        if i + 8 + ots_len == bytes.len() {
            return Some(bytes[i + 8..].to_vec());
        }
    }
    None
}
