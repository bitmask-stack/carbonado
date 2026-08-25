//! Wave 2 / **W2d**: codecode (EDE) + decodec (DED) determinism contracts.
//!
//! ## Contracts (normative)
//!
//! | Contract | Steps | Assert |
//! |----------|-------|--------|
//! | **codecode** (EDE) | encode → decode → encode | `pt' == pt` and `A' == A` under fixed pins |
//! | **decodec** (DED) | decode archive A → encode → decode | `pt' == pt` and `B == A` when encode is deterministic |
//!
//! Pins: same MASTER / NONCE / plaintext as G9 (`g9_matrix_v1`). Encrypted formats
//! use fixed `NONCE` so wire identity is in scope.
//!
//! ## Matrix (no-compress — full wire equality)
//!
//! | Layout | Formats |
//! |--------|---------|
//! | body | c0, c1, c4, c5, c8, c9, c12, c13 |
//! | headered | c4, c5, c12, c13 |
//! | outboard | c4, c5, c12, c13 |
//!
//! ## Compression (**W2a** — same-engine determinism only)
//!
//! Body + headered + outboard compress formats (public + fixed-nonce encrypted):
//! same-engine codecode/decodec require `A' == A`. **Cross-backend** encode
//! bit-match is a **permanent residual** (LIMITS / GAPS): Lean AOT zstd frames
//! differ from Rust `zstd` (measured on G9 `outboard_c14` mains; hard-asserted).
//!
//! ## Directory (**W2b**)
//!
//! Same-engine catalog+segment codecode/decodec under pinned options. Cross-engine
//! encode residual is **live rust root vs historical Lean AOT catalog pin**.
//! `tests/fixtures/phase3_g9_directory` matches live rust encode after catalog
//! bundle append follows sorted `rel_path` (not `read_dir` order).

use std::fs;
use std::path::{Path, PathBuf};

use carbonado::{
    OutboardEncoded, constants::Format, decode, decode_outboard, encode_with_nonce, file,
    stream_encode_outboard_buffer, structs::Encoded,
};

/// Same master as G9 / Phase 2.
const MASTER: [u8; 32] = [
    0x0c, 0xa1, 0xb0, 0xda, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
];

/// Fixed 16-byte nonce for encrypted pins (G9 / Phase 2).
const NONCE: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

/// Same plaintext as G9 matrix (`plaintext_id = g9_matrix_v1`).
const PLAINTEXT: &[u8] = b"g9 cross-backend matrix v1";

/// No-compress body formats (G9-green).
const BODY_NO_COMPRESS: &[u8] = &[0, 1, 4, 5, 8, 9, 12, 13];
/// Headered no-compress subset.
const HEADERED_NO_COMPRESS: &[u8] = &[4, 5, 12, 13];
/// Outboard no-compress subset.
const OUTBOARD_NO_COMPRESS: &[u8] = &[4, 5, 12, 13];

/// Compression body formats for same-engine W2a determinism (public + encrypted fixed-nonce).
const BODY_COMPRESS: &[u8] = &[2, 3, 6, 7, 10, 11, 14, 15];
/// Headered compress subset (Verification + Compression; public + encrypted).
const HEADERED_COMPRESS: &[u8] = &[6, 7, 14, 15];
/// Outboard compress subset (public + encrypted header-path).
const OUTBOARD_COMPRESS: &[u8] = &[6, 7, 14, 15];

/// Live `backend-rust` catalog Bao root for [`dir_files`] + zero master + default options.
///
/// Matches [`PHASE3_SEED_DIR_CATALOG_ROOT`]: encode sorts by `rel_path` before appending
/// verification outboard / FEC (`a.txt` then `sub/b.bin`).
const LIVE_RUST_DIR_CATALOG_ROOT: &str =
    "16e2369f4f4465014e5e92740e3f76403f681cd60c01f7605ee11acd5423024f";

/// Historical Lean AOT catalog Bao root for the same tree/options as [`LIVE_RUST_DIR_CATALOG_ROOT`].
const LIVE_LEAN_DIR_CATALOG_ROOT: &str =
    "d468ea7a9e8afc13f3c4a533c0d9614ecc6d032dae2255013bcf433c592e07b5";

/// Committed phase3 G9 directory catalog root. Live rust encode of [`dir_files`] matches this
/// seed once the catalog bundle is appended in sorted `rel_path` order.
const PHASE3_SEED_DIR_CATALOG_ROOT: &str =
    "16e2369f4f4465014e5e92740e3f76403f681cd60c01f7605ee11acd5423024f";

fn is_encrypted(format: u8) -> bool {
    Format::from(format).contains(Format::Encryption)
}

fn nonce_for(format: u8) -> Option<[u8; 16]> {
    if is_encrypted(format) {
        Some(NONCE)
    } else {
        None
    }
}

fn active_engine() -> &'static str {
    "rust"
}

// ---------------------------------------------------------------------------
// Body helpers
// ---------------------------------------------------------------------------

fn encode_body(format: u8, pt: &[u8]) -> (Vec<u8>, [u8; 32], u32) {
    let Encoded(body, hash, info) = encode_with_nonce(&MASTER, pt, format, nonce_for(format))
        .unwrap_or_else(|e| panic!("[{}] encode body c{format}: {e}", active_engine()));
    (body, *hash.as_bytes(), info.padding_len)
}

fn decode_body(format: u8, body: &[u8], hash: &[u8; 32], pad: u32) -> Vec<u8> {
    decode(&MASTER, hash, body, pad, format)
        .unwrap_or_else(|e| panic!("[{}] decode body c{format}: {e}", active_engine()))
}

/// codecode: E → D → E; assert pt' and A' == A.
fn codecode_body(format: u8, pt: &[u8]) {
    let (a, hash, pad) = encode_body(format, pt);
    let pt1 = decode_body(format, &a, &hash, pad);
    assert_eq!(
        pt1,
        pt,
        "[{}] codecode body c{format}: pt' != pt",
        active_engine()
    );
    let (a2, hash2, pad2) = encode_body(format, &pt1);
    assert_eq!(
        a2,
        a,
        "[{}] codecode body c{format}: A' != A (wire)",
        active_engine()
    );
    assert_eq!(
        hash2,
        hash,
        "[{}] codecode body c{format}: hash",
        active_engine()
    );
    assert_eq!(
        pad2,
        pad,
        "[{}] codecode body c{format}: pad",
        active_engine()
    );
}

/// decodec: start from A, D → E → D; assert pt' and B == A.
fn decodec_body(format: u8, pt: &[u8]) {
    let (a, hash, pad) = encode_body(format, pt);
    let pt1 = decode_body(format, &a, &hash, pad);
    assert_eq!(pt1, pt, "[{}] decodec body c{format}: pt", active_engine());
    let (b, hash_b, pad_b) = encode_body(format, &pt1);
    assert_eq!(
        b,
        a,
        "[{}] decodec body c{format}: B != A (wire)",
        active_engine()
    );
    let pt2 = decode_body(format, &b, &hash_b, pad_b);
    assert_eq!(
        pt2,
        pt,
        "[{}] decodec body c{format}: pt' after re-encode",
        active_engine()
    );
}

// ---------------------------------------------------------------------------
// Headered helpers
// ---------------------------------------------------------------------------

fn encode_headered(format: u8, pt: &[u8]) -> Vec<u8> {
    let (archive, _) = file::encode_with_nonce(&MASTER, pt, format, None, nonce_for(format))
        .unwrap_or_else(|e| panic!("[{}] encode headered c{format}: {e}", active_engine()));
    archive
}

fn decode_headered(archive: &[u8]) -> (file::Header, Vec<u8>) {
    file::decode(&MASTER, archive)
        .unwrap_or_else(|e| panic!("[{}] decode headered: {e}", active_engine()))
}

fn codecode_headered(format: u8, pt: &[u8]) {
    let a = encode_headered(format, pt);
    let (hdr, pt1) = decode_headered(&a);
    assert_eq!(
        pt1,
        pt,
        "[{}] codecode headered c{format}: pt'",
        active_engine()
    );
    assert_eq!(hdr.format.bits(), format);
    let a2 = encode_headered(format, &pt1);
    assert_eq!(
        a2,
        a,
        "[{}] codecode headered c{format}: A' != A",
        active_engine()
    );
}

fn decodec_headered(format: u8, pt: &[u8]) {
    let a = encode_headered(format, pt);
    let (_, pt1) = decode_headered(&a);
    assert_eq!(pt1, pt);
    let b = encode_headered(format, &pt1);
    assert_eq!(
        b,
        a,
        "[{}] decodec headered c{format}: B != A",
        active_engine()
    );
    let (_, pt2) = decode_headered(&b);
    assert_eq!(pt2, pt);
}

// ---------------------------------------------------------------------------
// Outboard helpers
// ---------------------------------------------------------------------------

struct OutboardWire {
    oenc: OutboardEncoded,
    header: Option<Vec<u8>>,
}

fn encode_outboard_wire(format: u8, pt: &[u8]) -> OutboardWire {
    if is_encrypted(format) {
        let oenc = stream_encode_outboard_buffer(&MASTER, pt, format, Some(NONCE))
            .unwrap_or_else(|e| panic!("[{}] outboard enc c{format}: {e}", active_engine()));
        let hdr = file::Header::new(
            &MASTER,
            NONCE,
            oenc.hash.as_bytes(),
            [0u8; 32],
            Format::from(format),
            0,
            oenc.info.bytes_verifiable,
            oenc.info.padding_len,
            None,
        )
        .expect("header for outboard");
        let hdr_bytes = hdr.try_to_vec().expect("hdr vec");
        OutboardWire {
            oenc,
            header: Some(hdr_bytes),
        }
    } else {
        let oenc = carbonado::encode_outboard(&MASTER, pt, format)
            .unwrap_or_else(|e| panic!("[{}] outboard pub c{format}: {e}", active_engine()));
        OutboardWire { oenc, header: None }
    }
}

fn decode_outboard_wire(format: u8, w: &OutboardWire) -> Vec<u8> {
    if is_encrypted(format) {
        file::decode_outboard(
            &MASTER,
            w.oenc.hash.as_bytes(),
            w.header.as_deref(),
            &w.oenc.main,
            w.oenc.verification_outboard.as_deref(),
            w.oenc.fec_parity.as_deref(),
            w.oenc.info.padding_len,
            format,
        )
        .unwrap_or_else(|e| panic!("[{}] decode outboard enc c{format}: {e}", active_engine()))
    } else {
        decode_outboard(
            &MASTER,
            w.oenc.hash.as_bytes(),
            &w.oenc.main,
            w.oenc.verification_outboard.as_deref(),
            w.oenc.fec_parity.as_deref(),
            w.oenc.info.padding_len,
            format,
        )
        .unwrap_or_else(|e| panic!("[{}] decode outboard pub c{format}: {e}", active_engine()))
    }
}

fn assert_outboard_wire_eq(label: &str, format: u8, a: &OutboardWire, b: &OutboardWire) {
    assert_eq!(
        a.oenc.main,
        b.oenc.main,
        "[{}] {label} outboard c{format}: main",
        active_engine()
    );
    assert_eq!(
        a.oenc.verification_outboard.as_deref(),
        b.oenc.verification_outboard.as_deref(),
        "[{}] {label} outboard c{format}: verification_outboard",
        active_engine()
    );
    assert_eq!(
        a.oenc.fec_parity.as_deref(),
        b.oenc.fec_parity.as_deref(),
        "[{}] {label} outboard c{format}: fec_parity",
        active_engine()
    );
    assert_eq!(
        a.oenc.hash.as_bytes(),
        b.oenc.hash.as_bytes(),
        "[{}] {label} outboard c{format}: hash",
        active_engine()
    );
    assert_eq!(
        a.oenc.info.padding_len,
        b.oenc.info.padding_len,
        "[{}] {label} outboard c{format}: pad",
        active_engine()
    );
    assert_eq!(
        a.header.as_deref(),
        b.header.as_deref(),
        "[{}] {label} outboard c{format}: header",
        active_engine()
    );
}

fn codecode_outboard(format: u8, pt: &[u8]) {
    let a = encode_outboard_wire(format, pt);
    let pt1 = decode_outboard_wire(format, &a);
    assert_eq!(
        pt1,
        pt,
        "[{}] codecode outboard c{format}: pt'",
        active_engine()
    );
    let a2 = encode_outboard_wire(format, &pt1);
    assert_outboard_wire_eq("codecode", format, &a, &a2);
}

fn decodec_outboard(format: u8, pt: &[u8]) {
    let a = encode_outboard_wire(format, pt);
    let pt1 = decode_outboard_wire(format, &a);
    assert_eq!(pt1, pt);
    let b = encode_outboard_wire(format, &pt1);
    assert_outboard_wire_eq("decodec", format, &a, &b);
    let pt2 = decode_outboard_wire(format, &b);
    assert_eq!(pt2, pt);
}

// ---------------------------------------------------------------------------
// W2d — no-compress matrix
// ---------------------------------------------------------------------------

#[test]
fn codecode_body_no_compress_matrix() {
    for &format in BODY_NO_COMPRESS {
        codecode_body(format, PLAINTEXT);
    }
}

#[test]
fn decodec_body_no_compress_matrix() {
    for &format in BODY_NO_COMPRESS {
        decodec_body(format, PLAINTEXT);
    }
}

#[test]
fn codecode_headered_no_compress_matrix() {
    for &format in HEADERED_NO_COMPRESS {
        codecode_headered(format, PLAINTEXT);
    }
}

#[test]
fn decodec_headered_no_compress_matrix() {
    for &format in HEADERED_NO_COMPRESS {
        decodec_headered(format, PLAINTEXT);
    }
}

#[test]
fn codecode_outboard_no_compress_matrix() {
    for &format in OUTBOARD_NO_COMPRESS {
        codecode_outboard(format, PLAINTEXT);
    }
}

#[test]
fn decodec_outboard_no_compress_matrix() {
    for &format in OUTBOARD_NO_COMPRESS {
        decodec_outboard(format, PLAINTEXT);
    }
}

// ---------------------------------------------------------------------------
// W2a — compression same-engine codecode/decodec (wire equality on one engine)
// ---------------------------------------------------------------------------

#[test]
fn codecode_body_compress_same_engine() {
    for &format in BODY_COMPRESS {
        codecode_body(format, PLAINTEXT);
    }
}

#[test]
fn decodec_body_compress_same_engine() {
    for &format in BODY_COMPRESS {
        decodec_body(format, PLAINTEXT);
    }
}

#[test]
fn codecode_headered_compress_same_engine() {
    for &format in HEADERED_COMPRESS {
        codecode_headered(format, PLAINTEXT);
    }
}

#[test]
fn decodec_headered_compress_same_engine() {
    for &format in HEADERED_COMPRESS {
        decodec_headered(format, PLAINTEXT);
    }
}

#[test]
fn codecode_outboard_compress_same_engine() {
    for &format in OUTBOARD_COMPRESS {
        codecode_outboard(format, PLAINTEXT);
    }
}

#[test]
fn decodec_outboard_compress_same_engine() {
    for &format in OUTBOARD_COMPRESS {
        decodec_outboard(format, PLAINTEXT);
    }
}

/// Documented residual: rust↔lean Compression encode is **not** bit-identical.
///
/// Evidence from committed G9 fixtures (`tests/fixtures/g9/{rust,lean}/outboard_c14/`):
/// - both mains 35 bytes; frame descriptor differs (`28b5 2ffd 00…` vs `28b5 2ffd 20…`)
/// - Bao roots differ (`0abe5781…` vs `129b4518…`)
/// - FEC parity shards differ (same length 16384)
///
/// Decode interop remains green (`g9_cross_backend` outboard_c14 both directions).
/// Re-encode bit-match across engines is permanently out of scope (LIMITS W2a).
/// Fail-closed if fixtures are stripped (permanent residual must stay assertable).
#[test]
fn compress_cross_engine_encode_not_bit_identical_documented() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/g9");
    let rust_main = root.join("rust/outboard_c14/main.bin");
    let lean_main = root.join("lean/outboard_c14/main.bin");
    assert!(
        rust_main.is_file(),
        "missing committed W2a residual fixture {}",
        rust_main.display()
    );
    assert!(
        lean_main.is_file(),
        "missing committed W2a residual fixture {}",
        lean_main.display()
    );
    let r = fs::read(&rust_main).expect("rust main");
    let l = fs::read(&lean_main).expect("lean main");
    assert_eq!(
        r.len(),
        l.len(),
        "c14 mains same length (frame residual, not size)"
    );
    assert_ne!(
        r, l,
        "W2a residual evidence: rust vs lean c14 main must still differ \
         (if this fails, re-check zstd alignment — residual may have closed)"
    );
    // Frame magic is zstd in both; descriptor byte (offset 4) is the known diverge point.
    assert_eq!(&r[..4], b"\x28\xb5\x2f\xfd");
    assert_eq!(&l[..4], b"\x28\xb5\x2f\xfd");
    assert_ne!(
        r[4], l[4],
        "expected zstd frame descriptor byte to differ (measured residual)"
    );
}

// ---------------------------------------------------------------------------
// W2d optional strength: DED starting from committed G9 goldens (no-compress body)
// ---------------------------------------------------------------------------

/// decodec from **committed** G9 body goldens for the active engine (not live-encode A).
///
/// Complements live-encode DED matrices: proves re-encode of decoded fixture plaintext
/// bit-matches the golden wire under the same pins.
#[test]
fn decodec_body_from_g9_fixture_no_compress() {

    let engine = active_engine();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/g9")
        .join(engine);

    for &format in BODY_NO_COMPRESS {
        let name = format!("body_c{format}");
        let body_path = root.join(format!("{name}.bin"));
        let meta_path = root.join(format!("{name}.meta.json"));
        assert!(
            body_path.is_file(),
            "missing G9 golden {}",
            body_path.display()
        );
        assert!(
            meta_path.is_file(),
            "missing G9 meta {}",
            meta_path.display()
        );
        let a = fs::read(&body_path).expect("read golden body");
        let meta: serde_json::Value =
            serde_json::from_slice(&fs::read(&meta_path).expect("read meta")).expect("meta json");
        let hash_hex = meta["hash_hex"].as_str().expect("hash_hex");
        let pad = meta["padding_len"].as_u64().expect("padding_len") as u32;
        let mut hash = [0u8; 32];
        let hb = from_hex(hash_hex);
        assert_eq!(hb.len(), 32);
        hash.copy_from_slice(&hb);

        let pt = decode_body(format, &a, &hash, pad);
        assert_eq!(pt, PLAINTEXT, "[{engine}] golden body c{format} plaintext");
        let (b, hash_b, pad_b) = encode_body(format, &pt);
        assert_eq!(
            b, a,
            "[{engine}] DED from G9 golden: re-encode must bit-match body_c{format}"
        );
        assert_eq!(hash_b, hash);
        assert_eq!(pad_b, pad);
        let pt2 = decode_body(format, &b, &hash_b, pad_b);
        assert_eq!(pt2, PLAINTEXT);
    }
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// W2b — directory same-engine codecode/decodec
// ---------------------------------------------------------------------------

fn tempdir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "carbonado-w2-{}-{}-{}",
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

fn write_tree(src: &Path, files: &[(&str, &[u8])]) {
    for (rel, data) in files {
        let path = src.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(&path, data).expect("write");
    }
}

fn read_tree_file(dec: &Path, rel: &str) -> Vec<u8> {
    fs::read(dec.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn list_archive_artifacts(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).expect("read_dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_file() {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = fs::read(&path).expect("read artifact");
            out.push((name, bytes));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Public directory uses conventional zero master (matches phase3 G9 seed).
const ZERO_MASTER: [u8; 32] = [0u8; 32];

/// Public directory encode with default policy (matches phase3 G9 seed shape).
fn dir_files() -> [(&'static str, &'static [u8]); 2] {
    [("a.txt", b"phase3 g9 hello"), ("sub/b.bin", b"nested data")]
}

#[test]
fn codecode_directory_public_same_engine() {

    let src = tempdir("dir_src");
    write_tree(&src, &dir_files());

    let enc1 = tempdir("dir_enc1");
    let arch1 = file::encode_directory(&ZERO_MASTER, &src, &enc1)
        .unwrap_or_else(|e| panic!("[{}] dir encode1: {e}", active_engine()));
    let artifacts1 = list_archive_artifacts(&enc1);

    let dec = tempdir("dir_dec");
    let catalog1 = enc1.join(format!(
        "{}.adam.c{}",
        hex32(&arch1.catalog_bao_root),
        file::DIRECTORY_ARCHIVE_FORMAT
    ));
    file::decode_directory(&ZERO_MASTER, &catalog1, &dec)
        .unwrap_or_else(|e| panic!("[{}] dir decode1: {e}", active_engine()));
    assert_eq!(read_tree_file(&dec, "a.txt"), b"phase3 g9 hello");
    assert_eq!(read_tree_file(&dec, "sub/b.bin"), b"nested data");

    // codecode: re-encode from extracted tree → same roots + wire bytes
    let enc2 = tempdir("dir_enc2");
    let arch2 = file::encode_directory(&ZERO_MASTER, &dec, &enc2)
        .unwrap_or_else(|e| panic!("[{}] dir encode2: {e}", active_engine()));
    assert_eq!(
        arch2.catalog_bao_root,
        arch1.catalog_bao_root,
        "[{}] directory codecode: catalog root must match",
        active_engine()
    );
    assert_eq!(arch2.entry_count, arch1.entry_count);
    let artifacts2 = list_archive_artifacts(&enc2);
    assert_eq!(
        artifacts2,
        artifacts1,
        "[{}] directory codecode: full archive tree must bit-match",
        active_engine()
    );

    let _ = fs::remove_dir_all(&src);
    let _ = fs::remove_dir_all(&enc1);
    let _ = fs::remove_dir_all(&enc2);
    let _ = fs::remove_dir_all(&dec);
}

#[test]
fn decodec_directory_public_same_engine() {

    let src = tempdir("dir_src_ded");
    write_tree(&src, &dir_files());

    let enc_a = tempdir("dir_enc_a");
    let arch_a = file::encode_directory(&ZERO_MASTER, &src, &enc_a)
        .unwrap_or_else(|e| panic!("[{}] dir encode A: {e}", active_engine()));
    let artifacts_a = list_archive_artifacts(&enc_a);

    let dec = tempdir("dir_dec_ded");
    let catalog = enc_a.join(format!(
        "{}.adam.c{}",
        hex32(&arch_a.catalog_bao_root),
        file::DIRECTORY_ARCHIVE_FORMAT
    ));
    file::decode_directory(&ZERO_MASTER, &catalog, &dec)
        .unwrap_or_else(|e| panic!("[{}] dir decode: {e}", active_engine()));

    // decodec: D → E → D; B == A wire
    let enc_b = tempdir("dir_enc_b");
    let arch_b = file::encode_directory(&ZERO_MASTER, &dec, &enc_b)
        .unwrap_or_else(|e| panic!("[{}] dir encode B: {e}", active_engine()));
    assert_eq!(arch_b.catalog_bao_root, arch_a.catalog_bao_root);
    let artifacts_b = list_archive_artifacts(&enc_b);
    assert_eq!(
        artifacts_b,
        artifacts_a,
        "[{}] directory decodec: B != A wire",
        active_engine()
    );

    let dec2 = tempdir("dir_dec2");
    let catalog_b = enc_b.join(format!(
        "{}.adam.c{}",
        hex32(&arch_b.catalog_bao_root),
        file::DIRECTORY_ARCHIVE_FORMAT
    ));
    file::decode_directory(&ZERO_MASTER, &catalog_b, &dec2)
        .unwrap_or_else(|e| panic!("[{}] dir decode2: {e}", active_engine()));
    assert_eq!(read_tree_file(&dec2, "a.txt"), b"phase3 g9 hello");
    assert_eq!(read_tree_file(&dec2, "sub/b.bin"), b"nested data");

    let _ = fs::remove_dir_all(&src);
    let _ = fs::remove_dir_all(&enc_a);
    let _ = fs::remove_dir_all(&enc_b);
    let _ = fs::remove_dir_all(&dec);
    let _ = fs::remove_dir_all(&dec2);
}

/// W2b residual canary: **live-vs-live** catalog roots under identical pins.
///
/// Compares pinned live rust encode root vs pinned live lean encode root for
/// [`dir_files`] + zero master + default options. Live rust matches the committed
/// `phase3_g9_directory` catalog (sorted `rel_path` bundle append). Cross-engine
/// residual is rust vs lean catalog bytes (zstd / catalog packaging), not readdir order.
///
/// Hard asserts:
/// - active engine live root matches its pin (`LIVE_RUST_*` / `LIVE_LEAN_*`)
/// - `LIVE_RUST_DIR_CATALOG_ROOT != LIVE_LEAN_DIR_CATALOG_ROOT` (cross-engine residual)
/// - live rust root equals the phase3 seed catalog
/// - seed catalog file still present (decode SSOT)
#[test]
fn directory_cross_engine_live_roots_residual() {

    // Pin table integrity: residual is live rust vs live lean, not readdir drift.
    assert_ne!(
        LIVE_RUST_DIR_CATALOG_ROOT, LIVE_LEAN_DIR_CATALOG_ROOT,
        "W2b residual pin table: live rust and live lean catalog roots must differ"
    );
    assert_eq!(
        LIVE_RUST_DIR_CATALOG_ROOT, PHASE3_SEED_DIR_CATALOG_ROOT,
        "live rust directory encode must match the phase3_g9_directory catalog seed"
    );

    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/phase3_g9_directory");
    let seed_catalog = fixture.join(format!("{PHASE3_SEED_DIR_CATALOG_ROOT}.adam.c14"));
    assert!(
        seed_catalog.is_file(),
        "missing phase3_g9_directory decode seed catalog {}",
        seed_catalog.display()
    );

    let src = tempdir("dir_xeng_src");
    write_tree(&src, &dir_files());
    let enc = tempdir("dir_xeng_enc");
    let arch = file::encode_directory(&ZERO_MASTER, &src, &enc)
        .unwrap_or_else(|e| panic!("[{}] dir encode for residual: {e}", active_engine()));
    let live = hex32(&arch.catalog_bao_root);

    assert_eq!(
        live, LIVE_RUST_DIR_CATALOG_ROOT,
        "live rust directory catalog root drifted from pin — update \
         LIVE_RUST_DIR_CATALOG_ROOT if intentional"
    );
    assert_eq!(
        live, PHASE3_SEED_DIR_CATALOG_ROOT,
        "live rust catalog must match the phase3_g9_directory seed (sorted rel_path bundle)"
    );
    assert_ne!(
        live, LIVE_LEAN_DIR_CATALOG_ROOT,
        "historical Lean AOT catalog pin must still differ from live rust encode"
    );

    let _ = fs::remove_dir_all(&src);
    let _ = fs::remove_dir_all(&enc);
}
