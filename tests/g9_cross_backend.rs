//! Milestone R8 / G9: full cross-backend encode/decode matrix (no-compress formats).
//!
//! Both directions:
//! - **rust→lean** (`#[cfg(feature = "backend-lean")]`): decode committed `tests/fixtures/g9/rust/*`
//! - **lean→rust** (`#[cfg(feature = "backend-rust")]`): decode committed `tests/fixtures/g9/lean/*`
//!
//! Fixtures are no-compress formats only (c0/c1/c4/c5/c8/c9/c12/c13 + selected headered/outboard)
//! so re-encode bit-match is meaningful. Compression (Zstd) is an intentional residual.
//!
//! Regenerate (writes under `tests/fixtures/g9/{rust,lean}/` for the active backend):
//! ```bash
//! # Rust goldens
//! G9_WRITE_FIXTURES=1 cargo test --test g9_cross_backend write_fixtures -- --ignored --nocapture
//! # Lean goldens (needs libcarbonado)
//! eval "$(just _lean-env)"
//! G9_WRITE_FIXTURES=1 cargo test --no-default-features --features "backend-lean,pqc,ots" \
//!   --test g9_cross_backend write_fixtures -- --ignored --nocapture
//! # or: just g9-gen-fixtures
//! ```
//!
//! Pins: [`MASTER`], [`NONCE`], [`PLAINTEXT`] — same MASTER/NONCE as `lean_backend_phase2`.

use std::fs;
use std::path::{Path, PathBuf};

use carbonado::{
    constants::Format, decode, decode_outboard, encode_with_nonce, file,
    stream_encode_outboard_buffer, structs::Encoded, OutboardEncoded,
};
use serde::{Deserialize, Serialize};

/// Same master as Phase 2 G9 seeds (continuity).
const MASTER: [u8; 32] = [
    0x0c, 0xa1, 0xb0, 0xda, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
];

/// Fixed 16-byte nonce for encrypted goldens (Phase 2 pattern `01..10`).
const NONCE: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

/// Single plaintext for all matrix entries (plaintext_id = `g9_matrix_v1`).
const PLAINTEXT: &[u8] = b"g9 cross-backend matrix v1";
const PLAINTEXT_ID: &str = "g9_matrix_v1";

/// No-compress body formats: public + encrypted fixed-nonce.
const BODY_FORMATS: &[u8] = &[0, 1, 4, 5, 8, 9, 12, 13];
/// Headered subset.
const HEADERED_FORMATS: &[u8] = &[4, 5, 12, 13];
/// Outboard subset (public + encrypted header-path).
const OUTBOARD_FORMATS: &[u8] = &[4, 5, 12, 13, 14];

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/g9")
}

fn engine_dir(engine: &str) -> PathBuf {
    fixtures_root().join(engine)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn require_write_env() {
    match std::env::var("G9_WRITE_FIXTURES") {
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes") => {}
        _ => panic!("set G9_WRITE_FIXTURES=1 to regenerate fixtures"),
    }
}

#[cfg(feature = "backend-lean")]
fn require_lean_lib() {
    if std::env::var_os("CARBONADO_LEAN_LIB").is_none() {
        panic!(
            "CARBONADO_LEAN_LIB unset. Build and export first:\n  \
             nix build .#libcarbonado -o result-libcarbonado\n  \
             export CARBONADO_LEAN_LIB=$PWD/result-libcarbonado/lib\n  \
             export CARBONADO_LEAN_INCLUDE=$PWD/result-libcarbonado/include\n  \
             export LD_LIBRARY_PATH=$CARBONADO_LEAN_LIB\n  \
             # or: just test-lean-ci / just g9-gen-fixtures"
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BodyMeta {
    layout: String,
    engine: String,
    format: u8,
    hash_hex: String,
    padding_len: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_hex: Option<String>,
    plaintext_id: String,
    encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeaderedMeta {
    layout: String,
    engine: String,
    format: u8,
    hash_hex: String,
    padding_len: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_hex: Option<String>,
    plaintext_id: String,
    encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutboardMeta {
    layout: String,
    engine: String,
    format: u8,
    hash_hex: String,
    padding_len: u32,
    /// Encrypted outboard fixtures use header-path layout (`[tag|ct]` + out-of-band header).
    header_path: bool,
    has_verification_outboard: bool,
    has_fec_parity: bool,
    has_header: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_hex: Option<String>,
    plaintext_id: String,
    encrypted: bool,
}

fn write_bytes(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("mkdir");
    }
    fs::write(path, data).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn write_json<T: Serialize>(path: &Path, value: &T) {
    let s = serde_json::to_string_pretty(value).expect("json");
    write_bytes(path, format!("{s}\n").as_bytes());
}

fn active_engine() -> &'static str {
    if cfg!(feature = "backend-lean") {
        "lean"
    } else {
        "rust"
    }
}

fn is_encrypted(format: u8) -> bool {
    Format::from(format).contains(Format::Encryption)
}

/// Encode body under the active backend with fixed nonce when encrypted.
fn encode_body(format: u8) -> (Vec<u8>, [u8; 32], u32) {
    let nonce = if is_encrypted(format) {
        Some(NONCE)
    } else {
        None
    };
    let carbonado::structs::Encoded(body, hash, info) =
        encode_with_nonce(&MASTER, PLAINTEXT, format, nonce)
            .unwrap_or_else(|e| panic!("encode body c{format}: {e}"));
    (body, *hash.as_bytes(), info.padding_len)
}

/// Encode headered under the active backend with fixed nonce when encrypted.
fn encode_headered(format: u8) -> (Vec<u8>, [u8; 32], u32, Option<[u8; 16]>) {
    let nonce = if is_encrypted(format) {
        Some(NONCE)
    } else {
        None
    };
    let (archive, info) = file::encode_with_nonce(&MASTER, PLAINTEXT, format, None, nonce)
        .unwrap_or_else(|e| panic!("encode headered c{format}: {e}"));
    let (hdr, _) = file::decode(&MASTER, &archive).expect("self-decode headered for hash");
    let hash = *hdr.hash.as_bytes();
    let nonce_out = if is_encrypted(format) {
        Some(hdr.payload_nonce)
    } else {
        None
    };
    (archive, hash, info.padding_len, nonce_out)
}

/// Encode outboard: public via low-level; encrypted via header-path + Header (fixed nonce).
fn encode_outboard_fixture(format: u8) -> (OutboardEncoded, Option<Vec<u8>>, bool) {
    let encrypted = is_encrypted(format);
    if encrypted {
        // Header-path: stream_encode_outboard_buffer Some(nonce) + Header for file::decode_outboard.
        let oenc = stream_encode_outboard_buffer(&MASTER, PLAINTEXT, format, Some(NONCE))
            .unwrap_or_else(|e| panic!("outboard header_path c{format}: {e}"));
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
        (oenc, Some(hdr_bytes), true)
    } else {
        let oenc = carbonado::encode_outboard(&MASTER, PLAINTEXT, format)
            .unwrap_or_else(|e| panic!("outboard public c{format}: {e}"));
        (oenc, None, false)
    }
}

// ---------------------------------------------------------------------------
// Fixture writer (ignored unless G9_WRITE_FIXTURES=1)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "set G9_WRITE_FIXTURES=1 to regenerate tests/fixtures/g9/{engine}/"]
fn write_fixtures() {
    require_write_env();
    #[cfg(feature = "backend-lean")]
    require_lean_lib();

    let engine = active_engine();
    let root = engine_dir(engine);
    fs::create_dir_all(&root).expect("mkdir engine");

    for &format in BODY_FORMATS {
        let (body, hash, padding) = encode_body(format);
        let name = format!("body_c{format}");
        write_bytes(&root.join(format!("{name}.bin")), &body);
        let meta = BodyMeta {
            layout: "body".into(),
            engine: engine.into(),
            format,
            hash_hex: to_hex(&hash),
            padding_len: padding,
            nonce_hex: if is_encrypted(format) {
                Some(to_hex(&NONCE))
            } else {
                None
            },
            plaintext_id: PLAINTEXT_ID.into(),
            encrypted: is_encrypted(format),
        };
        write_json(&root.join(format!("{name}.meta.json")), &meta);
        eprintln!("wrote {engine}/{name} ({} bytes)", body.len());
    }

    for &format in HEADERED_FORMATS {
        let (archive, hash, padding, nonce_out) = encode_headered(format);
        let name = format!("headered_c{format}");
        write_bytes(&root.join(format!("{name}.bin")), &archive);
        let meta = HeaderedMeta {
            layout: "headered".into(),
            engine: engine.into(),
            format,
            hash_hex: to_hex(&hash),
            padding_len: padding,
            nonce_hex: nonce_out.map(|n| to_hex(&n)),
            plaintext_id: PLAINTEXT_ID.into(),
            encrypted: is_encrypted(format),
        };
        write_json(&root.join(format!("{name}.meta.json")), &meta);
        eprintln!("wrote {engine}/{name} ({} bytes)", archive.len());
    }

    for &format in OUTBOARD_FORMATS {
        let (oenc, header, header_path) = encode_outboard_fixture(format);
        let dir = root.join(format!("outboard_c{format}"));
        fs::create_dir_all(&dir).expect("mkdir outboard");
        write_bytes(&dir.join("main.bin"), &oenc.main);
        let has_ob = oenc.verification_outboard.is_some();
        let has_par = oenc.fec_parity.is_some();
        if let Some(ref ob) = oenc.verification_outboard {
            write_bytes(&dir.join("out.bin"), ob);
        }
        if let Some(ref par) = oenc.fec_parity {
            write_bytes(&dir.join("par.bin"), par);
        }
        let has_header = if let Some(ref h) = header {
            write_bytes(&dir.join("header.bin"), h);
            true
        } else {
            false
        };
        let meta = OutboardMeta {
            layout: "outboard".into(),
            engine: engine.into(),
            format,
            hash_hex: to_hex(oenc.hash.as_bytes()),
            padding_len: oenc.info.padding_len,
            header_path,
            has_verification_outboard: has_ob,
            has_fec_parity: has_par,
            has_header,
            nonce_hex: if is_encrypted(format) {
                Some(to_hex(&NONCE))
            } else {
                None
            },
            plaintext_id: PLAINTEXT_ID.into(),
            encrypted: is_encrypted(format),
        };
        write_json(&dir.join("meta.json"), &meta);
        eprintln!(
            "wrote {engine}/outboard_c{format} (main {} bytes)",
            oenc.main.len()
        );
    }

    eprintln!("G9 fixtures written under {}", root.display());
}

// ---------------------------------------------------------------------------
// Load helpers
// ---------------------------------------------------------------------------

/// Assert encrypted fixture meta carries the pin NONCE (and optional wire check).
fn assert_encrypted_nonce_meta(nonce_hex: &Option<String>, label: &str) {
    let hex = nonce_hex
        .as_deref()
        .unwrap_or_else(|| panic!("{label}: encrypted fixture missing nonce_hex"));
    assert_eq!(
        hex,
        to_hex(&NONCE),
        "{label}: nonce_hex must match pin NONCE"
    );
}

fn load_body(engine: &str, format: u8) -> (Vec<u8>, BodyMeta) {
    let root = engine_dir(engine);
    let name = format!("body_c{format}");
    let body = fs::read(root.join(format!("{name}.bin")))
        .unwrap_or_else(|e| panic!("missing {engine}/{name}.bin: {e}"));
    let meta: BodyMeta = serde_json::from_slice(
        &fs::read(root.join(format!("{name}.meta.json")))
            .unwrap_or_else(|e| panic!("missing {engine}/{name}.meta.json: {e}")),
    )
    .expect("body meta json");
    assert_eq!(meta.format, format);
    assert_eq!(meta.plaintext_id, PLAINTEXT_ID);
    assert_eq!(
        meta.encrypted,
        is_encrypted(format),
        "{engine}/{name} encrypted flag"
    );
    if meta.encrypted {
        assert_encrypted_nonce_meta(&meta.nonce_hex, &format!("{engine}/{name}"));
        // Pure Encryption (c1): body is embedded `[nonce|tag|ct]` with no Bao/FEC wrap.
        // c5/c9/c13 wrap ciphertext in Bao and/or FEC — nonce is not at offset 0.
        if format == 1 {
            assert!(
                body.len() >= 16,
                "{engine}/{name}: body too short for embedded nonce"
            );
            assert_eq!(
                &body[..16],
                &NONCE[..],
                "{engine}/{name}: c1 embedded body nonce must match pin"
            );
        }
    } else {
        assert!(
            meta.nonce_hex.is_none(),
            "{engine}/{name}: public body has no nonce_hex"
        );
    }
    (body, meta)
}

fn load_headered(engine: &str, format: u8) -> (Vec<u8>, HeaderedMeta) {
    let root = engine_dir(engine);
    let name = format!("headered_c{format}");
    let archive = fs::read(root.join(format!("{name}.bin")))
        .unwrap_or_else(|e| panic!("missing {engine}/{name}.bin: {e}"));
    let meta: HeaderedMeta = serde_json::from_slice(
        &fs::read(root.join(format!("{name}.meta.json")))
            .unwrap_or_else(|e| panic!("missing {engine}/{name}.meta.json: {e}")),
    )
    .expect("headered meta json");
    assert_eq!(meta.format, format);
    assert_eq!(meta.plaintext_id, PLAINTEXT_ID);
    assert_eq!(
        meta.encrypted,
        is_encrypted(format),
        "{engine}/{name} encrypted flag"
    );
    assert!(
        archive.len() >= file::Header::LEN,
        "{engine}/{name}: archive shorter than header"
    );
    // Header wire: payload_nonce at bytes [12..28] (after 12-byte MAGIC).
    let wire_nonce = &archive[12..28];
    if meta.encrypted {
        assert_encrypted_nonce_meta(&meta.nonce_hex, &format!("{engine}/{name}"));
        assert_eq!(
            wire_nonce,
            &NONCE[..],
            "{engine}/{name}: header payload_nonce must match pin"
        );
    } else {
        assert!(
            meta.nonce_hex.is_none(),
            "{engine}/{name}: public headered has no nonce_hex"
        );
        assert_eq!(
            wire_nonce,
            &[0u8; 16][..],
            "{engine}/{name}: public payload_nonce is zero"
        );
    }
    (archive, meta)
}

struct LoadedOutboard {
    main: Vec<u8>,
    verification_outboard: Option<Vec<u8>>,
    fec_parity: Option<Vec<u8>>,
    header: Option<Vec<u8>>,
    meta: OutboardMeta,
}

fn load_outboard(engine: &str, format: u8) -> LoadedOutboard {
    let dir = engine_dir(engine).join(format!("outboard_c{format}"));
    let meta: OutboardMeta = serde_json::from_slice(
        &fs::read(dir.join("meta.json"))
            .unwrap_or_else(|e| panic!("missing {}/meta.json: {e}", dir.display())),
    )
    .expect("outboard meta");
    assert_eq!(meta.format, format);
    assert_eq!(meta.plaintext_id, PLAINTEXT_ID);
    assert_eq!(
        meta.encrypted,
        is_encrypted(format),
        "{engine}/outboard_c{format} encrypted"
    );
    let main = fs::read(dir.join("main.bin")).expect("main.bin");
    let verification_outboard = if meta.has_verification_outboard {
        Some(fs::read(dir.join("out.bin")).expect("out.bin"))
    } else {
        None
    };
    let fec_parity = if meta.has_fec_parity {
        Some(fs::read(dir.join("par.bin")).expect("par.bin"))
    } else {
        None
    };
    let header = if meta.has_header {
        Some(fs::read(dir.join("header.bin")).expect("header.bin"))
    } else {
        None
    };
    if meta.encrypted {
        assert_encrypted_nonce_meta(&meta.nonce_hex, &format!("{engine}/outboard_c{format}"));
        assert!(
            meta.header_path,
            "{engine}/outboard_c{format}: encrypted is header_path"
        );
        assert!(
            meta.has_header,
            "{engine}/outboard_c{format}: encrypted needs header.bin"
        );
        let hdr = header.as_ref().expect("header");
        assert!(
            hdr.len() >= file::Header::LEN,
            "{engine}/outboard_c{format}: header.bin short"
        );
        assert_eq!(
            &hdr[12..28],
            &NONCE[..],
            "{engine}/outboard_c{format}: header payload_nonce must match pin"
        );
    } else {
        assert!(
            meta.nonce_hex.is_none(),
            "{engine}/outboard_c{format}: public has no nonce_hex"
        );
    }
    LoadedOutboard {
        main,
        verification_outboard,
        fec_parity,
        header,
        meta,
    }
}

fn hash_from_meta(hex: &str) -> [u8; 32] {
    let v = from_hex(hex);
    assert_eq!(v.len(), 32, "hash must be 32 bytes");
    let mut h = [0u8; 32];
    h.copy_from_slice(&v);
    h
}

fn decode_body_fixture(engine: &str, format: u8) {
    let (body, meta) = load_body(engine, format);
    let hash = hash_from_meta(&meta.hash_hex);
    let decoded = decode(&MASTER, &hash, &body, meta.padding_len, format)
        .unwrap_or_else(|e| panic!("{engine}→active body c{format}: {e}"));
    assert_eq!(decoded, PLAINTEXT, "{engine} body c{format} plaintext");
}

fn decode_headered_fixture(engine: &str, format: u8) {
    let (archive, meta) = load_headered(engine, format);
    let (hdr, decoded) = file::decode(&MASTER, &archive)
        .unwrap_or_else(|e| panic!("{engine}→active headered c{format}: {e}"));
    assert_eq!(hdr.format.bits(), format);
    assert_eq!(decoded, PLAINTEXT, "{engine} headered c{format}");
    assert_eq!(
        to_hex(hdr.hash.as_bytes()),
        meta.hash_hex,
        "{engine} headered c{format} hash"
    );
}

fn decode_outboard_fixture(engine: &str, format: u8) {
    let loaded = load_outboard(engine, format);
    let hash = hash_from_meta(&loaded.meta.hash_hex);
    let decoded = if loaded.meta.encrypted {
        // Header-path encrypted outboard → high-level file::decode_outboard
        file::decode_outboard(
            &MASTER,
            &hash,
            loaded.header.as_deref(),
            &loaded.main,
            loaded.verification_outboard.as_deref(),
            loaded.fec_parity.as_deref(),
            loaded.meta.padding_len,
            format,
        )
        .unwrap_or_else(|e| panic!("{engine}→active outboard c{format}: {e}"))
    } else {
        decode_outboard(
            &MASTER,
            &hash,
            &loaded.main,
            loaded.verification_outboard.as_deref(),
            loaded.fec_parity.as_deref(),
            loaded.meta.padding_len,
            format,
        )
        .unwrap_or_else(|e| panic!("{engine}→active outboard c{format}: {e}"))
    };
    assert_eq!(decoded, PLAINTEXT, "{engine} outboard c{format}");
}

// ---------------------------------------------------------------------------
// lean→rust: decode lean fixtures under default backend-rust
// ---------------------------------------------------------------------------

#[cfg(feature = "backend-rust")]
mod lean_to_rust {
    use super::*;

    #[test]
    fn body_matrix() {
        for &format in BODY_FORMATS {
            decode_body_fixture("lean", format);
        }
    }

    #[test]
    fn headered_matrix() {
        for &format in HEADERED_FORMATS {
            decode_headered_fixture("lean", format);
        }
    }

    #[test]
    fn outboard_matrix() {
        for &format in OUTBOARD_FORMATS {
            decode_outboard_fixture("lean", format);
        }
    }
}

// ---------------------------------------------------------------------------
// rust→lean: decode rust fixtures under backend-lean (+ optional re-encode bit-match)
// ---------------------------------------------------------------------------

#[cfg(feature = "backend-lean")]
mod rust_to_lean {
    use super::*;
    use carbonado::structs::Encoded;

    #[test]
    fn body_matrix() {
        require_lean_lib();
        for &format in BODY_FORMATS {
            decode_body_fixture("rust", format);
        }
    }

    #[test]
    fn headered_matrix() {
        require_lean_lib();
        for &format in HEADERED_FORMATS {
            decode_headered_fixture("rust", format);
        }
    }

    #[test]
    fn outboard_matrix() {
        require_lean_lib();
        for &format in OUTBOARD_FORMATS {
            decode_outboard_fixture("rust", format);
        }
    }

    /// Public no-compress body re-encode under lean must bit-match rust golden.
    #[test]
    fn public_body_reencode_bit_match() {
        require_lean_lib();
        for &format in &[0u8, 4, 8, 12] {
            let (rust_body, meta) = load_body("rust", format);
            let Encoded(lean_body, lean_hash, _) =
                encode_with_nonce(&MASTER, PLAINTEXT, format, None)
                    .unwrap_or_else(|e| panic!("lean re-encode c{format}: {e}"));
            assert_eq!(
                lean_body, rust_body,
                "lean re-encode must bit-match rust body c{format}"
            );
            assert_eq!(
                to_hex(lean_hash.as_bytes()),
                meta.hash_hex,
                "lean re-encode hash c{format}"
            );
        }
    }

    /// Encrypted fixed-nonce body re-encode under lean must bit-match rust golden.
    #[test]
    fn encrypted_body_reencode_bit_match() {
        require_lean_lib();
        for &format in &[1u8, 5, 9, 13] {
            let (rust_body, meta) = load_body("rust", format);
            let Encoded(lean_body, lean_hash, _) =
                encode_with_nonce(&MASTER, PLAINTEXT, format, Some(NONCE))
                    .unwrap_or_else(|e| panic!("lean re-encode enc c{format}: {e}"));
            assert_eq!(
                lean_body, rust_body,
                "lean re-encode must bit-match rust encrypted body c{format}"
            );
            assert_eq!(
                to_hex(lean_hash.as_bytes()),
                meta.hash_hex,
                "lean re-encode enc hash c{format}"
            );
        }
    }

    /// Headered re-encode under lean must bit-match rust golden (no-compress formats).
    #[test]
    fn headered_reencode_bit_match() {
        require_lean_lib();
        for &format in HEADERED_FORMATS {
            let (rust_arch, meta) = load_headered("rust", format);
            let nonce = if is_encrypted(format) {
                Some(NONCE)
            } else {
                None
            };
            let (lean_arch, _) = file::encode_with_nonce(&MASTER, PLAINTEXT, format, None, nonce)
                .unwrap_or_else(|e| panic!("lean re-encode headered c{format}: {e}"));
            assert_eq!(
                lean_arch, rust_arch,
                "lean re-encode must bit-match rust headered c{format}"
            );
            let (hdr, _) = file::decode(&MASTER, &lean_arch).expect("decode lean headered");
            assert_eq!(to_hex(hdr.hash.as_bytes()), meta.hash_hex);
        }
    }

    /// Outboard re-encode under lean must bit-match rust golden (skip compressed c14).
    #[test]
    fn outboard_reencode_bit_match_no_compress() {
        require_lean_lib();
        for &format in &[4u8, 5, 12, 13] {
            let loaded = load_outboard("rust", format);
            let (oenc, header, _) = encode_outboard_fixture(format);
            assert_eq!(
                oenc.main, loaded.main,
                "lean re-encode main must bit-match rust outboard c{format}"
            );
            assert_eq!(
                oenc.verification_outboard.as_deref(),
                loaded.verification_outboard.as_deref(),
                "outboard c{format} verification outboard"
            );
            assert_eq!(
                oenc.fec_parity.as_deref(),
                loaded.fec_parity.as_deref(),
                "outboard c{format} fec parity"
            );
            if is_encrypted(format) {
                assert_eq!(
                    header.as_deref(),
                    loaded.header.as_deref(),
                    "outboard c{format} header.bin"
                );
            }
            assert_eq!(
                to_hex(oenc.hash.as_bytes()),
                loaded.meta.hash_hex,
                "outboard c{format} hash"
            );
        }
    }
}

/// `Some([0u8; 16])` must be honored literally on the active backend (no CSPRNG override).
///
/// Uses c1 (encryption-only body, embedded layout) and c5 headered so the zero nonce is
/// visible on the wire. Dual-backend identity is the same contract on both engines.
#[test]
fn explicit_zero_nonce_is_honored_headered_and_body() {
    #[cfg(feature = "backend-lean")]
    require_lean_lib();

    let zero = [0u8; 16];
    let pt = b"g9 zero nonce dual contract";

    // Body c1 (embedded only): two encodes with Some(zero) must match (deterministic).
    let Encoded(b1, h1, i1) =
        encode_with_nonce(&MASTER, pt, 1, Some(zero)).expect("body zero nonce 1");
    let Encoded(b2, h2, i2) =
        encode_with_nonce(&MASTER, pt, 1, Some(zero)).expect("body zero nonce 2");
    assert_eq!(b1, b2, "Some([0;16]) body must be deterministic");
    assert_eq!(h1, h2);
    assert_eq!(i1.padding_len, i2.padding_len);
    assert_eq!(
        &b1[..16],
        &zero[..],
        "c1 embedded layout starts with zero nonce"
    );
    let d = decode(&MASTER, h1.as_bytes(), &b1, i1.padding_len, 1).expect("decode body zero");
    assert_eq!(d, pt);

    // Headered c5: payload_nonce in header must be all-zero, and encode is deterministic.
    let (a1, _) = file::encode_with_nonce(&MASTER, pt, 5, None, Some(zero)).expect("hdr 1");
    let (a2, _) = file::encode_with_nonce(&MASTER, pt, 5, None, Some(zero)).expect("hdr 2");
    assert_eq!(a1, a2, "Some([0;16]) headered must be deterministic");
    assert_eq!(&a1[12..28], &zero[..], "header payload_nonce is zero");
    let (hdr, d2) = file::decode(&MASTER, &a1).expect("decode headered zero");
    assert_eq!(hdr.payload_nonce, zero);
    assert_eq!(d2, pt);
}

// ---------------------------------------------------------------------------
// Smoke: active backend self roundtrip for matrix formats (always runs)
// ---------------------------------------------------------------------------

#[test]
fn active_backend_self_roundtrip_matrix() {
    #[cfg(feature = "backend-lean")]
    require_lean_lib();

    for &format in BODY_FORMATS {
        let (body, hash, pad) = encode_body(format);
        let d = decode(&MASTER, &hash, &body, pad, format).expect("body decode");
        assert_eq!(d, PLAINTEXT, "self body c{format}");
    }
    for &format in HEADERED_FORMATS {
        let (arch, _, _, _) = encode_headered(format);
        let (_, d) = file::decode(&MASTER, &arch).expect("headered decode");
        assert_eq!(d, PLAINTEXT, "self headered c{format}");
    }
    for &format in OUTBOARD_FORMATS {
        let (oenc, header, _) = encode_outboard_fixture(format);
        let d = if is_encrypted(format) {
            file::decode_outboard(
                &MASTER,
                oenc.hash.as_bytes(),
                header.as_deref(),
                &oenc.main,
                oenc.verification_outboard.as_deref(),
                oenc.fec_parity.as_deref(),
                oenc.info.padding_len,
                format,
            )
            .expect("outboard enc decode")
        } else {
            decode_outboard(
                &MASTER,
                oenc.hash.as_bytes(),
                &oenc.main,
                oenc.verification_outboard.as_deref(),
                oenc.fec_parity.as_deref(),
                oenc.info.padding_len,
                format,
            )
            .expect("outboard pub decode")
        };
        assert_eq!(d, PLAINTEXT, "self outboard c{format}");
    }
}
