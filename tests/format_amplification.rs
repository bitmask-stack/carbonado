//! Format amplification / overhead matrix for all c0–c15 levels.
//!
//! Fixture: deterministic **compressible** ~1 MiB payload built from a repeating 4 KiB
//! pattern (mimics repetitive archival text/binary). Fixed master key for encrypted formats.
//!
//! Uses high-level [`carbonado::file::encode`] and records [`EncodeInfo`] fields.
//! `net_amp = output_len / input_len` is printed for end-to-end overhead vs raw input.
//!
//! Run: `cargo test --test format_amplification -- --nocapture` to print the matrix.

use carbonado::{
    constants::{FEC_K, FEC_M, SLICE_LEN},
    file::{self, Header},
};

/// ~1 MiB input (exactly 1_048_576 bytes).
const INPUT_LEN: usize = 1_048_576;

/// Repeating 4 KiB pattern — highly compressible under Zstd-20.
const PATTERN_LEN: usize = 4096;

/// Fixed master for reproducible encrypted encodes.
const MASTER: [u8; 32] = [0x42u8; 32];

/// RS stripe alignment unit: `FEC_K * SLICE_LEN` = 16 KiB.
const FEC_STRIPE: u32 = FEC_K as u32 * SLICE_LEN;

// --- Bounds on net_amp = output_len / input_len (measured geometry) ---

const NET_AMP_C0_MAX: f32 = 1.0001;
const NET_AMP_ENCRYPT_MAX: f32 = 1.001;
const NET_AMP_COMPRESS_MAX: f32 = 0.01;
const NET_AMP_BAO_MIN: f32 = 1.01;
const NET_AMP_BAO_MAX: f32 = 1.02;
const NET_AMP_FEC_MIN: f32 = 1.99;
const NET_AMP_FEC_MAX: f32 = 2.05;
/// Compressed then FEC: one 16 KiB stripe × 2 / 1 MiB ≈ 0.03125
const NET_AMP_COMPRESS_FEC_MIN: f32 = 0.025;
const NET_AMP_COMPRESS_FEC_MAX: f32 = 0.04;
/// Full c15: compress → encrypt → FEC → Bao on ~2 KiB logical body
const NET_AMP_C15_MIN: f32 = 0.025;
const NET_AMP_C15_MAX: f32 = 0.04;

fn compressible_payload() -> Vec<u8> {
    let mut pattern = Vec::with_capacity(PATTERN_LEN);
    for i in 0..PATTERN_LEN {
        pattern.push(((i % 251) ^ (i >> 4)) as u8);
    }
    let mut out = Vec::with_capacity(INPUT_LEN);
    while out.len() < INPUT_LEN {
        let take = (INPUT_LEN - out.len()).min(PATTERN_LEN);
        out.extend_from_slice(&pattern[..take]);
    }
    out
}

#[derive(Debug)]
struct Row {
    format: u8,
    input_len: u32,
    output_len: u32,
    on_disk_len: usize,
    bytes_compressed: u32,
    bytes_encrypted: u32,
    bytes_ecc: u32,
    bytes_verifiable: u32,
    padding_len: u32,
    amplification_factor: f32,
    compression_factor: f32,
    net_amp: f32,
}

fn measure_row(format: u8, input: &[u8]) -> Row {
    let (encoded, info) = file::encode(&MASTER, input, format, None).expect("encode");
    let net_amp = info.output_len as f32 / info.input_len.max(1) as f32;
    Row {
        format,
        input_len: info.input_len,
        output_len: info.output_len,
        on_disk_len: encoded.len(),
        bytes_compressed: info.bytes_compressed,
        bytes_encrypted: info.bytes_encrypted,
        bytes_ecc: info.bytes_ecc,
        bytes_verifiable: info.bytes_verifiable,
        padding_len: info.padding_len,
        amplification_factor: info.amplification_factor,
        compression_factor: info.compression_factor,
        net_amp,
    }
}

fn print_matrix(rows: &[Row]) {
    eprintln!("\n=== Format amplification matrix (1 MiB compressible fixture) ===");
    eprintln!(
        "FEC geometry: FEC_K={FEC_K}, FEC_M={FEC_M}, SLICE_LEN={SLICE_LEN}, stripe={FEC_STRIPE}"
    );
    eprintln!(
        "{:>4} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8} {:>8} {:>6} {:>8} {:>8} {:>8}",
        "fmt",
        "input",
        "body",
        "on_disk",
        "comp",
        "enc",
        "ecc",
        "bao",
        "pad",
        "amp",
        "cf",
        "net_amp"
    );
    for r in rows {
        eprintln!(
            "c{:02X} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8} {:>8} {:>6} {:>8.4} {:>8.4} {:>8.4}",
            r.format,
            r.input_len,
            r.output_len,
            r.on_disk_len,
            r.bytes_compressed,
            r.bytes_encrypted,
            r.bytes_ecc,
            r.bytes_verifiable,
            r.padding_len,
            r.amplification_factor,
            r.compression_factor,
            r.net_amp,
        );
    }
}

#[test]
fn format_amplification_matrix_all_levels() {
    let input = compressible_payload();
    assert_eq!(input.len(), INPUT_LEN);

    let mut rows = Vec::with_capacity(16);
    for format in 0u8..=15 {
        rows.push(measure_row(format, &input));
    }
    print_matrix(&rows);

    // EncodeInfo field assertions (file layer must thread preprocess stats).
    let c0 = &rows[0];
    assert_eq!(c0.bytes_encrypted, 0);
    assert_eq!(c0.bytes_compressed, 0);

    let c1 = &rows[1];
    assert_eq!(c1.bytes_encrypted, INPUT_LEN as u32 + 64);
    assert_eq!(c1.bytes_compressed, 0);

    let c2 = &rows[2];
    assert!(c2.bytes_compressed < INPUT_LEN as u32 / 100);
    assert_eq!(c2.bytes_encrypted, 0);

    let c4 = &rows[4];
    assert_eq!(c4.bytes_encrypted, 0);

    let c8 = &rows[8];
    assert_eq!(c8.bytes_encrypted, 0);

    // c0: passthrough (no pipeline bits).
    assert_eq!(c0.output_len, INPUT_LEN as u32);
    assert!(c0.net_amp <= NET_AMP_C0_MAX);
    assert_eq!(c0.on_disk_len, Header::LEN + INPUT_LEN);

    // c1: encrypt only — +64 B EtM tag on ~1 MiB body.
    assert!(c1.net_amp <= NET_AMP_ENCRYPT_MAX);
    assert_eq!(c1.output_len, INPUT_LEN as u32 + 64);

    // c2: compress only — body shrinks dramatically vs input.
    assert!(
        c2.net_amp <= NET_AMP_COMPRESS_MAX,
        "c2 net_amp={}",
        c2.net_amp
    );
    assert!(c2.output_len < INPUT_LEN as u32 / 100);

    // c4: Bao only — ~1.5% inboard tree overhead on 1 MiB.
    assert!(
        (NET_AMP_BAO_MIN..=NET_AMP_BAO_MAX).contains(&c4.net_amp),
        "c4 net_amp={}",
        c4.net_amp
    );

    // c8: FEC only — RS 4/8 ⇒ ~2× (FEC_M/FEC_K).
    assert!(
        (NET_AMP_FEC_MIN..=NET_AMP_FEC_MAX).contains(&c8.net_amp),
        "c8 net_amp={} (FEC_M/FEC_K={})",
        c8.net_amp,
        FEC_M as f32 / FEC_K as f32
    );
    assert_eq!(c8.bytes_ecc, c8.output_len);

    // c10: compress + FEC — one padded stripe (16 KiB) × 2 shards / 1 MiB input.
    let c10 = &rows[10];
    assert!(
        (NET_AMP_COMPRESS_FEC_MIN..=NET_AMP_COMPRESS_FEC_MAX).contains(&c10.net_amp),
        "c10 net_amp={}",
        c10.net_amp
    );
    assert_eq!(c10.bytes_ecc, FEC_STRIPE * FEC_M as u32 / FEC_K as u32);

    // c12: FEC + Bao on full input — ~2× net + small Bao overhead.
    let c12 = &rows[12];
    assert!(
        (NET_AMP_FEC_MIN..=NET_AMP_FEC_MAX + 0.05).contains(&c12.net_amp),
        "c12 net_amp={}",
        c12.net_amp
    );

    // c15: full pipeline on compressible input.
    let c15 = &rows[15];
    assert!(
        (NET_AMP_C15_MIN..=NET_AMP_C15_MAX).contains(&c15.net_amp),
        "c15 net_amp={}",
        c15.net_amp
    );
    assert!(c15.bytes_compressed < INPUT_LEN as u32 / 100);
    assert!(c15.bytes_encrypted > 0);

    // Global invariants.
    for r in &rows {
        assert_eq!(r.input_len, INPUT_LEN as u32);
        assert_eq!(r.on_disk_len, Header::LEN + r.output_len as usize);
        assert!(r.net_amp > 0.0);
    }

    // Roundtrip all formats c0–c15.
    for format in 0u8..=15 {
        roundtrip(format, &input);
    }
}

fn roundtrip(format: u8, expected: &[u8]) {
    let (encoded, _) = file::encode(&MASTER, expected, format, None).expect("encode");
    let (_hdr, decoded) = file::decode(&MASTER, &encoded).expect("decode");
    assert_eq!(decoded, expected, "roundtrip failed for c{format:02X}");
}
