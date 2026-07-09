//! Criterion benchmarks for the Carbonado v2 symmetric cryptographic stack.
//!
//! These benchmarks exercise the production primitives:
//! - AES-256-CTR + HMAC-SHA512 EtM (core encryption path)
//! - Full file::encode / file::decode pipeline
//! - Public c14 outboard encode/decode (format 0x0E)
//! - Directory archive encode (Adamantine + per-file c14)
//! - Outboard scrub recovery (bare main + sidecars)
//! - SLH-DSA (via bitcoinpqc) keygen + sign + verify
//!
//! Run with hardware acceleration visible:
//!   RUSTFLAGS="-C target-cpu=native" cargo bench --bench crypto_bench
//!
//! See AGENTS.md §2.6 and README "Benchmarks" for published numbers.

use carbonado::crypto::{slh_dsa_generate_keypair, slh_dsa_sign, slh_dsa_verify};
use carbonado::file::encode_directory;
use carbonado::{decode, decode_outboard, encode, encode_outboard, scrub_outboard};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use getrandom::getrandom;
use std::fs;
use std::path::PathBuf;

/// Public c14 directory archive format (Snappy + Bao + Zfec, no encryption).
const C14_FORMAT: u8 = 0x0E;

fn bench_symmetric_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric_etm");
    let sizes = [1024, 64 * 1024, 1024 * 1024]; // 1KB, 64KB, 1MB

    for size in sizes {
        let mut data = vec![0u8; size];
        getrandom(&mut data).unwrap();

        let mut master_key = [0u8; 32];
        getrandom(&mut master_key).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("encrypt_decrypt_{}kb", size / 1024), |b| {
            b.iter(|| {
                let encoded = encode(black_box(&master_key), black_box(&data), 1).unwrap();
                let _ = decode(
                    black_box(&master_key),
                    black_box(encoded.1.as_bytes()),
                    black_box(&encoded.0),
                    black_box(encoded.2.padding_len),
                    1,
                )
                .unwrap();
            })
        });
    }
    group.finish();
}

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline_level15");

    let sizes = [64 * 1024, 1024 * 1024]; // 64KB, 1MB (realistic archival sizes)

    for size in sizes {
        let mut data = vec![0u8; size];
        getrandom(&mut data).unwrap();

        let mut master_key = [0u8; 32];
        getrandom(&mut master_key).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("encode_decode_{}kb", size / 1024), |b| {
            b.iter(|| {
                let encoded = encode(black_box(&master_key), black_box(&data), 15).unwrap();
                let _ = decode(
                    black_box(&master_key),
                    black_box(encoded.1.as_bytes()),
                    black_box(&encoded.0),
                    black_box(encoded.2.padding_len),
                    15,
                )
                .unwrap();
            })
        });
    }
    group.finish();
}

fn bench_outboard_c14(c: &mut Criterion) {
    let mut group = c.benchmark_group("outboard_c14");
    let master_key = [0u8; 32]; // public c14
    let sizes = [64 * 1024, 1024 * 1024];

    for size in sizes {
        let mut data = vec![0u8; size];
        getrandom(&mut data).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("encode_decode_{}kb", size / 1024), |b| {
            b.iter(|| {
                let oenc =
                    encode_outboard(black_box(&master_key), black_box(&data), C14_FORMAT).unwrap();
                let bao_ob = oenc.verification_outboard.as_deref();
                let fec_par = oenc.fec_parity.as_deref();
                let _ = decode_outboard(
                    black_box(&master_key),
                    black_box(oenc.hash.as_bytes()),
                    black_box(&oenc.main),
                    black_box(bao_ob),
                    black_box(fec_par),
                    black_box(oenc.info.padding_len),
                    C14_FORMAT,
                )
                .unwrap();
            })
        });
    }
    group.finish();
}

fn bench_encode_directory(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_directory");
    let master_key = [0u8; 32];

    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples");
    let total_bytes: u64 = fs::read_dir(&input)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| fs::metadata(e.path()).ok())
        .map(|m| m.len())
        .sum();

    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("small_tree_tests_samples", |b| {
        let out_base = std::env::temp_dir().join("carbonado-bench-dir-out");
        b.iter(|| {
            if out_base.exists() {
                fs::remove_dir_all(&out_base).unwrap();
            }
            fs::create_dir_all(&out_base).unwrap();
            let archive = encode_directory(
                black_box(&master_key),
                black_box(&input),
                black_box(&out_base),
            )
            .unwrap();
            black_box(archive.entry_count);
        })
    });
    group.finish();
}

fn bench_scrub_outboard(c: &mut Criterion) {
    let mut group = c.benchmark_group("scrub_outboard");
    let master_key = [0u8; 32];
    let input = b"scrub bench fixture: bare c14 main + bao out + fec parity sidecars";

    let oenc = encode_outboard(&master_key, input, C14_FORMAT).unwrap();
    let bao_ob = oenc.verification_outboard.clone().expect("bao sidecar");
    let fec_par = oenc.fec_parity.clone().expect("fec parity");
    let hash = oenc.hash;
    let info = oenc.info.clone();

    let mut corrupted = oenc.main.clone();
    corrupted[0] ^= 0xff;
    if corrupted.len() > 1 {
        let mid = corrupted.len() / 2;
        corrupted[mid] ^= 0x55;
    }

    group.throughput(Throughput::Bytes(input.len() as u64));
    group.bench_function("recover_corrupted_main", |b| {
        b.iter(|| {
            let recovered = scrub_outboard(
                black_box(&corrupted),
                black_box(Some(bao_ob.as_slice())),
                black_box(Some(fec_par.as_slice())),
                black_box(&info),
                C14_FORMAT,
                black_box(hash.as_bytes()),
            )
            .unwrap();
            black_box(recovered);
        })
    });
    group.finish();
}

fn bench_slh_dsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_shake_128s");

    // 128 bytes entropy for keygen
    let mut entropy = [0u8; 128];
    getrandom(&mut entropy).unwrap();

    let keypair = slh_dsa_generate_keypair(&entropy).unwrap();

    let message = b"benchmark manifest or checkpoint bao hash - 32 bytes typical";

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let mut e = [0u8; 128];
            getrandom(&mut e).unwrap();
            black_box(slh_dsa_generate_keypair(black_box(&e)).unwrap())
        })
    });

    group.bench_function("sign", |b| {
        b.iter(|| {
            black_box(slh_dsa_sign(black_box(&keypair.secret_key), black_box(message)).unwrap())
        })
    });

    let signature = slh_dsa_sign(&keypair.secret_key, message).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(
                slh_dsa_verify(
                    black_box(&keypair.public_key),
                    black_box(message),
                    black_box(&signature),
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_symmetric_roundtrip,
    bench_full_pipeline,
    bench_outboard_c14,
    bench_encode_directory,
    bench_scrub_outboard,
    bench_slh_dsa
);
criterion_main!(benches);
