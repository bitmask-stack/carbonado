//! Criterion benchmarks for the Carbonado v2 symmetric cryptographic stack.
//!
//! These benchmarks exercise the production primitives:
//! - AES-256-CTR + HMAC-SHA512 EtM (core encryption path)
//! - Full file::encode / file::decode pipeline
//! - SLH-DSA (via libbitcoinpqc) keygen + sign + verify
//!
//! Run with hardware acceleration visible:
//!   RUSTFLAGS="-C target-cpu=native" cargo bench
//!
//! See AGENTS.md §2.6 for hardware acceleration notes.

use carbonado::crypto::{slh_dsa_generate_keypair, slh_dsa_sign, slh_dsa_verify};
use carbonado::{decode, encode};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use getrandom::getrandom;

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
    bench_slh_dsa
);
criterion_main!(benches);
