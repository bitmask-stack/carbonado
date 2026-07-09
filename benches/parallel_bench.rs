//! Criterion benchmarks: serial vs parallel RS parity generation (Phase 3).
//!
//! Run:
//!   RUSTFLAGS="-C target-cpu=native" cargo bench --features parallel --bench parallel_bench
//!
//! Carbonado inboard/outboard stripes always have `chunk_len >= 4096` (see `calc_padding_len`).
//! The `rs_parity_synthetic_chunk_len` group exercises the defensive sub-threshold serial fallback
//! via direct shard vectors. AES/HMAC SIMD is unchanged — use `RUSTFLAGS="-C target-cpu=native"`.

#![cfg(feature = "parallel")]

use std::io::Cursor;

use carbonado::constants::FEC_M;
use carbonado::stream::fec::FecInboardEncoder;
use carbonado::stream::parallel::{
    encode_rs_parity_serial, encode_rs_parity_with_config, ParallelConfig,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use reed_solomon_erasure::galois_8::ReedSolomon;

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn pre_parity_shards(logical_len: usize) -> (ReedSolomon, Vec<Vec<u8>>, usize) {
    let rs = ReedSolomon::new(4, 4).expect("rs");
    let mut enc = FecInboardEncoder::new(logical_len).expect("new");
    let input = patterned(logical_len);
    enc.feed(Cursor::new(&input)).expect("feed");
    let stripe = enc.finish().expect("finish").expect("stripe");
    let chunk_len = stripe.chunk_len as usize;
    let mut shards = stripe.shards;
    for s in shards.iter_mut().skip(4) {
        s.fill(0);
    }
    (rs, shards, chunk_len)
}

fn synthetic_pre_parity_shards(chunk_len: usize) -> (ReedSolomon, Vec<Vec<u8>>) {
    let rs = ReedSolomon::new(4, 4).expect("rs");
    let mut shards = Vec::with_capacity(FEC_M);
    for i in 0..FEC_M {
        shards.push(vec![(i as u8).wrapping_mul(17); chunk_len]);
    }
    (rs, shards)
}

fn bench_rs_parity_serial_vs_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("rs_parity_carbonado_stripe");
    let logical_sizes = [16_384usize, 65_536, 262_144];

    for logical_len in logical_sizes {
        let (rs, shards_template, chunk_len) = pre_parity_shards(logical_len);
        let throughput = (FEC_M * chunk_len) as u64;
        group.throughput(Throughput::Bytes(throughput));

        group.bench_with_input(
            BenchmarkId::new("serial", logical_len),
            &logical_len,
            |b, _| {
                b.iter(|| {
                    let mut shards = black_box(shards_template.clone());
                    encode_rs_parity_serial(black_box(&rs), black_box(&mut shards)).unwrap();
                    black_box(shards);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("parallel_4", logical_len),
            &logical_len,
            |b, _| {
                b.iter(|| {
                    let mut shards = black_box(shards_template.clone());
                    encode_rs_parity_with_config(
                        black_box(&rs),
                        black_box(&mut shards),
                        chunk_len,
                        ParallelConfig { max_threads: 4 },
                    )
                    .unwrap();
                    black_box(shards);
                });
            },
        );
    }
    group.finish();
}

fn bench_rs_parity_synthetic_chunk_len(c: &mut Criterion) {
    let mut group = c.benchmark_group("rs_parity_synthetic_chunk_len");

    for chunk_len in [512usize, 1024, 2048, 4096] {
        let (rs, shards_template) = synthetic_pre_parity_shards(chunk_len);
        let throughput = (FEC_M * chunk_len) as u64;
        group.throughput(Throughput::Bytes(throughput));

        group.bench_with_input(BenchmarkId::new("serial", chunk_len), &chunk_len, |b, _| {
            b.iter(|| {
                let mut shards = black_box(shards_template.clone());
                encode_rs_parity_serial(black_box(&rs), black_box(&mut shards)).unwrap();
                black_box(shards);
            });
        });

        group.bench_with_input(
            BenchmarkId::new("parallel_4", chunk_len),
            &chunk_len,
            |b, _| {
                b.iter(|| {
                    let mut shards = black_box(shards_template.clone());
                    encode_rs_parity_with_config(
                        black_box(&rs),
                        black_box(&mut shards),
                        chunk_len,
                        ParallelConfig { max_threads: 4 },
                    )
                    .unwrap();
                    black_box(shards);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_rs_parity_serial_vs_parallel,
    bench_rs_parity_synthetic_chunk_len
);
criterion_main!(benches);
