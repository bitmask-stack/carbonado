//! c12 (Bao + FEC, no compress) encode / decode / scrub at 1 MiB and 16 MiB.
//!
//! Run:
//!   RUSTFLAGS="-C target-cpu=native" cargo bench --bench fec_stripe_bench
//!
//! First land is measurement, not a CI cap. Sample on this host with
//! `RUSTFLAGS="-C target-cpu=native"` (10 samples, 3 s):
//!   1 MiB  encode ~7.2 ms (~139 MiB/s), decode ~1.13 ms (~882 MiB/s), scrub ~8.4 ms (~118 MiB/s)
//!   16 MiB encode ~112 ms (~143 MiB/s), decode ~28 ms (~572 MiB/s), scrub ~132 ms (~121 MiB/s)

use carbonado::{decode, encode, scrub, structs::Encoded};
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

const C12: u8 = 12;
const ZERO_MASTER: [u8; 32] = [0u8; 32];

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn bench_c12_stripe(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_stripe_c12");
    for &size in &[1024 * 1024usize, 16 * 1024 * 1024] {
        let data = patterned(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_function(format!("encode_{}mib", size / (1024 * 1024)), |b| {
            b.iter(|| {
                let Encoded(_body, _hash, _info) =
                    encode(black_box(&ZERO_MASTER), black_box(&data), C12).unwrap();
            })
        });

        let Encoded(body, hash, info) = encode(&ZERO_MASTER, &data, C12).unwrap();
        let hash_bytes = hash.as_bytes().to_vec();

        group.bench_function(format!("decode_{}mib", size / (1024 * 1024)), |b| {
            b.iter(|| {
                let _ = decode(
                    black_box(&ZERO_MASTER),
                    black_box(&hash_bytes),
                    black_box(&body),
                    black_box(info.padding_len),
                    C12,
                )
                .unwrap();
            })
        });

        let mut nicked = body.clone();
        // One 4 KiB leaf (stripe 0, symbol 0) so scrub has work without a 16 MiB copy each iter.
        if let Ok(ranges) = carbonado::stream::inboard_leaf_data_ranges(&nicked)
            && let Some(range) = ranges.first()
        {
            nicked[range.clone()].fill(0xEE);
        }

        group.bench_function(format!("scrub_{}mib", size / (1024 * 1024)), |b| {
            b.iter(|| {
                let _ = scrub(
                    black_box(&nicked),
                    black_box(&hash_bytes),
                    black_box(&info),
                    C12,
                )
                .unwrap();
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_c12_stripe);
criterion_main!(benches);
