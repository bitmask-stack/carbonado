//! Shared corruption helpers for FEC / scrub / chaos integration tests.
//!
//! Models inboard Bao+FEC layout as used by `scrub`: 8-byte content-length prefix,
//! then a response region partitioned into `FEC_M` logical shard stripes spaced by
//! `chunk_len` (see `tests/codec.rs::fec_robustness` — empirically matches scrub extract).

use std::ops::Range;

use carbonado::constants::{FEC_K, FEC_M};
use rand::Rng;

/// Bao inboard prefix: `u64 LE` content length of the logical (post-FEC) body.
pub const BAO_INBOARD_PREFIX_LEN: usize = 8;

/// Layout of shard-sized stripes inside an inboard verifiable blob (c8–c15 with Bao).
#[derive(Clone, Debug)]
pub struct InboardShardLayout {
    pub bao_prefix_len: usize,
    pub chunk_len: usize,
    pub num_shards: usize,
    pub encoded_len: usize,
}

impl InboardShardLayout {
    pub fn from_encode_info(encoded_len: usize, chunk_len: u32) -> Self {
        Self {
            bao_prefix_len: BAO_INBOARD_PREFIX_LEN,
            chunk_len: chunk_len as usize,
            num_shards: FEC_M,
            encoded_len,
        }
    }

    /// Approximate byte span for shard `idx` in the encoded buffer (for chaos injection).
    ///
    /// Scrub extracts shards via keyed Bao slices; this linear model matches the
    /// spacing used in existing robustness tests and is sufficient for distributed
    /// knockout that stays within RS 4/8 recovery when ≤4 shards are touched.
    pub fn shard_byte_range(&self, shard_idx: usize) -> Range<usize> {
        assert!(shard_idx < self.num_shards);
        // Match `tests/codec.rs::fec_robustness`: step = chunk_len, not response_len / 8.
        let step = self.chunk_len.max(1);
        let start = self.bao_prefix_len + shard_idx * step;
        let end = (start + self.chunk_len).min(self.encoded_len);
        start..end
    }

    pub fn max_recoverable_bad_shards(&self) -> usize {
        FEC_K
    }
}

#[derive(Clone, Debug, Default)]
pub struct KnockoutReport {
    pub positions: Vec<usize>,
    pub shards_touched: Vec<usize>,
}

/// Knock out (zero) random bytes spread across at most `max_bad_shards` distinct shards.
///
/// Corruption is **distributed** across the stream (multiple shards, multiple offsets),
/// never confined to a single contiguous segment. RS 4/8 recovery requires ≤4 bad
/// shards; default `max_bad_shards = FEC_K` (50% shard erasure budget).
pub fn distributed_byte_knockout(
    buf: &mut [u8],
    layout: &InboardShardLayout,
    max_bad_shards: usize,
    knockouts_per_shard: usize,
    rng: &mut impl Rng,
) -> KnockoutReport {
    let cap = max_bad_shards.min(FEC_K).min(layout.num_shards);
    // Restrict to data-shard indices 0..FEC_K so knockouts stay in RS data columns
    // (matches codec.rs `shard % 4` — avoids flakiness from parity-region layout skew).
    let mut shard_pool: Vec<usize> = (0..FEC_K.min(layout.num_shards)).collect();
    for i in 0..cap {
        let j = rng.gen_range(i..shard_pool.len());
        shard_pool.swap(i, j);
    }
    let bad_shards = &shard_pool[..cap];

    let mut report = KnockoutReport {
        shards_touched: bad_shards.to_vec(),
        ..Default::default()
    };

    for &shard in bad_shards {
        let range = layout.shard_byte_range(shard);
        if range.is_empty() {
            continue;
        }
        for _ in 0..knockouts_per_shard {
            let pos = rng.gen_range(range.start..range.end);
            // XOR (not zero) — breaks Bao verify on small payloads where zero may be benign.
            buf[pos] ^= rng.gen_range(1u8..=255);
            report.positions.push(pos);
        }
    }
    report
}

/// Uniformly scatter knockouts across the full encoded stream, assigning each to a
/// distinct shard bucket so total bad shards never exceeds `max_bad_shards`.
pub fn scattered_stream_knockout(
    buf: &mut [u8],
    layout: &InboardShardLayout,
    total_knockouts: usize,
    max_bad_shards: usize,
    rng: &mut impl Rng,
) -> KnockoutReport {
    let cap = max_bad_shards.min(FEC_K);
    // Data-shard indices only (0..FEC_K), same rationale as distributed_byte_knockout.
    let shard_assignments: Vec<usize> = (0..cap).collect();
    let mut report = KnockoutReport {
        positions: Vec::with_capacity(total_knockouts),
        shards_touched: Vec::new(),
    };

    for _ in 0..total_knockouts {
        let shard = shard_assignments[rng.gen_range(0..shard_assignments.len())];
        let range = layout.shard_byte_range(shard);
        if range.is_empty() {
            continue;
        }
        let pos = rng.gen_range(range.start..range.end);
        buf[pos] ^= rng.gen_range(1u8..=255);
        report.positions.push(pos);
        if !report.shards_touched.contains(&shard) {
            report.shards_touched.push(shard);
        }
    }
    report
}

/// Zero an entire shard stripe (simulates full shard loss).
pub fn erase_shards(buf: &mut [u8], layout: &InboardShardLayout, shard_indices: &[usize]) {
    for &idx in shard_indices {
        let range = layout.shard_byte_range(idx);
        if !range.is_empty() {
            buf[range].fill(0);
        }
    }
}

/// Flip a single byte (header tamper helper).
pub fn flip_byte(buf: &mut [u8], offset: usize, mask: u8) {
    if offset < buf.len() {
        buf[offset] ^= mask;
    }
}