//! Shared corruption helpers for FEC / scrub / chaos integration tests.
//!
//! Inboard Bao+FEC bodies are a sequence of 4 KiB Bao leaves: eight leaves per
//! 16 KiB logical stripe (4 data + 4 parity). Leaf payload ranges come from
//! [`carbonado::stream::inboard_leaf_data_ranges`] so nicks hit leaf data, not
//! parent hash pairs.

use std::ops::Range;

use carbonado::constants::{FEC_K, FEC_M};
use carbonado::stream::inboard_leaf_data_ranges;
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

    /// Linear fallback span for shard `idx` (`bao_prefix + idx * chunk_len`).
    ///
    /// Stripe datagrams and `erase_shards` use [`inboard_symbol_payload`] (every
    /// 4 KiB leaf with that RS symbol). This range is only the last-resort map
    /// when `inboard_leaf_data_ranges` cannot walk the body.
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

fn leaf_ranges_or_linear(buf: &[u8], layout: &InboardShardLayout) -> Vec<Range<usize>> {
    match inboard_leaf_data_ranges(buf) {
        Ok(ranges) if !ranges.is_empty() => ranges,
        _ => (0..layout.num_shards)
            .map(|i| layout.shard_byte_range(i))
            .filter(|r| !r.is_empty())
            .collect(),
    }
}

fn leaf_symbol(index: usize) -> usize {
    index % FEC_M
}

/// Concatenate every 4 KiB inboard leaf whose RS symbol is `symbol` (`0..FEC_M`).
///
/// One UDP chaos datagram is this concat, not a tall `chunk_len` column.
pub fn inboard_symbol_payload(buf: &[u8], layout: &InboardShardLayout, symbol: usize) -> Vec<u8> {
    assert!(symbol < layout.num_shards);
    let mut out = Vec::new();
    for (i, range) in leaf_ranges_or_linear(buf, layout).into_iter().enumerate() {
        if leaf_symbol(i) == symbol && !range.is_empty() {
            out.extend_from_slice(&buf[range]);
        }
    }
    out
}

/// Write `payload` into every 4 KiB leaf with RS `symbol`, in leaf order.
///
/// `Err((got, expected))` when `payload` is not the concat of those leaf ranges.
pub fn write_inboard_symbol_payload(
    buf: &mut [u8],
    layout: &InboardShardLayout,
    symbol: usize,
    payload: &[u8],
) -> Result<(), (usize, usize)> {
    assert!(symbol < layout.num_shards);
    let ranges = leaf_ranges_or_linear(buf, layout);
    let expected: usize = ranges
        .iter()
        .enumerate()
        .filter(|(i, r)| leaf_symbol(*i) == symbol && !r.is_empty())
        .map(|(_, r)| r.len())
        .sum();
    if payload.len() != expected {
        return Err((payload.len(), expected));
    }
    let mut off = 0usize;
    for (i, range) in ranges.into_iter().enumerate() {
        if leaf_symbol(i) == symbol && !range.is_empty() {
            let n = range.len();
            buf[range].copy_from_slice(&payload[off..off + n]);
            off += n;
        }
    }
    Ok(())
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
    let ranges = leaf_ranges_or_linear(buf, layout);
    let leaf_assignments: Vec<usize> = (0..ranges.len())
        .filter(|&i| leaf_symbol(i) < cap && !ranges[i].is_empty())
        .collect();
    let mut report = KnockoutReport {
        positions: Vec::with_capacity(total_knockouts),
        shards_touched: Vec::new(),
    };
    if leaf_assignments.is_empty() {
        return report;
    }

    let max_attempts = total_knockouts.saturating_mul(8).max(1);
    let mut attempts = 0usize;
    while report.positions.len() < total_knockouts && attempts < max_attempts {
        let leaf = leaf_assignments[rng.gen_range(0..leaf_assignments.len())];
        let range = &ranges[leaf];
        if range.is_empty() {
            attempts += 1;
            continue;
        }
        let pos = rng.gen_range(range.start..range.end);
        buf[pos] ^= rng.gen_range(1u8..=255);
        report.positions.push(pos);
        let symbol = leaf_symbol(leaf);
        if !report.shards_touched.contains(&symbol) {
            report.shards_touched.push(symbol);
        }
        attempts += 1;
    }
    report
}

/// Zero every inboard leaf whose symbol is in `shard_indices` (simulates slot loss).
pub fn erase_shards(buf: &mut [u8], layout: &InboardShardLayout, shard_indices: &[usize]) {
    let ranges = leaf_ranges_or_linear(buf, layout);
    for (i, range) in ranges.iter().enumerate() {
        if shard_indices.contains(&leaf_symbol(i)) && !range.is_empty() {
            buf[range.clone()].fill(0);
        }
    }
}

/// Flip a single byte (header tamper helper).
pub fn flip_byte(buf: &mut [u8], offset: usize, mask: u8) {
    if offset < buf.len() {
        buf[offset] ^= mask;
    }
}

/// Fill selected 4 KiB Bao leaves in an inboard blob with `fill`.
///
/// Parent hash pairs are left intact so other leaves still Bao-verify.
pub fn wipe_inboard_leaves(buf: &mut [u8], leaf_indices: &[u32], fill: u8) {
    let ranges = inboard_leaf_data_ranges(buf).expect("inboard leaf ranges");
    for &idx in leaf_indices {
        let i = idx as usize;
        if i < ranges.len() {
            let range = ranges[i].clone();
            if range.end <= buf.len() {
                buf[range].fill(fill);
            }
        }
    }
}

/// Every inboard leaf index whose symbol is in `slots` (0..8).
pub fn leaves_with_symbol_slots(leaf_count: u32, slots: &[u8]) -> Vec<u32> {
    (0..leaf_count)
        .filter(|leaf| {
            let symbol = (*leaf % FEC_M as u32) as u8;
            slots.contains(&symbol)
        })
        .collect()
}

/// First `count` leaf indices in `[0, leaf_count)` (row-major order).
pub fn first_n_leaves(leaf_count: u32, count: u32) -> Vec<u32> {
    (0..count.min(leaf_count)).collect()
}

/// Last `count` leaf indices in `[0, leaf_count)`.
pub fn last_n_leaves(leaf_count: u32, count: u32) -> Vec<u32> {
    let count = count.min(leaf_count);
    ((leaf_count - count)..leaf_count).collect()
}

/// Every other leaf (`leaf % 2 == 0`) up to `count` (50% when `count == leaf_count / 2`).
pub fn every_other_leaf(leaf_count: u32, start_parity: u32) -> Vec<u32> {
    (0..leaf_count)
        .filter(|leaf| leaf % 2 == start_parity)
        .collect()
}

/// Layout of data-shard stripes inside an outboard bare main (c8–c15 with Zfec).
///
/// Outboard bare `main` stores the pre-FEC logical body; `scrub_outboard` and
/// `fec_with_parity` read data shards at fixed `chunk_len` strides. Parity
/// shards live in the separate `.par` sidecar.
#[derive(Clone, Debug)]
pub struct OutboardShardLayout {
    pub chunk_len: usize,
    pub main_len: usize,
    pub parity_len: usize,
}

impl OutboardShardLayout {
    pub fn from_outboard_encode(main_len: usize, parity_len: usize, chunk_len: u32) -> Self {
        Self {
            chunk_len: chunk_len as usize,
            main_len,
            parity_len,
        }
    }

    /// Data shard `idx` (0..FEC_K) byte span in bare main.
    pub fn data_shard_byte_range(&self, shard_idx: usize) -> Range<usize> {
        assert!(shard_idx < FEC_K);
        let start = shard_idx * self.chunk_len;
        let end = (start + self.chunk_len).min(self.main_len);
        start..end
    }

    /// Parity shard `idx` (0..FEC_M - FEC_K) byte span in `.par` sidecar.
    pub fn parity_shard_byte_range(&self, parity_shard_idx: usize) -> Range<usize> {
        assert!(parity_shard_idx < FEC_M - FEC_K);
        let start = parity_shard_idx * self.chunk_len;
        let end = (start + self.chunk_len).min(self.parity_len);
        start..end
    }

    pub fn max_recoverable_bad_shards(&self) -> usize {
        FEC_K
    }
}

/// Scatter knockouts across outboard bare main data shards (≤ `max_bad_shards`).
///
/// Does not touch the `.par` sidecar — models JBOD main-disk corruption with
/// intact parity for `fec_with_parity` / `scrub_outboard` recovery.
pub fn scattered_outboard_main_knockout(
    main: &mut [u8],
    layout: &OutboardShardLayout,
    total_knockouts: usize,
    max_bad_shards: usize,
    rng: &mut impl Rng,
) -> KnockoutReport {
    let cap = max_bad_shards.min(FEC_K);
    let shard_assignments: Vec<usize> = (0..cap)
        .filter(|&s| !layout.data_shard_byte_range(s).is_empty())
        .collect();
    let mut report = KnockoutReport {
        positions: Vec::with_capacity(total_knockouts),
        shards_touched: Vec::new(),
    };
    if shard_assignments.is_empty() {
        return report;
    }

    let max_attempts = total_knockouts.saturating_mul(8).max(1);
    let mut attempts = 0usize;
    while report.positions.len() < total_knockouts && attempts < max_attempts {
        let shard = shard_assignments[rng.gen_range(0..shard_assignments.len())];
        let range = layout.data_shard_byte_range(shard);
        if range.is_empty() {
            attempts += 1;
            continue;
        }
        let pos = rng.gen_range(range.start..range.end);
        main[pos] ^= rng.gen_range(1u8..=255);
        report.positions.push(pos);
        if !report.shards_touched.contains(&shard) {
            report.shards_touched.push(shard);
        }
        attempts += 1;
    }
    report
}
