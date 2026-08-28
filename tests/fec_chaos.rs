//! FEC stripe contracts: 16 KiB logical stripes of eight 4 KiB leaves (c12).
//!
//! Deterministic (no `rand` / `getrandom` in the named contracts). Scrub nicks
//! Bao leaf payloads via [`common::corruption::wipe_inboard_leaves`].

mod common;

use anyhow::Result;
use carbonado::constants::{FEC_M, SLICE_LEN};
use carbonado::stream::{leaf_index_to_stripe_symbol, stripe_symbol_to_leaf_index};
use carbonado::{
    decode, decode_outboard, error::CarbonadoError, extract_slice, scrub, scrub_outboard,
    structs::Encoded,
};
use common::corruption::{
    InboardShardLayout, OutboardShardLayout, every_other_leaf, first_n_leaves, last_n_leaves,
    leaves_with_symbol_slots, scattered_outboard_main_knockout, scattered_stream_knockout,
    wipe_inboard_leaves,
};
use common::format_matrix::{format_label, verification_fec_levels};
use common::{encode, encode_outboard};
use proptest::prelude::*;
use rand::Rng;

const CHAOS_PAYLOAD_SIZES: [usize; 5] = [4096, 16_384, 65_536, 131_072, 262_144];

/// Payload sizes spanning the 16 KiB RS stripe geometry edge (4 × 4 KiB data leaves).
/// Encode emits one 32 KiB inboard stripe per 16 KiB of padded logical, then the next stripe.
const STRIPE_BOUNDARY_SIZES: [usize; 5] = [16 * 1024 - 1, 16 * 1024, 16 * 1024 + 1, 32_768, 49_152];

const C12: u8 = 12;
const ZERO_MASTER: [u8; 32] = [0u8; 32];
const LEAF_FILL: u8 = 0xEE;

fn varied_payload(size: usize, seed: u8) -> Vec<u8> {
    // Period 251, not 256, so 16 KiB stripe boundaries are not identical slices.
    (0..size)
        .map(|i| (i % 251).wrapping_add(seed as usize) as u8)
        .collect()
}

#[test]
fn distributed_knockout_recovers_up_to_four_shards_public_bao_zfec() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];

    for level in verification_fec_levels().filter(|l| l & 1 == 0) {
        for &size in &CHAOS_PAYLOAD_SIZES {
            let payload = varied_payload(size, level);
            let Encoded(orig, hash, info) = encode(&key, &payload, level)?;
            let hash_bytes = hash.as_bytes();

            // Good data must not scrub.
            assert!(
                matches!(
                    scrub(&orig, hash_bytes, &info, level),
                    Err(CarbonadoError::UnnecessaryScrub)
                ),
                "unnecessary scrub for {} size {}",
                format_label(level),
                size
            );

            let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);

            // Distributed knockouts spread across ≤4 data shards (50% RS budget).
            let mut corrupted = orig.clone();
            let knockouts = (size / 512).clamp(8, 48);
            let report = scattered_stream_knockout(
                &mut corrupted,
                &layout,
                knockouts,
                layout.max_recoverable_bad_shards(),
                &mut rng,
            );
            assert!(
                report.shards_touched.len() <= 4,
                "must stay within RS recovery: {:?}",
                report.shards_touched
            );
            assert!(
                !report.positions.is_empty(),
                "knockouts require non-empty data shard ranges"
            );
            assert!(
                matches!(
                    scrub(&orig, hash_bytes, &info, level),
                    Err(CarbonadoError::UnnecessaryScrub)
                ),
                "sanity: pristine must not scrub for {} size {}",
                format_label(level),
                size
            );

            let recovered = scrub(&corrupted, hash_bytes, &info, level).unwrap_or_else(|e| {
                panic!(
                    "scrub failed level {} size {} shards {:?}: {e}",
                    format_label(level),
                    size,
                    report.shards_touched
                )
            });
            assert_eq!(recovered, orig, "byte-identical recovery");

            let dec = decode(&key, hash_bytes, &recovered, info.padding_len, level)?;
            assert_eq!(dec, payload);
        }
    }
    Ok(())
}

#[test]
fn encrypted_distributed_knockout_roundtrip_content() -> Result<()> {
    let mut rng = rand::thread_rng();
    for level in [13u8, 15] {
        let payload = varied_payload(32_768, level);
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);
        let Encoded(orig, hash, info) = encode(&key, &payload, level)?;
        let hash_bytes = hash.as_bytes();

        let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);
        let mut corrupted = orig.clone();
        scattered_stream_knockout(&mut corrupted, &layout, 80, 4, &mut rng);

        let recovered = scrub(&corrupted, hash_bytes, &info, level)?;
        assert_eq!(recovered, orig);
        let dec = decode(&key, hash_bytes, &recovered, info.padding_len, level)?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn outboard_distributed_knockout_scrub_recover_c12_c14_c15() -> Result<()> {
    let mut rng = rand::thread_rng();

    for level in [12u8, 14, 15] {
        let key = if level & 1 != 0 {
            let mut k = [0u8; 32];
            rng.fill(&mut k);
            k
        } else {
            [0u8; 32]
        };
        let payload = varied_payload(32_768, level);
        let oenc = encode_outboard(&key, &payload, level)?;
        let hash_bytes = oenc.hash.as_bytes();
        let ob = oenc.verification_outboard.as_deref().expect("bao outboard");
        let par = oenc.fec_parity.as_deref().expect("fec parity");

        assert!(matches!(
            scrub_outboard(
                &oenc.main,
                Some(ob),
                Some(par),
                &oenc.info,
                level,
                hash_bytes
            ),
            Err(CarbonadoError::UnnecessaryScrub)
        ));

        let layout = OutboardShardLayout::from_outboard_encode(
            oenc.main.len(),
            par.len(),
            oenc.info.chunk_len,
        );
        let mut corrupted = oenc.main.clone();
        let report = scattered_outboard_main_knockout(
            &mut corrupted,
            &layout,
            48,
            layout.max_recoverable_bad_shards(),
            &mut rng,
        );
        assert!(
            report.shards_touched.len() <= 4,
            "outboard chaos must stay within RS budget: {:?}",
            report.shards_touched
        );
        assert!(
            !report.positions.is_empty(),
            "knockouts spread across bare main"
        );

        let recovered = scrub_outboard(
            &corrupted,
            Some(ob),
            Some(par),
            &oenc.info,
            level,
            hash_bytes,
        )?;
        assert_eq!(
            recovered, oenc.main,
            "scrub_outboard byte-identical recovery"
        );

        let dec = decode_outboard(
            &key,
            hash_bytes,
            &recovered,
            Some(ob),
            Some(par),
            oenc.info.padding_len,
            level,
        )?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn fec_with_parity_outboard_decode_without_scrub() -> Result<()> {
    let key = [0u8; 32];

    // Zfec-only outboard (no Bao gate): decode_outboard calls fec_with_parity directly.
    // Truncating bare main erases trailing data shards; RS reconstructs from intact `.par`.
    // XOR bit-flip corruption on Bao+Zfec paths still requires scrub_outboard.
    // c8 only: bare main bytes map 1:1 to pre-FEC logical body (c10 Snappy shrinks main vs chunk).
    for level in [8u8] {
        for &size in &[16_384usize, 32_768] {
            let payload = varied_payload(size, level);
            let oenc = encode_outboard(&key, &payload, level)?;
            let par = oenc.fec_parity.as_deref().expect("parity sidecar");
            let chunk = oenc.info.chunk_len as usize;

            let erase_shards = if size > 16_384 { 2 } else { 1 };
            let keep = oenc.main.len().saturating_sub(erase_shards * chunk);
            assert!(
                keep >= chunk,
                "truncation must leave at least one data shard"
            );
            let truncated = &oenc.main[..keep];

            let dec = decode_outboard(
                &key,
                oenc.hash.as_bytes(),
                truncated,
                None,
                Some(par),
                oenc.info.padding_len,
                level,
            )?;
            assert_eq!(
                dec,
                payload,
                "fec_with_parity erasure recovery {} size {} keep {}",
                format_label(level),
                size,
                keep
            );
        }
    }
    Ok(())
}

#[test]
fn scrub_outboard_truncated_main_recovers_c14() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];
    // Random payload resists Snappy shrink so bare main spans multiple FEC data shards.
    let mut payload = vec![0u8; 131_072];
    rng.fill(&mut payload[..]);
    let oenc = encode_outboard(&key, &payload, 14)?;
    let hash_bytes = oenc.hash.as_bytes();
    let ob = oenc.verification_outboard.as_deref().expect("bao outboard");
    let par = oenc.fec_parity.as_deref().expect("fec parity");
    let chunk = oenc.info.chunk_len as usize;

    // Truncate bare main (JBOD tail loss); parity retains encode-time geometry.
    let erase_shards = if oenc.main.len() >= 3 * chunk { 2 } else { 1 };
    let keep = oenc.main.len().saturating_sub(erase_shards * chunk);
    assert!(
        keep >= chunk,
        "truncation must leave at least one data shard (main {} chunk {})",
        oenc.main.len(),
        chunk
    );
    let truncated = &oenc.main[..keep];

    let recovered = scrub_outboard(truncated, Some(ob), Some(par), &oenc.info, 14, hash_bytes)?;
    assert_eq!(recovered, oenc.main);

    let dec = decode_outboard(
        &key,
        hash_bytes,
        &recovered,
        Some(ob),
        Some(par),
        oenc.info.padding_len,
        14,
    )?;
    assert_eq!(dec, payload);
    Ok(())
}

#[test]
fn stripe_boundary_inboard_distributed_chaos() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];

    for &size in &STRIPE_BOUNDARY_SIZES {
        let payload = varied_payload(size, 12);
        let Encoded(orig, hash, info) = encode(&key, &payload, 12)?;
        let hash_bytes = hash.as_bytes();
        let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);

        let mut corrupted = orig.clone();
        let knockouts = (size / 256).clamp(12, 64);
        let report = scattered_stream_knockout(&mut corrupted, &layout, knockouts, 4, &mut rng);
        assert!(
            report.shards_touched.len() <= 4,
            "stripe-boundary size {size} shards {:?}",
            report.shards_touched
        );

        let recovered = scrub(&corrupted, hash_bytes, &info, 12)?;
        assert_eq!(
            recovered, orig,
            "inboard stripe-boundary recovery size {size}"
        );

        let dec = decode(&key, hash_bytes, &recovered, info.padding_len, 12)?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn stripe_boundary_outboard_scrub_chaos() -> Result<()> {
    let mut rng = rand::thread_rng();
    let key = [0u8; 32];

    for &size in &STRIPE_BOUNDARY_SIZES {
        let payload = varied_payload(size, 14);
        let oenc = encode_outboard(&key, &payload, 14)?;
        let hash_bytes = oenc.hash.as_bytes();
        let ob = oenc.verification_outboard.as_deref().expect("bao outboard");
        let par = oenc.fec_parity.as_deref().expect("fec parity");

        let layout = OutboardShardLayout::from_outboard_encode(
            oenc.main.len(),
            par.len(),
            oenc.info.chunk_len,
        );
        let mut corrupted = oenc.main.clone();
        let knockouts = (size / 256).clamp(12, 64);
        let report =
            scattered_outboard_main_knockout(&mut corrupted, &layout, knockouts, 4, &mut rng);
        assert!(
            report.shards_touched.len() <= 4,
            "outboard stripe-boundary size {size} shards {:?}",
            report.shards_touched
        );
        assert!(
            !report.positions.is_empty(),
            "outboard stripe-boundary knockouts size {size}"
        );

        let recovered =
            scrub_outboard(&corrupted, Some(ob), Some(par), &oenc.info, 14, hash_bytes)?;
        assert_eq!(
            recovered, oenc.main,
            "outboard stripe-boundary scrub recovery size {size}"
        );

        let dec = decode_outboard(
            &key,
            hash_bytes,
            &recovered,
            Some(ob),
            Some(par),
            oenc.info.padding_len,
            14,
        )?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn five_shard_touch_fails_scrub_proves_fifty_percent_limit() -> Result<()> {
    // Five 4 KiB leaves in stripe 0 (symbols 0..5): above the RS 4/8 budget.
    let payload = varied_payload(32_768, 12);
    let Encoded(orig, hash, info) = encode(&ZERO_MASTER, &payload, C12)?;
    let hash_bytes = hash.as_bytes();
    let mut corrupted = orig.clone();
    wipe_inboard_leaves(&mut corrupted, &[0, 1, 2, 3, 4], LEAF_FILL);

    let err = scrub(&corrupted, hash_bytes, &info, C12).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidScrubbedHash),
        "5/8 leaf loss in one stripe must be irrecoverable, got {err:?}"
    );
    Ok(())
}

/// c12, payload larger than one 16 KiB stripe: each Bao leaf is 4 KiB, not a tall
/// `padded_len / 4` column.
#[test]
fn c12_leaf_is_4kib_not_tall_column() -> Result<()> {
    let payload = varied_payload(32_768, 7);
    let Encoded(orig, hash, info) = encode(&ZERO_MASTER, &payload, C12)?;
    let hash_bytes = hash.as_bytes();

    assert_eq!(
        info.chunk_len, SLICE_LEN,
        "RS symbol / Bao leaf is 4 KiB, not padded/4 tall columns (got {})",
        info.chunk_len
    );
    let leaf0 = extract_slice(&orig, 0, hash_bytes, C12)?;
    assert_eq!(leaf0.len(), SLICE_LEN as usize, "leaf 0 size");
    assert_eq!(&leaf0[..], &payload[0..SLICE_LEN as usize]);

    // Stripe layout: leaves 0..3 are data of stripe 0; 4..7 are parity; leaf 8
    // is the first data leaf of stripe 1 (logical[16384..20480]). Tall columns
    // put logical[16384..20480] at leaf 4 instead.
    let leaf4 = extract_slice(&orig, 4, hash_bytes, C12)?;
    assert_eq!(leaf4.len(), SLICE_LEN as usize);
    assert_ne!(
        &leaf4[..],
        &payload[16_384..16_384 + SLICE_LEN as usize],
        "leaf 4 must be stripe-0 parity, not the start of a tall column"
    );
    let leaf8 = extract_slice(&orig, 8, hash_bytes, C12)?;
    assert_eq!(&leaf8[..], &payload[16_384..16_384 + SLICE_LEN as usize]);
    assert_eq!(leaf_index_to_stripe_symbol(4), (0, 4));
    assert_eq!(leaf_index_to_stripe_symbol(8), (1, 0));
    assert_eq!(stripe_symbol_to_leaf_index(1, 0), 8);
    Ok(())
}

/// Four symbol slots nicked (one leaf in each of four positions, across stripes) recovers.
#[test]
fn four_symbol_slots_nicked_across_stripes_recovers() -> Result<()> {
    let payload = varied_payload(49_152, 9);
    let Encoded(orig, hash, info) = encode(&ZERO_MASTER, &payload, C12)?;
    let hash_bytes = hash.as_bytes();
    // Three stripes. Nick slot 0 in stripe 0, slot 2 in stripe 1, slot 5 in
    // stripe 2, slot 7 in stripe 0: four positions, spread across stripes.
    let nicks = [
        stripe_symbol_to_leaf_index(0, 0),
        stripe_symbol_to_leaf_index(1, 2),
        stripe_symbol_to_leaf_index(2, 5),
        stripe_symbol_to_leaf_index(0, 7),
    ];
    let mut corrupted = orig.clone();
    wipe_inboard_leaves(&mut corrupted, &nicks, LEAF_FILL);
    let recovered = scrub(&corrupted, hash_bytes, &info, C12)?;
    assert_eq!(recovered, orig);
    let dec = decode(&ZERO_MASTER, hash_bytes, &recovered, info.padding_len, C12)?;
    assert_eq!(dec, payload);
    Ok(())
}

/// Five leaves bad in one stripe fails.
#[test]
fn five_leaves_bad_in_one_stripe_fails() -> Result<()> {
    let payload = varied_payload(32_768, 11);
    let Encoded(orig, hash, info) = encode(&ZERO_MASTER, &payload, C12)?;
    let hash_bytes = hash.as_bytes();
    let bad: Vec<u32> = (0..5).map(|s| stripe_symbol_to_leaf_index(1, s)).collect();
    let mut corrupted = orig.clone();
    wipe_inboard_leaves(&mut corrupted, &bad, LEAF_FILL);
    let err = scrub(&corrupted, hash_bytes, &info, C12).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidScrubbedHash),
        "five bad leaves in stripe 1 must fail, got {err:?}"
    );
    Ok(())
}

fn assert_fifty_percent_then_plus_one(
    payload: &[u8],
    mask: &[u32],
    plus_one: u32,
    label: &str,
) -> Result<()> {
    let Encoded(orig, hash, info) = encode(&ZERO_MASTER, payload, C12)?;
    let hash_bytes = hash.as_bytes();
    let leaf_count = info.verifiable_slice_count;
    assert_eq!(
        mask.len() * 2,
        leaf_count as usize,
        "{label}: mask must be exactly 50% of {leaf_count} leaves"
    );

    let mut half = orig.clone();
    wipe_inboard_leaves(&mut half, mask, LEAF_FILL);
    let recovered = scrub(&half, hash_bytes, &info, C12).unwrap_or_else(|e| {
        panic!("{label}: 50% leaf wipe must recover, got {e}");
    });
    assert_eq!(recovered, orig, "{label}: 50% recovered body");
    let dec = decode(&ZERO_MASTER, hash_bytes, &recovered, info.padding_len, C12)?;
    assert_eq!(dec, payload, "{label}: 50% decoded payload");

    let mut plus = orig.clone();
    let mut plus_mask = mask.to_vec();
    plus_mask.push(plus_one);
    wipe_inboard_leaves(&mut plus, &plus_mask, LEAF_FILL);
    let err = scrub(&plus, hash_bytes, &info, C12).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidScrubbedHash),
        "{label}: 50%+1 must fail, got {err:?}"
    );
    Ok(())
}

/// First four symbol slots of every stripe (`leaf % 8 < 4`). That is the first
/// half of each stripe's eight leaves, 50% of all leaves, 4 of 8 symbols per stripe.
#[test]
fn fifty_percent_first_half_of_leaves_then_plus_one() -> Result<()> {
    let payload = varied_payload(65_536, 1);
    let Encoded(_, _, info) = encode(&ZERO_MASTER, &payload, C12)?;
    let n = info.verifiable_slice_count;
    let mask = leaves_with_symbol_slots(n, &[0, 1, 2, 3]);
    let plus_one = stripe_symbol_to_leaf_index(0, 4);
    assert_fifty_percent_then_plus_one(&payload, &mask, plus_one, "first half")
}

/// Last four symbol slots of every stripe (`leaf % 8 >= 4`).
#[test]
fn fifty_percent_last_half_of_leaves_then_plus_one() -> Result<()> {
    let payload = varied_payload(65_536, 2);
    let Encoded(_, _, info) = encode(&ZERO_MASTER, &payload, C12)?;
    let n = info.verifiable_slice_count;
    let mask = leaves_with_symbol_slots(n, &[4, 5, 6, 7]);
    let plus_one = stripe_symbol_to_leaf_index(0, 0);
    assert_fifty_percent_then_plus_one(&payload, &mask, plus_one, "last half")
}

/// Even leaf indices: slots 0,2,4,6 of every stripe.
#[test]
fn fifty_percent_every_other_leaf_then_plus_one() -> Result<()> {
    let payload = varied_payload(65_536, 3);
    let Encoded(_, _, info) = encode(&ZERO_MASTER, &payload, C12)?;
    let n = info.verifiable_slice_count;
    let mask = every_other_leaf(n, 0);
    let plus_one = 1;
    assert_fifty_percent_then_plus_one(&payload, &mask, plus_one, "every other")
}

/// Four-of-eight slots 0,3,4,6 in every stripe (mixed data and parity).
#[test]
fn fifty_percent_four_of_eight_slots_then_plus_one() -> Result<()> {
    let payload = varied_payload(65_536, 4);
    let Encoded(_, _, info) = encode(&ZERO_MASTER, &payload, C12)?;
    let n = info.verifiable_slice_count;
    let mask = leaves_with_symbol_slots(n, &[0, 3, 4, 6]);
    let plus_one = stripe_symbol_to_leaf_index(0, 1);
    assert_fifty_percent_then_plus_one(&payload, &mask, plus_one, "four-of-eight slots")
}

/// Coffee-cup fill on an 8×8 leaf square.
///
/// Payload is 128 KiB (8 × 16 KiB stripes → 64 inboard leaves). Leaves sit in
/// row-major order: `leaf = row * 8 + col`, `row` is the stripe, `col` is the
/// RS symbol (0..3 data, 4..7 parity).
///
/// Cell centers are `(col + 0.5, row + 0.5)`. The circle is at the square
/// center `(4.0, 4.0)`. Rank every cell by Euclidean distance to that center,
/// then by leaf index.
///
/// Grow the mask in that order. Skip a leaf when its stripe already has 4
/// marked (RS 4/8 can take at most 4 erasures per stripe). Stop at 32 leaves
/// (exactly 50%). The +1 leaf is the next in rank order: the first that would
/// be a fifth erasure in some stripe.
///
/// Without the per-stripe cap, the nearest 32 cells to center would mark 6
/// leaves in the middle rows. The cap flattens the cup to the 4/8 budget
/// while still preferring the center.
fn coffee_cup_mask_128kib() -> (Vec<u32>, u32) {
    const SIDE: u32 = 8;
    const LEAVES: u32 = SIDE * SIDE;
    let center = 4.0f64;
    let mut ranked: Vec<(u32, u64, u32)> = (0..LEAVES)
        .map(|leaf| {
            let row = leaf / SIDE;
            let col = leaf % SIDE;
            let dx = (col as f64 + 0.5) - center;
            let dy = (row as f64 + 0.5) - center;
            let dist2_bits = (dx * dx + dy * dy).to_bits();
            (leaf, dist2_bits, leaf)
        })
        .collect();
    ranked.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));

    let mut mask = Vec::with_capacity(32);
    let mut per_stripe = [0u8; FEC_M];
    let mut plus_one = None;
    for &(leaf, _, _) in &ranked {
        let stripe = (leaf / FEC_M as u32) as usize;
        if mask.len() < 32 {
            if per_stripe[stripe] < 4 {
                mask.push(leaf);
                per_stripe[stripe] += 1;
            }
            continue;
        }
        plus_one = Some(leaf);
        break;
    }
    let plus_one = plus_one.expect("ranked list must supply a +1 leaf after 50%");
    (mask, plus_one)
}

#[test]
fn fifty_percent_coffee_cup_then_plus_one() -> Result<()> {
    let payload = varied_payload(128 * 1024, 5);
    let (mask, plus_one) = coffee_cup_mask_128kib();
    assert_eq!(mask.len(), 32, "coffee-cup mask is 50% of 64 leaves");
    assert_eq!(
        first_n_leaves(64, 32).len(),
        32,
        "sanity: first-half helper"
    );
    assert_eq!(last_n_leaves(64, 32).len(), 32);
    assert_fifty_percent_then_plus_one(&payload, &mask, plus_one, "coffee-cup")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

    #[test]
    fn proptest_distributed_knockout_c12(
        size in 4096usize..=65536,
        knockouts in 8usize..=64,
    ) {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let Encoded(orig, hash, info) = encode(&[0u8; 32], &payload, 12)?;
        let hash_bytes = hash.as_bytes();
        let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);

        let mut corrupted = orig.clone();
        let mut rng = rand::thread_rng();
        let report = scattered_stream_knockout(&mut corrupted, &layout, knockouts, 4, &mut rng);
        prop_assert!(report.shards_touched.len() <= 4);
        prop_assert!(!report.positions.is_empty());

        let recovered = scrub(&corrupted, hash_bytes, &info, 12)?;
        prop_assert_eq!(&recovered, &orig);
        let dec = decode(&[0u8; 32], hash_bytes, &recovered, info.padding_len, 12)?;
        prop_assert_eq!(dec, payload);
    }
}
