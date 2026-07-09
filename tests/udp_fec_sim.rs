//! UDP / FEC chaos injection model (RS 4/8) — **not** normative on-disk wire layout.
//!
//! This crate simulates JBOD/UDP **shard erasure** using the same approximate
//! `InboardShardLayout` helper as `tests/common/corruption.rs` and `tests/fec_chaos.rs`
//! (`shard_byte_range` spaced by `chunk_len` from the 8-byte Bao prefix). That linear
//! model is for distributed knockout / `erase_shards` injection only; true inboard
//! c12/c14 wire is `[u64 LE content_len | keyed Bao response]` with FEC stripes inside
//! the Bao envelope (`src/stream/encode.rs`, `src/stream/bao.rs`).
//!
//! **Intended contract under test:** if a transport maps one logical RS shard column to
//! one datagram payload *at the scrub injection coordinates*, then dropping ≤4 datagrams
//! should match `erase_shards` + `scrub` recovery. At five drops: c12 is irrecoverable
//! (`InvalidScrubbedHash`); c14 may still recover (Snappy/geometry asymmetry — see
//! `five_datagram_drops_c12_irrecoverable_c14_documents_asymmetry`). Bao provides keyed
//! verification independent of datagram arrival order.
//!
//! Format coverage: 4-drop recovery uses c14 (Snappy+Bao+Zfec); 5-drop asymmetry is
//! exercised on both c12 (Bao+Zfec) and c14.

mod common;

use anyhow::Result;
use carbonado::{
    constants::{FEC_K, FEC_M},
    decode, encode,
    error::CarbonadoError,
    scrub,
    structs::Encoded,
};
use common::corruption::{erase_shards, InboardShardLayout, OutboardShardLayout};

/// Chaos-injection datagram: `shard_index` + payload at `InboardShardLayout` coordinates.
#[derive(Clone, Debug)]
struct FecDatagram {
    shard_index: usize,
    payload: Vec<u8>,
}

/// Split encoded buffer into eight chaos-injection shard slots (helper-internal geometry).
fn inboard_to_datagrams(encoded: &[u8], layout: &InboardShardLayout) -> Vec<FecDatagram> {
    (0..layout.num_shards)
        .map(|shard_index| {
            let range = layout.shard_byte_range(shard_index);
            FecDatagram {
                shard_index,
                payload: encoded[range].to_vec(),
            }
        })
        .collect()
}

/// Reassemble buffer from received datagrams into `buf` (typically zero-filled on loss).
/// Unwritten shard slots remain as in `buf`. Duplicate `shard_index`: **last writer wins**.
fn datagrams_to_inboard(
    datagrams: &[FecDatagram],
    layout: &InboardShardLayout,
    buf: &mut [u8],
) -> Result<()> {
    for dgram in datagrams {
        let range = layout.shard_byte_range(dgram.shard_index);
        if range.len() != dgram.payload.len() {
            anyhow::bail!(
                "datagram shard {} payload len {} != layout range len {}",
                dgram.shard_index,
                dgram.payload.len(),
                range.len()
            );
        }
        buf[range].copy_from_slice(&dgram.payload);
    }
    Ok(())
}

/// Simulate datagram loss at chaos-injection coordinates: erase dropped shard stripes,
/// then overlay surviving datagram payloads (arrival order independent).
fn reassemble_after_datagram_loss(
    orig: &[u8],
    datagrams: &[FecDatagram],
    layout: &InboardShardLayout,
    dropped_shard_indices: &[usize],
) -> Result<Vec<u8>> {
    let received: Vec<FecDatagram> = datagrams
        .iter()
        .filter(|d| !dropped_shard_indices.contains(&d.shard_index))
        .cloned()
        .collect();
    let mut buf = orig.to_vec();
    erase_shards(&mut buf, layout, dropped_shard_indices);
    datagrams_to_inboard(&received, layout, &mut buf)?;
    Ok(buf)
}

/// Drop datagrams by erasing the corresponding shard stripes (chaos injection).
fn datagram_loss_to_corrupted_inboard(
    template: &[u8],
    layout: &InboardShardLayout,
    dropped_shard_indices: &[usize],
) -> Vec<u8> {
    let mut buf = template.to_vec();
    erase_shards(&mut buf, layout, dropped_shard_indices);
    buf
}

/// Fixed 4-of-8 drop subsets (stable; supplements one seeded random case).
fn varied_payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i.wrapping_mul(13).wrapping_add(seed as usize)) as u8)
        .collect()
}

const FOUR_DROP_SUBSETS: &[&[usize]] =
    &[&[0, 1, 2, 3], &[0, 2, 4, 6], &[1, 3, 5, 7], &[4, 5, 6, 7]];

/// Chaos-injection datagram for one outboard FEC parity shard (centralized bundle slice).
#[derive(Clone, Debug)]
struct ParityDatagram {
    parity_shard_index: usize,
    payload: Vec<u8>,
}

fn parity_to_datagrams(fec_par: &[u8], layout: &OutboardShardLayout) -> Vec<ParityDatagram> {
    (0..FEC_M - FEC_K)
        .map(|idx| {
            let range = layout.parity_shard_byte_range(idx);
            ParityDatagram {
                parity_shard_index: idx,
                payload: fec_par[range].to_vec(),
            }
        })
        .collect()
}

fn datagrams_to_parity(
    datagrams: &[ParityDatagram],
    layout: &OutboardShardLayout,
    buf: &mut [u8],
) -> Result<()> {
    for dgram in datagrams {
        let range = layout.parity_shard_byte_range(dgram.parity_shard_index);
        if range.len() != dgram.payload.len() {
            anyhow::bail!(
                "parity datagram shard {} payload len {} != layout range len {}",
                dgram.parity_shard_index,
                dgram.payload.len(),
                range.len()
            );
        }
        buf[range].copy_from_slice(&dgram.payload);
    }
    Ok(())
}

fn erase_parity_shards(buf: &mut [u8], layout: &OutboardShardLayout, shard_indices: &[usize]) {
    for &idx in shard_indices {
        let range = layout.parity_shard_byte_range(idx);
        if !range.is_empty() {
            buf[range].fill(0);
        }
    }
}

/// Simulate bundle parity datagram loss: zero dropped parity stripes, overlay survivors.
fn reassemble_parity_after_datagram_loss(
    orig: &[u8],
    datagrams: &[ParityDatagram],
    layout: &OutboardShardLayout,
    dropped_shard_indices: &[usize],
) -> Result<Vec<u8>> {
    let received: Vec<ParityDatagram> = datagrams
        .iter()
        .filter(|d| !dropped_shard_indices.contains(&d.parity_shard_index))
        .cloned()
        .collect();
    let mut buf = orig.to_vec();
    erase_parity_shards(&mut buf, layout, dropped_shard_indices);
    datagrams_to_parity(&received, layout, &mut buf)?;
    Ok(buf)
}

#[test]
fn chaos_datagram_slots_align_with_inboard_shard_layout_helper() -> Result<()> {
    let payload: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
    let Encoded(encoded, _hash, info) = encode(&[0u8; 32], &payload, 12)?;
    let layout = InboardShardLayout::from_encode_info(encoded.len(), info.chunk_len);

    let datagrams = inboard_to_datagrams(&encoded, &layout);
    assert_eq!(
        datagrams.len(),
        8,
        "RS 4/8 chaos model uses eight shard slots"
    );

    for dgram in &datagrams {
        let range = layout.shard_byte_range(dgram.shard_index);
        assert_eq!(
            dgram.payload, encoded[range],
            "chaos slot {} must match InboardShardLayout range (helper-internal)",
            dgram.shard_index
        );
    }

    let mut reassembled = encoded.to_vec();
    datagrams_to_inboard(&datagrams, &layout, &mut reassembled)?;
    assert_eq!(reassembled, encoded, "lossless chaos-slot reassembly");
    Ok(())
}

#[test]
fn truncated_datagram_payload_fails_reassembly() -> Result<()> {
    let payload: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
    let Encoded(encoded, _hash, info) = encode(&[0u8; 32], &payload, 12)?;
    let layout = InboardShardLayout::from_encode_info(encoded.len(), info.chunk_len);
    let mut datagrams = inboard_to_datagrams(&encoded, &layout);
    let trunc_len = datagrams[2].payload.len().saturating_sub(1);
    datagrams[2].payload.truncate(trunc_len);

    let mut buf = vec![0u8; encoded.len()];
    let err = datagrams_to_inboard(&datagrams, &layout, &mut buf)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("payload len") && err.contains("shard 2"),
        "length mismatch must surface explicitly, got {err}"
    );
    Ok(())
}

#[test]
fn duplicate_datagram_shard_index_last_writer_wins() -> Result<()> {
    let payload: Vec<u8> = (0..16_384).map(|i| (i % 251) as u8).collect();
    let Encoded(encoded, _hash, info) = encode(&[0u8; 32], &payload, 12)?;
    let layout = InboardShardLayout::from_encode_info(encoded.len(), info.chunk_len);
    let datagrams = inboard_to_datagrams(&encoded, &layout);

    let mut first = datagrams[1].clone();
    first.payload.fill(0xAA);
    let second = datagrams[1].clone();

    let mut reassembled = vec![0u8; encoded.len()];
    datagrams_to_inboard(&[first, second], &layout, &mut reassembled)?;
    let range = layout.shard_byte_range(1);
    assert_eq!(
        &reassembled[range.clone()],
        &encoded[range],
        "duplicate shard_index: last datagram wins"
    );
    Ok(())
}

#[test]
fn four_datagram_drops_recover_via_scrub_reassembly_path() -> Result<()> {
    let payload = varied_payload(65_536, 14);
    let Encoded(orig, hash, info) = encode(&[0u8; 32], &payload, 14)?;
    let hash_bytes = hash.as_bytes();
    let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);
    let datagrams = inboard_to_datagrams(&orig, &layout);

    for &dropped in FOUR_DROP_SUBSETS {
        assert_eq!(
            datagrams.len() - dropped.len(),
            4,
            "subset {dropped:?} must drop exactly four"
        );

        let corrupted = reassemble_after_datagram_loss(&orig, &datagrams, &layout, dropped)?;
        let erased = datagram_loss_to_corrupted_inboard(&orig, &layout, dropped);
        assert_eq!(
            corrupted, erased,
            "erase+overlay reassembly must match erase_shards for {dropped:?}"
        );

        let recovered = scrub(&corrupted, hash_bytes, &info, 14)?;
        assert_eq!(recovered, orig, "scrub recovery for dropped {dropped:?}");

        let dec = decode(&[0u8; 32], hash_bytes, &recovered, info.padding_len, 14)?;
        assert_eq!(dec, payload);
    }
    Ok(())
}

#[test]
fn five_datagram_drops_c12_irrecoverable_c14_documents_asymmetry() -> Result<()> {
    // c12 negative mirrors `fec_chaos::five_shard_touch_fails_scrub_proves_fifty_percent_limit`.
    for level in [12u8, 14] {
        let payload = varied_payload(65_536, level);
        let Encoded(orig, hash, info) = encode(&[0u8; 32], &payload, level)?;
        let hash_bytes = hash.as_bytes();
        let layout = InboardShardLayout::from_encode_info(orig.len(), info.chunk_len);
        let datagrams = inboard_to_datagrams(&orig, &layout);
        let dropped = [0usize, 1, 2, 3, 4];

        let erased = datagram_loss_to_corrupted_inboard(&orig, &layout, &dropped);
        let reassembled = reassemble_after_datagram_loss(&orig, &datagrams, &layout, &dropped)?;
        assert_eq!(
            reassembled, erased,
            "five-drop erase+overlay must match erase_shards at level {level}"
        );

        let scrub_result = scrub(&erased, hash_bytes, &info, level);
        if level == 12 {
            let err = scrub_result.unwrap_err();
            assert!(
                matches!(err, CarbonadoError::InvalidScrubbedHash),
                "five datagram drops must be irrecoverable at c12, got {err:?}"
            );
        } else {
            // c14 + Snappy: at the approximate chaos coordinates, five erased stripes can
            // still leave enough RS columns for scrub recovery (documented asymmetry vs c12).
            let recovered = scrub_result.expect("c14 five-drop scrub recovery");
            assert_eq!(recovered, orig);
        }
    }
    Ok(())
}

#[test]
fn directory_bundle_parity_outboard_scrub_recovery() -> Result<()> {
    use carbonado::{
        adamantine::decode_adamantine,
        adamantine_payload::{
            fec_slice_from_bundle, split_adamantine_payload, verification_slice_from_bundle,
        },
        directory::SegmentFormatPolicy,
        encode_outboard,
        file::{
            decode, decode_directory, encode_directory_with_options, DirectoryEncodeOptions,
            DIRECTORY_ARCHIVE_FORMAT,
        },
        filepack_manifest::FilepackManifest,
        scrub_outboard,
    };

    use std::fs;
    use std::path::PathBuf;

    let key = [0u8; 32];
    let samples = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples");
    let payload = fs::read(samples.join("content.png"))?;
    let enc_dir =
        std::env::temp_dir().join(format!("carbonado_udp_dir_bundle_{}", std::process::id()));
    let dec_dir = std::env::temp_dir().join(format!(
        "carbonado_udp_dir_bundle_dec_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&enc_dir);
    let _ = fs::remove_dir_all(&dec_dir);
    fs::create_dir_all(&enc_dir)?;
    fs::create_dir_all(&dec_dir)?;

    let archive = encode_directory_with_options(
        &key,
        &samples,
        &enc_dir,
        DirectoryEncodeOptions {
            segment_format_policy: SegmentFormatPolicy::ForceC12,
            ..DirectoryEncodeOptions::default()
        },
    )?;
    let catalog_path = enc_dir.join(format!(
        "{}.adam.c{}",
        archive
            .catalog_bao_root
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        DIRECTORY_ARCHIVE_FORMAT
    ));
    let catalog_bytes = fs::read(&catalog_path)?;
    let (_, body) = decode(&key, &catalog_bytes)?;
    let (adam_payload, _) = decode_adamantine(&body)?;
    let (rkyv, bundle) = split_adamantine_payload(&adam_payload)?;
    let manifest = FilepackManifest::from_bytes_with_root(&rkyv, archive.catalog_bao_root)?;
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.rel_path == "content.png")
        .expect("content.png");
    let seg = &entry.segments[0];
    let bao_ob = verification_slice_from_bundle(
        &bundle,
        seg.verification_outboard_offset,
        seg.verification_outboard_len,
    )?;
    let fec_par = fec_slice_from_bundle(&bundle, seg.fec_parity_offset, seg.fec_parity_len)?;
    let seg_path = enc_dir.join(format!(
        "{}.c{}",
        seg.segment_bao_root
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        entry.segment_format
    ));
    let pristine = fs::read(&seg_path)?;
    let oenc = encode_outboard(&key, &payload, entry.segment_format)?;
    let layout = OutboardShardLayout::from_outboard_encode(
        pristine.len(),
        fec_par.len(),
        oenc.info.chunk_len,
    );

    let parity_datagrams = parity_to_datagrams(fec_par, &layout);
    assert_eq!(
        parity_datagrams.len(),
        FEC_M - FEC_K,
        "bundle FEC parity must split into four RS parity shard datagrams"
    );
    let intact_fec =
        reassemble_parity_after_datagram_loss(fec_par, &parity_datagrams, &layout, &[])?;
    assert_eq!(
        intact_fec, fec_par,
        "lossless parity datagram reassembly must preserve bundle slice"
    );

    let dropped_parity = [0usize, 1, 2, 3];
    let partial_fec = reassemble_parity_after_datagram_loss(
        fec_par,
        &parity_datagrams,
        &layout,
        &dropped_parity,
    )?;
    assert_ne!(
        partial_fec, fec_par,
        "four dropped parity datagrams must alter reassembled bundle slice"
    );

    let mut corrupt = pristine.clone();
    use common::corruption::scattered_outboard_main_knockout;
    use rand::thread_rng;
    let report = scattered_outboard_main_knockout(&mut corrupt, &layout, 12, 4, &mut thread_rng());
    assert!(
        report.shards_touched.len() <= 4,
        "main knockout must stay within RS budget, touched {:?}",
        report.shards_touched
    );
    assert!(
        !report.positions.is_empty(),
        "main knockout must corrupt at least one byte before scrub"
    );

    // Scrub uses intact catalog parity (Adamantine bundle); datagram-loss model above
    // exercises transport of centralized parity shards separately.
    let recovered = scrub_outboard(
        &corrupt,
        Some(bao_ob),
        Some(fec_par),
        &oenc.info,
        entry.segment_format,
        &seg.segment_bao_root,
    )?;
    assert_eq!(recovered, pristine);

    fs::write(&seg_path, &recovered)?;
    decode_directory(&key, &catalog_path, &dec_dir)?;
    assert_eq!(fs::read(dec_dir.join("content.png"))?, payload);
    Ok(())
}
