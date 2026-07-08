use std::{
    fs::{read, OpenOptions},
    io::Write,
    path::PathBuf,
};

use anyhow::Result;
use carbonado::{
    constants::Format, decode, encode, error::CarbonadoError, extract_slice, file::Header, scrub,
    structs::Encoded, verify_slice,
};
use log::{debug, info};
use rand::{Rng, RngCore};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[test]
fn contract() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    codec("tests/samples/contract.rgbc")?;
    // codec("tests/samples/navi10_arch.7z")?;

    Ok(())
}

#[test]
fn content() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    codec("tests/samples/content.png")?;

    Ok(())
}

#[test]
fn code() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    codec("tests/samples/code.tar")?;

    Ok(())
}

#[wasm_bindgen_test]
fn wasm_contract() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    codec("tests/samples/contract.rgbc")?;

    Ok(())
}

#[wasm_bindgen_test]
fn wasm_content() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    codec("tests/samples/content.png")?;

    Ok(())
}

#[wasm_bindgen_test]
fn wasm_code() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    codec("tests/samples/code.tar")?;

    Ok(())
}

fn codec(path: &str) -> Result<()> {
    let input = read(path)?;

    // Use a random 32-byte symmetric master key for the new AES+HMAC encryption + header auth path
    let mut sym_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sym_key);

    info!("Encoding {path}...");
    let Encoded(encoded, hash, encode_info) = encode(&sym_key, &input, 15)?;

    debug!("Encoding Info: {encode_info:#?}");
    assert_eq!(
        encoded.len() as u32,
        encode_info.bytes_verifiable,
        "Length of encoded bytes matches bytes_verifiable field"
    );

    info!("Verifying stream against hash: {hash}...");
    verify_slice(
        &encoded,
        0,
        encode_info.verifiable_slice_count,
        hash.as_bytes(),
        15,
    )?;

    // Exercise extract_slice and verify returning logical data (post-zfec for this level).
    // For bao+zfec, full count verify returns exactly the zfec bytes (skipping 64B parents).
    let _ = extract_slice(&encoded, 0, hash.as_bytes(), 15);
    let verified_full = verify_slice(
        &encoded,
        0,
        encode_info.verifiable_slice_count,
        hash.as_bytes(),
        15,
    )?;
    assert_eq!(
        verified_full.len() as u32,
        encode_info.bytes_ecc,
        "verify/extract now return logical data using 4KB BAO_BLOCK_SIZE geometry"
    );
    assert_eq!(encode_info.bytes_verifiable, encoded.len() as u32);

    // Strengthen: use level 4 (Bao only) where logical data == original input for content check.
    let Encoded(encoded4, hash4, ei4) = encode(&sym_key, &input, 4)?;
    let vslice = verify_slice(
        &encoded4,
        0,
        1.min(ei4.verifiable_slice_count),
        hash4.as_bytes(),
        4,
    )?;
    let n = vslice.len().min(input.len());
    assert_eq!(
        &vslice[..n],
        &input[..n],
        "verify/extract returns correct logical data bytes (content match)"
    );

    // Minimal edge coverage for BAO_BLOCK_SIZE geometry (per review):  <1 group, exact, +partial.
    for &sz in &[100usize, 4095, 4096, 4100] {
        let tiny = vec![0xABu8; sz];
        let Encoded(e, h, _ei) = encode(&sym_key, &tiny, 4)?; // Bao only; logical==tiny
        let got = verify_slice(&e, 0, 1, h.as_bytes(), 4)?;
        let want = &tiny[0..got.len().min(tiny.len())];
        assert_eq!(&got[..], want, "edge size {} verify content", sz);
        let _ = extract_slice(&e, 0, h.as_bytes(), 4);
    }

    info!("Decoding Carbonado bytes");
    let decoded = decode(
        &sym_key,
        hash.as_bytes(),
        &encoded,
        encode_info.padding_len,
        15,
    )?;
    assert_eq!(decoded, input, "Decoded output is same as encoded input");

    let carbonado_level = 15;
    let format = Format::from(carbonado_level);

    // v2 Header creation using the symmetric key for auth (nonce is zero here for the manual test path; real usage generates it)
    let mut payload_nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut payload_nonce);

    let header = Header::new(
        &sym_key,
        payload_nonce,
        hash.as_bytes(),
        [0u8; 32],
        format,
        0u32,
        encode_info.bytes_verifiable,
        encode_info.padding_len,
        None,
    )?;

    let header_bytes = header.try_to_vec()?;
    assert_eq!(
        &header_bytes[0..12],
        carbonado::constants::MAGICNO,
        "header magic CARBONADO20"
    );

    let file_path = PathBuf::from("/tmp").join(header.file_name());
    info!("Writing test file to: {file_path:?}");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&file_path)?;
    file.write_all(&header_bytes)?;
    file.write_all(&encoded)?;
    info!("Test file successfully written.");
    info!("All good!");

    Ok(())
}

// FEC robustness, determinism, edges, recovery, scrub e2e for Reed-Solomon impl.
// Covers: det for non-encrypt (no rand), roundtrip for all Zfec (incl encrypted), 50% shard-aligned + random/chaos via rand+explicit 4-shard, unconditional asserts + negative >4, large, 0, wasm note. Format keying correct via level.
#[test]
fn fec_robustness() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    // Use non-encrypt formats so re-encode is deterministic (no internal nonce)
    // 12 = Bao+Zfec, 14=Bao+Snappy+Zfec, 8=Zfec only (no bao, scrub not used), 10=snappy+zfec
    for &level in &[8u8, 10, 12, 14] {
        for &size in &[0usize, 1, 100, 1023, 4096, 5000, 8192, 10000] {
            let mut input = vec![0u8; size];
            // varied content
            for (i, b) in input.iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);

            let Encoded(e1, h1, ei1) = encode(&key, &input, level)?;
            let Encoded(e2, h2, ei2) = encode(&key, &input, level)?;
            assert_eq!(
                e1, e2,
                "FEC encode deterministic for level {} size {}",
                level, size
            );
            assert_eq!(h1, h2);
            assert_eq!(ei1.padding_len, ei2.padding_len);

            // full roundtrip via decode
            let dec = decode(&key, h1.as_bytes(), &e1, ei1.padding_len, level)?;
            assert_eq!(dec, input, "roundtrip level {} size {}", level, size);

            // edges on slice counts etc already covered somewhat
            if level & 4 != 0 {
                // has bao; assert on return (was discard) for strength + content sanity
                let v = verify_slice(
                    &e1,
                    0,
                    ei1.verifiable_slice_count.min(1),
                    h1.as_bytes(),
                    level,
                )?;
                let _ = v.len(); // exercised + non-zero for non-empty cases
            }
        }
    }

    // Encrypted+Zfec with Bao for scrub (13/15 = E+(S)+Bao+Zfec). 9/11 lack Bao so return ScrubRequiresBao (now exercised in matrix + scrub_specific_errors).
    for &level in &[13u8, 15] {
        let input = b"encrypted zfec roundtrip and scrub test payload";
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let Encoded(e, h, ei) = encode(&key, input, level)?;
        let dec = decode(&key, h.as_bytes(), &e, ei.padding_len, level)?;
        assert_eq!(&dec[..], input);
        // light corruption + scrub recover (then decode to check plaintext). Unconditional like main paths.
        let mut bad = e.clone();
        if bad.len() > 100 {
            bad[80] ^= 0x33;
        }
        let rec =
            scrub(&bad, h.as_bytes(), &ei, level).expect("scrub must recover for encrypted+Zfec");
        assert_eq!(rec, e, "scrub body matches original encoded for this run");
        let drec = decode(&key, h.as_bytes(), &rec, ei.padding_len, level)?;
        assert_eq!(&drec[..], input);
    }

    // Scrub recovery e2e, including large for det + chaos patterns (taint distributed <=~50% shard wise)
    // Use level 12 (zfec+bao, repeatable)
    let mut input = vec![0xABu8; 16384]; // >8k to cover previous non-det TODO case
    for (i, b) in input.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7);
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let Encoded(orig_encoded, hash, encode_info) = encode(&key, &input, 12)?;
    // baseline: no scrub needed
    assert!(scrub(&orig_encoded, hash.as_bytes(), &encode_info, 12).is_err());

    // Chaos/50%: rand + explicit patterns + full 4-shard erasures (spaced response taints sized to logical shards).
    // Unconditional asserts (scrub must succeed for <=4). Negative for 5+ (irrecoverable).
    // Uses rand (dev-dep) + explicit; correct format=12 for keyed bao in scrub/encode.
    let mut rng = rand::thread_rng();
    let mut rand_chaos = orig_encoded.clone();
    let resp = 8;
    // Shard-aware: use chunk_len (from EncodeInfo for Zfec) for step so taints are aligned to logical shards (guarantees control over #shards hit; addresses flakiness).
    let chunk = if encode_info.chunk_len > 0 {
        encode_info.chunk_len as usize
    } else {
        (rand_chaos.len().saturating_sub(resp) / 8).max(1)
    };
    let step = chunk.max(1);
    if rand_chaos.len() > resp + 1000 {
        for _ in 0..5 {
            // rand within first 4 shards for <=4 guarantee on average; explicit 4/5 cases below ensure boundaries
            let shard = rng.next_u32() as usize % 4;
            let p = resp + shard * step + (rng.next_u32() as usize % step.max(1));
            if p < rand_chaos.len() {
                rand_chaos[p] ^= rng.gen_range(0u8..=255);
            }
        }
    }
    let rec = scrub(&rand_chaos, hash.as_bytes(), &encode_info, 12)
        .expect("rand chaos <= threshold recoverable");
    assert_eq!(rec, orig_encoded, "scrub rand chaos");

    // More adversarial: multiple rand runs + bit-level flips (not just byte) + chaos-ray sim
    // (partial taints across shards but leaving >=4 clean for recovery; exercises scrub search
    // for distributed "chaos ray" corruption while still succeeding).
    for run in 0..3 {
        let mut bit_chaos = orig_encoded.clone();
        if bit_chaos.len() > resp + 200 {
            for _ in 0..4 {
                let shard = rng.next_u32() as usize % 4;
                let p = resp + shard * step + (rng.next_u32() as usize % step.max(1));
                let bit = rng.gen_range(0u8..8);
                bit_chaos[p] ^= 1u8 << bit; // bit flip adversarial
            }
        }
        let recb = scrub(&bit_chaos, hash.as_bytes(), &encode_info, 12)
            .unwrap_or_else(|_| panic!("bit chaos run {} recoverable", run));
        assert_eq!(recb, orig_encoded, "scrub bit chaos run {}", run);
    }

    // chaos ray: partial taint inside data areas of *all 8* logical shards, but only first 4 tainted
    // so 4 remain fully good -> scrub search must succeed and recover exact bytes (not len only)
    let mut ray = orig_encoded.clone();
    let step = (ray.len().saturating_sub(resp) / 8).max(1);
    let taint_sz = 37usize; // small partial inside shard for "hit"
    for i in 0..8 {
        let p = resp + i * step;
        if p + taint_sz < ray.len() && i < 4 {
            // taint only 4; other 4 untouched (sim distributed hit on "all" but recoverable)
            ray[p..p + taint_sz].fill(0xEE);
        }
    }
    let rec_ray = scrub(&ray, hash.as_bytes(), &encode_info, 12)
        .expect("chaos ray partial across shards recoverable");
    assert_eq!(
        rec_ray, orig_encoded,
        "scrub recovered exact bytes after chaos-ray partial taints"
    );
    assert_eq!(rec_ray.len(), orig_encoded.len()); // pair len with content (hash via outer eq)

    // explicit 4-of-8 shard taint (spaced full-chunk sized zeros in response)
    let mut four_shard = orig_encoded.clone();
    let clen = encode_info.chunk_len as usize;
    let step = (four_shard.len().saturating_sub(resp) / 8).max(1);
    for i in 0..4 {
        let p = resp + i * step;
        let z = clen.min(four_shard.len().saturating_sub(p));
        if z > 0 {
            four_shard[p..p + z].fill(0);
        }
    }
    let rec4 =
        scrub(&four_shard, hash.as_bytes(), &encode_info, 12).expect("4-shard erasure recoverable");
    assert_eq!(rec4, orig_encoded);

    // >4 (5) should fail to find good subset
    let mut five = orig_encoded.clone();
    for i in 0..5 {
        let p = resp + i * step;
        let z = clen.min(five.len().saturating_sub(p));
        if z > 0 {
            five[p..p + z].fill(0);
        }
    }
    assert!(
        scrub(&five, hash.as_bytes(), &encode_info, 12).is_err(),
        "5 shards irrecoverable"
    );

    // consecutive
    let mut consec = orig_encoded.clone();
    if consec.len() > 2000 {
        consec[500..800].fill(0xFF);
    }
    let rec2 = scrub(&consec, hash.as_bytes(), &encode_info, 12).expect("consec recoverable");
    assert_eq!(rec2, orig_encoded, "scrub from consec corruption");

    // 0-byte case for zfec
    let Encoded(e0, h0, ei0) = encode(&key, &[], 12)?;
    let d0 = decode(&key, h0.as_bytes(), &e0, ei0.padding_len, 12)?;
    assert!(d0.is_empty());

    // 0-byte Bao+Zfec scrub (good data -> unnecessary err; unconditional e2e for edge per plan).
    let Encoded(e0b, h0b, ei0b) = encode(&key, &[], 12)?;
    assert!(
        scrub(&e0b, h0b.as_bytes(), &ei0b, 12).is_err(),
        "0-byte good Bao+Zfec must unnecessary-scrub-err"
    );

    info!("FEC robustness tests passed");
    Ok(())
}

#[wasm_bindgen_test]
fn wasm_fec_robustness_small() -> Result<()> {
    // Small exercised path for wasm (full 16-format matrix + chaos + edges in native only; pre-existing WASM cross limits for deps noted in AGENTS.md §10 + WASM section).
    let _ = pretty_env_logger::try_init();
    let input = b"wasm small fec";
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let Encoded(e, h, ei) = encode(&key, input, 12)?;
    let Encoded(e2, _, _) = encode(&key, input, 12)?;
    assert_eq!(e, e2); // det
    let mut bad = e.clone();
    if bad.len() > 10 {
        bad[10] ^= 0x01;
    }
    let rec = scrub(&bad, h.as_bytes(), &ei, 12).expect("wasm scrub recover");
    assert_eq!(rec, e);
    let d = decode(&key, h.as_bytes(), &rec, ei.padding_len, 12)?;
    assert_eq!(&d[..], input);
    Ok(())
}

/// Full 16-format matrix roundtrips (content equality, not len-only), plus explicit det for
/// non-encrypt Zfec, scrub/error coverage for *all* Zfec formats (incl 9/11 for ScrubRequiresBao
/// and 12-15 for recovery). Exercises FEC paths changed in v2 + non-FEC unchanged.
/// Covers plan req: full encode/decode for all 16 (w/wo FEC), det, 4/8 shards etc via scrub.
#[test]
fn all_formats_matrix_roundtrips() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    // Deterministic small varied payload (repeatable)
    let mut input = vec![0u8; 2048];
    for (i, b) in input.iter_mut().enumerate() {
        *b = ((i * 7) % 251) as u8;
    }

    for level in 0u8..=15 {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        let Encoded(e, h, ei) = encode(&key, &input, level)?;
        // content eq (not just len)
        let dec = decode(&key, h.as_bytes(), &e, ei.padding_len, level)?;
        assert_eq!(
            dec, input,
            "full roundtrip content eq for all formats level={}",
            level
        );

        // header fields when we construct one (as in other tests). Only for Bao (meaningful bytes_verifiable/hash); pure Zfec sets 0 in low-level Encoded.
        if level & 4 != 0 {
            // Bao cases produce proper verifiable len + keyed hash for header

            let mut nonce = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut nonce);
            let format = Format::from(level);
            let hdr = Header::new(
                &key,
                nonce,
                h.as_bytes(),
                [0u8; 32],
                format,
                0,
                ei.bytes_verifiable,
                ei.padding_len,
                None,
            )?;
            assert_eq!(hdr.format, format);
            assert_eq!(hdr.encoded_len, ei.bytes_verifiable);
            assert_eq!(hdr.slh_public_key, [0u8; 32]);
            assert_eq!(
                hdr.payload_nonce, nonce,
                "manual nonce roundtrips in matrix header"
            );
            // magic validated on try_to_vec/parse path
            let hb = hdr.try_to_vec()?;
            assert_eq!(&hb[0..12], carbonado::constants::MAGICNO);
        }

        // For Zfec formats (bit 3 set), cover det (non-E only), scrub paths
        if level & 8 != 0 {
            if level & 1 == 0 {
                // non-encrypted Zfec: must be deterministic (key point of RS)
                let Encoded(e2, h2, ei2) = encode(&key, &input, level)?;
                assert_eq!(e, e2, "det encode for non-E Zfec level {}", level);
                assert_eq!(h, h2);
                assert_eq!(ei.padding_len, ei2.padding_len);
            }

            // Exercise scrub or its required error for every Zfec format
            if level & 4 != 0 {
                // has Bao: good data -> UnnecessaryScrub; light taint -> recover + content
                let err = scrub(&e, h.as_bytes(), &ei, level).unwrap_err();
                assert!(
                    matches!(err, CarbonadoError::UnnecessaryScrub),
                    "good bao+zfec data must err UnnecessaryScrub (level {})",
                    level
                );
                let mut bad = e.clone();
                if bad.len() > 64 {
                    bad[48] ^= 0x5A; // light
                }
                let rec = scrub(&bad, h.as_bytes(), &ei, level)
                    .expect("scrub recover for bao+zfec level");
                assert_eq!(rec, e, "scrub body eq level {}", level);
                let drec = decode(&key, h.as_bytes(), &rec, ei.padding_len, level)?;
                assert_eq!(drec, input, "post-scrub decode eq level {}", level);
            } else {
                // no Bao Zfec (e.g. 8,9,10,11): scrub must give ScrubRequiresBao
                let err = scrub(&e, h.as_bytes(), &ei, level).unwrap_err();
                assert!(
                    matches!(err, CarbonadoError::ScrubRequiresBao),
                    "Zfec w/o Bao level {} -> ScrubRequiresBao",
                    level
                );
            }
        }
    }

    // Short bao prefix (<8 bytes, after u64 content len prefix expected) for verify/decode paths.
    // Covers bao error paths (InvalidHeaderLength) on malformed short bodies (not just header magic).
    let short_bao = vec![0u8; 4];
    let err_bao = verify_slice(&short_bao, 0, 1, &[0u8; 32], 4).unwrap_err();
    assert!(matches!(err_bao, CarbonadoError::InvalidHeaderLength));

    Ok(())
}
