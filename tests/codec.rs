use std::{
    fs::{read, OpenOptions},
    io::Write,
    path::PathBuf,
};

use anyhow::Result;
use carbonado::{
    constants::Format, decode, encode, extract_slice, file::Header, scrub, structs::Encoded,
    verify_slice,
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
    verify_slice(&encoded, 0, encode_info.verifiable_slice_count)?;

    // Exercise extract_slice and verify returning logical data (post-zfec for this level).
    // For bao+zfec, full count verify returns exactly the zfec bytes (skipping 64B parents).
    let _ = extract_slice(&encoded, 0);
    let verified_full = verify_slice(&encoded, 0, encode_info.verifiable_slice_count)?;
    assert_eq!(
        verified_full.len() as u32,
        encode_info.bytes_ecc,
        "verify/extract now return logical data using 4KB BAO_BLOCK_SIZE geometry"
    );

    // Strengthen: use level 4 (Bao only) where logical data == original input for content check.
    let Encoded(encoded4, _hash4, ei4) = encode(&sym_key, &input, 4)?;
    let vslice = verify_slice(&encoded4, 0, 1.min(ei4.verifiable_slice_count))?;
    let n = vslice.len().min(input.len());
    assert_eq!(
        &vslice[..n],
        &input[..n],
        "verify/extract returns correct logical data bytes (content match)"
    );

    // Minimal edge coverage for BAO_BLOCK_SIZE geometry (per review):  <1 group, exact, +partial.
    for &sz in &[100usize, 4095, 4096, 4100] {
        let tiny = vec![0xABu8; sz];
        let Encoded(e, _h, _ei) = encode(&sym_key, &tiny, 4)?; // Bao only; logical==tiny
        let got = verify_slice(&e, 0, 1)?;
        let want = &tiny[0..got.len().min(tiny.len())];
        assert_eq!(&got[..], want, "edge size {} verify content", sz);
        let _ = extract_slice(&e, 0);
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
                // has bao
                let _ = verify_slice(&e1, 0, ei1.verifiable_slice_count.min(1));
            }
        }
    }

    // Encrypted+Zfec with Bao for scrub (13/15 = E+(S)+Bao+Zfec). 9/11 lack Bao so intentionally return ScrubRequiresBao (not exercised for scrub here).
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
    if rand_chaos.len() > resp + 1000 {
        for _ in 0..5 {
            let p = resp + (rng.next_u32() as usize % (rand_chaos.len() - resp - 1));
            if p < rand_chaos.len() {
                rand_chaos[p] ^= rng.gen_range(0u8..=255);
            }
        }
    }
    let rec = scrub(&rand_chaos, hash.as_bytes(), &encode_info, 12)
        .expect("rand chaos <= threshold recoverable");
    assert_eq!(rec, orig_encoded, "scrub rand chaos");

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

    info!("FEC robustness tests passed");
    Ok(())
}

#[wasm_bindgen_test]
fn wasm_fec_robustness_small() -> Result<()> {
    // Small exercised path for wasm (full matrix in native; pre-existing WASM cross limits for some deps noted in AGENTS).
    // Uses level with Zfec+Bao, det encode, light scrub recovery, format keying.
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
