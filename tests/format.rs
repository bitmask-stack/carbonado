use std::{fs::OpenOptions, io::Write, path::PathBuf};

use anyhow::Result;
use carbonado::{
    constants::Format, decode, encode, error::CarbonadoError, file::Header, scrub, structs::Encoded,
};
use log::{debug, info, trace};
use rand::RngCore;
use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_browser);

#[test]
fn format() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    let input = "Hello world!".as_bytes();
    let carbonado_level = 15;
    let format = Format::from(carbonado_level);

    // Simple random 32-byte symmetric master key.
    // Key agreement (ECDH or otherwise) is an application-layer concern and is no
    // longer demonstrated here. Carbonado assumes you already have a master key.
    // There is no direct equivalent for SLH-DSA (which is a signature scheme only).
    let mut master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master);

    info!("Encoding input: {input:?}...");

    let Encoded(encoded, hash, encode_info) = encode(&master, input, carbonado_level)?;

    debug!("Encoding Info: {encode_info:#?}");

    // For v2 header we need a payload nonce (the one used for AES-CTR of this segment)
    let mut payload_nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut payload_nonce);

    let header = Header::new(
        &master,
        payload_nonce,
        hash.as_bytes(),
        [0u8; 32],
        format,
        0u32,
        encode_info.bytes_verifiable,
        encode_info.padding_len,
        None,
    )?;
    trace!("Header: {header:#?}");

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

    info!("Parsing file headers...");
    // Use the v2-aware slice parser (the file-based legacy TryFrom was removed in the clean break)
    let mut file_for_parse = std::fs::File::open(&file_path)?;
    let mut file_bytes = Vec::new();
    std::io::Read::read_to_end(&mut file_for_parse, &mut file_bytes)?;
    let header = Header::try_from(&file_bytes[..])?;

    // v2 Header no longer stores the signer pubkey (symmetric model)
    assert_eq!(header.hash, hash);
    assert_eq!(header.format, format);
    assert_eq!(header.chunk_index, 0);
    assert_eq!(header.padding_len, encode_info.padding_len);
    assert_eq!(header.encoded_len, encode_info.bytes_verifiable);
    assert_eq!(header.slh_public_key, [0u8; 32]);
    assert_eq!(
        header.payload_nonce, payload_nonce,
        "nonce roundtrips through header"
    );

    // Confirm v2 magic in serialized header (CARBONADO20, old 02 rejected separately)
    let header_bytes = header.try_to_vec()?;
    assert_eq!(
        &header_bytes[0..12],
        carbonado::constants::MAGICNO,
        "serialized header uses CARBONADO20 magic"
    );

    info!("Decoding Carbonado bytes");
    let decoded = decode(
        &master,
        hash.as_bytes(),
        &encoded,
        encode_info.padding_len,
        carbonado_level,
    )?;

    assert_eq!(decoded, input, "Decoded output is same as encoded input");

    info!("All good!");

    Ok(())
}

/// Targeted test for v2 magic: old/dev magic (CARBONADO02) and other invalids rejected with clear error.
/// Covers the "old magic produces migration error" requirement from v2 stabilization plan.
#[test]
fn header_rejects_bad_magic() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    // Craft a buffer >= LEN with old dev magic (02 transitional)
    let mut bad02 = [0u8; Header::LEN];
    bad02[0..12].copy_from_slice(b"CARBONADO02\n"); // exactly 12 bytes: CARBONADO(9)+02(2)+\n(1)
    let err = Header::try_from(&bad02[..]).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidMagicNumber(_)),
        "CARBONADO02 (old dev) must be rejected as InvalidMagicNumber (directs to external migration)"
    );

    // Random invalid magic
    let mut bad = [0u8; Header::LEN];
    bad[0..12].copy_from_slice(b"BADMAGIC!\nXX"); // 12 bytes
    let err2 = Header::try_from(&bad[..]).unwrap_err();
    assert!(matches!(err2, CarbonadoError::InvalidMagicNumber(_)));

    // Too short also errors (length before magic check path)
    let short = [0u8; 10];
    let err3 = Header::try_from(&short[..]).unwrap_err();
    // short < LEN hits length check before magic (specific)
    assert!(matches!(err3, CarbonadoError::InvalidHeaderLength));

    Ok(())
}

/// Exercise specific scrub errors for Zfec formats: ScrubRequiresBao for no-Bao Zfec (9/11 etc),
/// and InvalidScrubbedHash for irrecoverable (exercises error paths unconditionally).
#[test]
fn scrub_specific_errors() -> Result<()> {
    let _ = pretty_env_logger::try_init();

    let mut input = vec![0xCCu8; 4096]; // large enough for shard taints to be effective (>~100)
    for (i, b) in input.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let input = &input[..];
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    // Levels 9,11 = Encrypted?+Zfec (no Bao) -> scrub must return ScrubRequiresBao
    for &level in &[9u8, 11] {
        let Encoded(e, h, ei) = encode(&key, input, level)?;
        let err = scrub(&e, h.as_bytes(), &ei, level).unwrap_err();
        assert!(
            matches!(err, CarbonadoError::ScrubRequiresBao),
            "level {} (Zfec no Bao) must error ScrubRequiresBao",
            level
        );
    }

    // Level 8/10 also no bao zfec (non E), same
    for &level in &[8u8, 10] {
        let Encoded(e, h, ei) = encode(&key, input, level)?;
        let err = scrub(&e, h.as_bytes(), &ei, level).unwrap_err();
        assert!(matches!(err, CarbonadoError::ScrubRequiresBao));
    }

    // For a Bao+Zfec, make irrecoverable (>4 shards) -> InvalidScrubbedHash
    let Encoded(e, h, ei) = encode(&key, input, 12)?;
    let mut too_bad = e.clone();
    // taint 5+ shard regions aggressively (large input ensures effective distributed hit)
    let step = (too_bad.len().saturating_sub(8) / 8).max(16);
    for i in 0..5 {
        let p = 8 + i * step;
        let z = (step / 2).max(8);
        if p + z <= too_bad.len() {
            too_bad[p..p + z].fill(0);
        }
    }
    let err = scrub(&too_bad, h.as_bytes(), &ei, 12).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidScrubbedHash),
        "excessive shard taint must yield InvalidScrubbedHash, got: {}",
        err
    );

    Ok(())
}
