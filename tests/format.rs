use std::{fs::OpenOptions, io::Write, path::PathBuf};

use anyhow::Result;
use carbonado::{
    constants::Format,
    decode, decode_outboard, encode, encode_outboard,
    error::CarbonadoError,
    file::{self, Header},
    filepack, scrub, scrub_outboard,
    structs::{Encoded, OutboardEncoded},
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

    let mut input = vec![0xCCu8; 16384]; // aligned for 4 KiB slice / FEC shard geometry
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
    let clen = ei.chunk_len as usize;
    for i in 0..5 {
        let p = 8 + i * step;
        let z = clen.min(too_bad.len().saturating_sub(p));
        if z > 0 {
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

// Test outboard roundtrips for public formats + c# commitment in keyed bao (different c produce different roots).
// Expanded per review: all public levels incl Zfec-only, 0-byte, error cases, OutboardEncoded, filepack.
#[test]
fn outboard_and_keyed_c_number() -> Result<()> {
    let _ = pretty_env_logger::try_init();
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let input = b"outboard test payload for bare + sidecar verification and c# binding";

    // all public levels (0/2/4/6/8/10/12/14) for outboard
    for &level in &[0u8, 2, 4, 6, 8, 10, 12, 14] {
        let oenc: OutboardEncoded = encode_outboard(&key, input, level)?;
        let (main, bao_ob, fec_par, h, ei) = (
            oenc.main,
            oenc.bao_outboard,
            oenc.fec_parity,
            oenc.hash,
            oenc.info,
        );
        let _ = (main.len(), input.len());
        if (level & 0b100) != 0 {
            assert!(
                bao_ob.is_some(),
                "bao bit requires outboard sidecar for level {}",
                level
            );
        }
        // decode outboard roundtrip (uses correct padding from ei)
        let rec = decode_outboard(
            &key,
            h.as_bytes(),
            &main,
            bao_ob.as_deref(),
            fec_par.as_deref(),
            ei.padding_len,
            level,
        )?;
        assert_eq!(rec, input, "outboard roundtrip for c{}", level);
    }

    // 0-byte input
    let empty: &[u8] = &[];
    let o0 = encode_outboard(&key, empty, 4)?;
    let rec0 = decode_outboard(
        &key,
        o0.hash.as_bytes(),
        &o0.main,
        o0.bao_outboard.as_deref(),
        o0.fec_parity.as_deref(),
        o0.info.padding_len,
        4,
    )?;
    assert_eq!(rec0, empty);

    // c# commitment proven
    let o4 = encode_outboard(&key, input, 4)?;
    let o6 = encode_outboard(&key, input, 6)?;
    assert_ne!(
        o4.hash, o6.hash,
        "different c must yield different keyed roots"
    );

    // encrypted outboard (level 5 = enc + bao): bare main + bao sidecar, embedded nonce in main
    let oenc_e = encode_outboard(&key, input, 5)?;
    assert!(
        oenc_e.bao_outboard.is_some(),
        "encrypted outboard with bao bit requires sidecar"
    );
    assert!(!oenc_e.main.starts_with(carbonado::constants::MAGICNO));
    let rec_e = decode_outboard(
        &key,
        oenc_e.hash.as_bytes(),
        &oenc_e.main,
        oenc_e.bao_outboard.as_deref(),
        oenc_e.fec_parity.as_deref(),
        oenc_e.info.padding_len,
        5,
    )?;
    assert_eq!(rec_e, input, "encrypted outboard roundtrip c5");

    // error paths: missing sidecars for bao/zfec outboard
    let o_bao = encode_outboard(&key, input, 4)?; // bao no zfec
    let err_bao = decode_outboard(
        &key,
        o_bao.hash.as_bytes(),
        &o_bao.main,
        None,
        None,
        o_bao.info.padding_len,
        4,
    )
    .unwrap_err();
    assert!(matches!(err_bao, CarbonadoError::MissingBaoOutboard));

    let o_z = encode_outboard(&key, input, 8)?; // zfec no bao (public zfec-only)
    let err_z = decode_outboard(
        &key,
        o_z.hash.as_bytes(),
        &o_z.main,
        None,
        None,
        o_z.info.padding_len,
        8,
    )
    .unwrap_err();
    assert!(matches!(err_z, CarbonadoError::MissingFecParity));

    // tampered sidecar (flip byte in a real ob if present) -> verification error (strict)
    if let Some(mut good_ob) = o4.bao_outboard.clone() {
        if !good_ob.is_empty() {
            good_ob[0] ^= 0xff;
            let err_verify = decode_outboard(
                &key,
                o4.hash.as_bytes(),
                &o4.main,
                Some(good_ob.as_slice()),
                None,
                o4.info.padding_len,
                4,
            )
            .unwrap_err();
            assert!(matches!(
                err_verify,
                CarbonadoError::OutboardVerificationFailed(_)
            ));
        }
    }

    Ok(())
}

// Filepack integration coverage (uses on-disk samples to avoid extra dev-dep)
#[test]
fn filepack_minimal_roundtrip() -> Result<()> {
    // pack an existing samples dir (contains files)
    let samples = std::path::Path::new("tests/samples");
    if samples.exists() {
        let packed = filepack::pack_directory(samples)?;
        assert!(!packed.manifest.is_empty());
        assert_ne!(packed.fingerprint, [0u8; 32]);
        // at least the known sample files
        assert!(packed.files.iter().any(|(p, _)| p.ends_with("content.png")
            || p.ends_with("code.tar")
            || p.ends_with("contract.rgbc")));
        let p2 = filepack::pack_directory(samples)?;
        assert_eq!(packed.fingerprint, p2.fingerprint);
    }
    Ok(())
}

// Red TDD test for high-level file:: outboard (will fail until impl in file.rs).
// Covers: public bare main (no header prepended for !Encrypted), sidecars, optional out-of-band Header (with mac),
// roundtrips via file decode_outboard (with/without header), encrypted outboard bare main + sidecars,
// specific error cases, content equality, c# , 0-byte. Uses matches! for errors (avoids past generic issues).
#[test]
fn file_outboard_high_level_bare_and_header() -> Result<()> {
    let _ = pretty_env_logger::try_init();
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let input = b"file-layer outboard bare public + optional header + sidecars TDD test data";

    // Public levels: bare main (no magic header in main), Some(header) for out-of-band, sidecars present for bits
    for &level in &[0u8, 2, 4, 6, 8, 10, 12, 14] {
        let (hdr_opt, oenc): (Option<Header>, OutboardEncoded) =
            file::encode_outboard(&key, input, level, Some(*b"testmeta"))?;
        assert!(
            hdr_opt.is_some(),
            "out-of-band header for public file outboard level {}",
            level
        );
        let hdr = hdr_opt.unwrap();
        assert_eq!(hdr.format.bits(), level);
        assert_eq!(hdr.metadata, Some(*b"testmeta"));
        // Critical: bare main for public outboard has NO Carbonado header prepended
        assert!(
            !oenc.main.starts_with(carbonado::constants::MAGICNO),
            "public outboard main must be bare (no header prefix) for c{}",
            level
        );
        // bytes_verifiable reflects bare size
        assert_eq!(oenc.info.bytes_verifiable, oenc.main.len() as u32);
        if (level & 0b100) != 0 {
            assert!(
                oenc.bao_outboard.is_some(),
                "bao requires sidecar in file outboard c{}",
                level
            );
        }

        // roundtrip decode_outboard with header (verifies header_mac)
        let hbytes = hdr.try_to_vec()?;
        let rec_with_h = file::decode_outboard(
            &key,
            hdr.hash.as_bytes(),
            Some(&hbytes),
            &oenc.main,
            oenc.bao_outboard.as_deref(),
            oenc.fec_parity.as_deref(),
            oenc.info.padding_len,
            level,
        )?;
        assert_eq!(
            rec_with_h, input,
            "file outboard roundtrip with header c{}",
            level
        );

        // without header (public bare serving path, uses bao outboard for verif)
        let rec_no_h = file::decode_outboard(
            &key,
            oenc.hash.as_bytes(),
            None,
            &oenc.main,
            oenc.bao_outboard.as_deref(),
            oenc.fec_parity.as_deref(),
            oenc.info.padding_len,
            level,
        )?;
        assert_eq!(
            rec_no_h, input,
            "file outboard roundtrip bare no-header c{}",
            level
        );
    }

    // 0-byte public via file outboard
    let empty: &[u8] = &[];
    let (h0, o0) = file::encode_outboard(&key, empty, 4, None)?;
    assert!(h0.is_some());
    assert!(o0.main.is_empty());
    let h0_bytes = h0.as_ref().map(|hh| hh.try_to_vec().unwrap());
    let r0 = file::decode_outboard(
        &key,
        o0.hash.as_bytes(),
        h0_bytes.as_deref(),
        &o0.main,
        o0.bao_outboard.as_deref(),
        o0.fec_parity.as_deref(),
        o0.info.padding_len,
        4,
    )?;
    assert_eq!(r0, empty);

    // c# commitment still holds via file layer
    let o4 = file::encode_outboard(&key, input, 4, None)?.1;
    let o6 = file::encode_outboard(&key, input, 6, None)?.1;
    assert_ne!(
        o4.hash, o6.hash,
        "file outboard different c produce different keyed roots"
    );

    // Encrypted outboard: bare main (no MAGIC), bao sidecar, nonce in out-of-band header
    let (he_opt, oe) = file::encode_outboard(&key, input, 5, None)?;
    assert!(he_opt.is_some());
    let hdr_e = he_opt.unwrap();
    assert!(
        oe.bao_outboard.is_some(),
        "encrypted file outboard requires bao sidecar for c5"
    );
    assert!(
        !oe.main.starts_with(carbonado::constants::MAGICNO),
        "encrypted outboard main must be bare ciphertext"
    );
    assert_ne!(
        hdr_e.payload_nonce, [0u8; 16],
        "encrypted header must carry nonce"
    );

    let hbytes = hdr_e.try_to_vec()?;
    let rec_via_out = file::decode_outboard(
        &key,
        hdr_e.hash.as_bytes(),
        Some(&hbytes),
        &oe.main,
        oe.bao_outboard.as_deref(),
        oe.fec_parity.as_deref(),
        oe.info.padding_len,
        5,
    )?;
    assert_eq!(rec_via_out, input, "file encrypted outboard roundtrip c5");

    // Encrypted outboard without header fails (nonce required for header-path decrypt).
    let err_no_hdr = file::decode_outboard(
        &key,
        oe.hash.as_bytes(),
        None,
        &oe.main,
        oe.bao_outboard.as_deref(),
        oe.fec_parity.as_deref(),
        oe.info.padding_len,
        5,
    )
    .unwrap_err();
    assert!(
        matches!(err_no_hdr, CarbonadoError::MissingOutboardHeader),
        "enc outboard without header must error specifically, got {err_no_hdr:?}"
    );

    // error: missing sidecar for bao public via file decode_outboard (specific error)
    let ob = file::encode_outboard(&key, input, 4, None)?.1;
    let err = file::decode_outboard(
        &key,
        ob.hash.as_bytes(),
        None,
        &ob.main,
        None,
        None,
        ob.info.padding_len,
        4,
    )
    .unwrap_err();
    assert!(
        matches!(err, CarbonadoError::MissingBaoOutboard),
        "specific missing error, not generic"
    );

    Ok(())
}

// Red TDD test for scrub_outboard (bare + sidecars). Will fail until impl.
#[test]
fn scrub_outboard_bare_sidecars() -> Result<()> {
    let _ = pretty_env_logger::try_init();
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let input = b"scrub outboard TDD: bare main + bao_ob + fec_par for public zfec+bao";

    // Use level 12 = Bao + Zfec (public) ; outboard bare + sidecars
    let oenc: OutboardEncoded = encode_outboard(&key, input, 12)?;
    let bare_main = oenc.main;
    let bao_ob = oenc.bao_outboard.clone().expect("bao sidecar");
    let fec_par = oenc.fec_parity.clone().expect("fec parity");
    let h = oenc.hash;
    let ei = oenc.info.clone();

    // Good case: scrub unnecessary
    let unnec = scrub_outboard(
        &bare_main,
        Some(&bao_ob),
        Some(&fec_par),
        &ei,
        12,
        h.as_bytes(),
    );
    assert!(unnec.is_err(), "good data -> unnecessary");
    if let Err(e) = unnec {
        assert!(
            matches!(e, CarbonadoError::UnnecessaryScrub),
            "scrub on good outboard data must be UnnecessaryScrub (specific)"
        );
    }

    // Corrupt bare, scrub recover using sidecars
    let mut corrupted = bare_main.clone();
    if !corrupted.is_empty() {
        corrupted[0] ^= 0xff;
        // also taint a bit in middle if long enough
        let mid = corrupted.len() / 2;
        if mid < corrupted.len() {
            corrupted[mid] ^= 0x55;
        }
    }
    let recovered = scrub_outboard(
        &corrupted,
        Some(&bao_ob),
        Some(&fec_par),
        &ei,
        12,
        h.as_bytes(),
    )?;
    // After recovery roundtrip via decode_outboard (which does bao_with inside)
    let rec_plain = decode_outboard(
        &key,
        h.as_bytes(),
        &recovered,
        Some(&bao_ob),
        Some(&fec_par),
        ei.padding_len,
        12,
    )?;
    assert_eq!(
        rec_plain, input,
        "scrub_outboard + decode recovers plaintext"
    );

    Ok(())
}

/// TDD test expansion: high-level file outboard with metadata; header_mac must bind it;
/// roundtrip preserves metadata; tampering header (even if mac recompute not) caught.
#[test]
fn file_outboard_metadata_roundtrip_and_mac_binding() -> Result<()> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let input = b"metadata test for outboard header auth";
    let meta = Some(*b"metameta");

    let (hdr_opt, oenc) = file::encode_outboard(&key, input, 4, meta)?;
    let hdr = hdr_opt.expect("public outboard produces out-of-band header");
    assert_eq!(hdr.metadata, meta, "metadata roundtrips in header");

    // decode with header succeeds
    let rec = file::decode_outboard(
        &key,
        oenc.hash.as_bytes(),
        Some(&hdr.try_to_vec()?),
        &oenc.main,
        oenc.bao_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        4,
    )?;
    assert_eq!(rec, input);

    // Tamper the serialized header metadata bytes (after mac computed); decode must fail auth
    let mut bad_hdr_bytes = hdr.try_to_vec()?;
    // metadata is last 8 bytes; flip one (this will fail mac verify)
    if bad_hdr_bytes.len() == Header::LEN {
        bad_hdr_bytes[Header::LEN - 1] ^= 0x01;
    }
    let err = file::decode_outboard(
        &key,
        oenc.hash.as_bytes(),
        Some(&bad_hdr_bytes),
        &oenc.main,
        oenc.bao_outboard.as_deref(),
        None,
        oenc.info.padding_len,
        4,
    )
    .unwrap_err();
    assert!(
        matches!(err, CarbonadoError::AuthenticationFailed),
        "tampered metadata in header must fail header_mac auth, got {:?}",
        err
    );

    Ok(())
}

/// TDD (red first): short input to high-level file::decode must return specific
/// InvalidHeaderLength error, never panic (split_at guard). Mirrors existing
/// guards in decode_outboard + TryFrom. Written before the impl guard.
#[test]
fn file_decode_short_input_returns_specific_error_not_panic() -> Result<()> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let short: &[u8] = &[0u8; 10]; // << Header::LEN (177)
    let err = carbonado::file::decode(&key, short).unwrap_err();
    assert!(
        matches!(err, CarbonadoError::InvalidHeaderLength),
        "short input to decode must give InvalidHeaderLength, got {:?}",
        err
    );

    // Also just under the threshold
    let almost = vec![0u8; Header::LEN - 1];
    let err2 = carbonado::file::decode(&key, &almost).unwrap_err();
    assert!(
        matches!(err2, CarbonadoError::InvalidHeaderLength),
        "almost-header input must give InvalidHeaderLength"
    );
    Ok(())
}
