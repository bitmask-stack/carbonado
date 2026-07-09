//! Carbonado integration contract tests for [bao-tree PR #77](https://github.com/n0-computer/bao-tree/pull/77)
//! keyed BLAKE3 mode.
//!
//! These tests document and validate how Carbonado v2 uses the upstream keyed API:
//! - Key: `blake3::derive_key("carbonado-v2/verification", &[format_byte])`
//! - Block size: `BlockSize::from_chunk_log(2)` (4 KiB leaves, `SLICE_LEN=4096`)
//! - Entry points: `PostOrderMemOutboard::create_keyed`, `keyed_outboard_post_order`,
//!   `keyed_encode_ranges_validated`, `keyed_decode_ranges`, `keyed_valid_ranges`
//!
//! A passing `cargo test --test bao_keyed_contract` is evidence that Carbonado's production
//! paths exercise the PR #77 surface correctly.

use std::io::Cursor;

use anyhow::Result;
use bao_tree::{
    blake3,
    io::{
        outboard::PostOrderMemOutboard,
        sync::{decode_ranges, keyed_encode_ranges_validated, keyed_valid_ranges},
    },
    BaoTree, ChunkNum, ChunkRanges,
};
use carbonado::{
    carbonado_verification_key,
    constants::{BAO_BLOCK_SIZE, SLICE_LEN},
    decode_outboard, encode, encode_outboard,
    error::CarbonadoError,
    stream::bao::{verification_inboard_buffer, verification_outboard_buffer},
    stream::encode::stream_encode_buffer,
    verify_slice, verify_slice_inboard_seekable, verify_slice_outboard,
};
use rand::RngCore;

const BAO_ONLY: u8 = 0x04;
const BAO_ZFEC: u8 = 0x0C;
const C14: u8 = 0x0E;

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// PR #77: keyed roots commit to the agreed 32-byte key, not raw BLAKE3(data).
#[test]
fn carbonado_key_derivation_and_domain_separation() {
    let data = patterned(12_345);
    let key4 = carbonado_verification_key(BAO_ONLY);
    let key6 = carbonado_verification_key(0x06);
    let key14 = carbonado_verification_key(C14);

    let root4 = PostOrderMemOutboard::create_keyed(&data, BAO_BLOCK_SIZE, &key4).root;
    let root6 = PostOrderMemOutboard::create_keyed(&data, BAO_BLOCK_SIZE, &key6).root;
    let root14 = PostOrderMemOutboard::create_keyed(&data, BAO_BLOCK_SIZE, &key14).root;

    assert_ne!(root4, root6);
    assert_ne!(root4, root14);
    assert_ne!(root4, blake3::hash(&data));
    assert_ne!(root4, blake3::keyed_hash(&key6, &data));
}

/// Bao-only (c4): Carbonado encode hash matches direct `PostOrderMemOutboard::create_keyed`.
#[test]
fn bao_only_encode_root_matches_bao_tree_create_keyed() -> Result<()> {
    for &len in &[0usize, 1, 100, 4095, 4096, 4097, 8192, 50_000] {
        let input = patterned(len);
        let key = carbonado_verification_key(BAO_ONLY);

        let (_blob, hash, _info) = stream_encode_buffer(&[0u8; 32], &input, BAO_ONLY)?;
        let direct = PostOrderMemOutboard::create_keyed(&input, BAO_BLOCK_SIZE, &key);
        assert_eq!(
            hash.as_bytes(),
            direct.root.as_bytes(),
            "len={len}: stream_encode_buffer hash must match create_keyed root"
        );
        assert_eq!(
            hash.as_bytes(),
            blake3::keyed_hash(&key, &input).as_bytes(),
            "len={len}: root must match blake3::keyed_hash (PR #77 contract)"
        );
    }
    Ok(())
}

/// All Carbonado buffer entry points agree on the keyed root for identical logical input.
#[test]
fn encode_entry_points_agree_on_keyed_root() -> Result<()> {
    let input = patterned(18_432);
    let master = [7u8; 32];

    let from_encoding = encode(&master, &input, BAO_ONLY)?;
    let from_stream = stream_encode_buffer(&master, &input, BAO_ONLY)?;
    let from_bao_helper = verification_inboard_buffer(&input, BAO_ONLY)?;

    assert_eq!(from_encoding.1, from_stream.1);
    assert_eq!(from_encoding.1, from_bao_helper.1);

    let key = carbonado_verification_key(BAO_ONLY);
    let direct = PostOrderMemOutboard::create_keyed(&input, BAO_BLOCK_SIZE, &key);
    assert_eq!(from_encoding.1.as_bytes(), direct.root.as_bytes());
    Ok(())
}

/// Outboard sidecar from Carbonado matches `create_keyed` (bao-only c4: main == logical body).
#[test]
fn outboard_sidecar_matches_bao_tree_keyed_outboard() -> Result<()> {
    let input = patterned(22_000);
    let key = carbonado_verification_key(BAO_ONLY);

    let oenc = encode_outboard(&[0u8; 32], &input, BAO_ONLY)?;
    let bao_ob = oenc
        .verification_outboard
        .as_ref()
        .expect("c4 requires .out sidecar");
    assert_eq!(
        oenc.main, input,
        "c4 outboard main is the logical bao input"
    );

    let direct = PostOrderMemOutboard::create_keyed(&input, BAO_BLOCK_SIZE, &key);
    assert_eq!(oenc.hash.as_bytes(), direct.root.as_bytes());
    assert_eq!(bao_ob, &direct.data);

    let (ob_buf, hash_buf) = verification_outboard_buffer(&input, BAO_ONLY)?;
    assert_eq!(oenc.hash, hash_buf);
    assert_eq!(bao_ob, &ob_buf);
    Ok(())
}

/// PR #77 cross-mode: keyed Carbonado stream cannot decode with unkeyed `decode_ranges`.
#[test]
fn keyed_encode_rejects_unkeyed_decode_ranges() -> Result<()> {
    let input = patterned(9_000);
    let key = carbonado_verification_key(BAO_ONLY);
    let outboard = PostOrderMemOutboard::create_keyed(&input, BAO_BLOCK_SIZE, &key);
    let mut encoded = Vec::new();
    keyed_encode_ranges_validated(&input, &outboard, &ChunkRanges::all(), &mut encoded, &key)?;

    let tree = BaoTree::new(input.len() as u64, BAO_BLOCK_SIZE);
    let mut decoded = Vec::new();
    let mut ob = bao_tree::io::outboard::EmptyOutboard {
        tree,
        root: outboard.root,
    };
    let err = decode_ranges(
        Cursor::new(&encoded),
        &ChunkRanges::all(),
        &mut decoded,
        &mut ob,
    )
    .unwrap_err();
    assert!(
        !decoded.eq(&input),
        "unkeyed decode must not silently recover keyed-encoded stream"
    );
    let _ = err;
    Ok(())
}

/// Wrong format byte => wrong key => authentication failure (inboard + outboard).
#[test]
fn wrong_format_key_rejected_at_carbonado_layer() -> Result<()> {
    let input = b"bao-tree PR77 wrong-key contract";
    let master = [3u8; 32];
    let encoded = encode(&master, input, BAO_ZFEC)?;
    let blob = &encoded.0;
    let hash = encoded.1;

    let err = verify_slice_inboard_seekable(blob, 0, 1, hash.as_bytes(), BAO_ZFEC + 1).unwrap_err();
    assert!(matches!(err, CarbonadoError::AuthenticationFailed));

    let oenc = encode_outboard(&master, input, C14)?;
    let bao_ob = oenc.verification_outboard.as_ref().unwrap();
    let err_ob = verify_slice_outboard(
        oenc.main.as_slice(),
        bao_ob,
        oenc.main.len() as u64,
        0,
        1,
        oenc.hash.as_bytes(),
        BAO_ONLY,
    )
    .unwrap_err();
    assert!(matches!(err_ob, CarbonadoError::AuthenticationFailed));
    Ok(())
}

/// `keyed_valid_ranges` over Carbonado-produced outboard matches `verify_slice_outboard` bytes.
#[test]
fn keyed_valid_ranges_matches_verify_slice_outboard() -> Result<()> {
    let input = patterned(3 * SLICE_LEN as usize + 512);
    let master = [9u8; 32];
    // c4 bao-only: bare main bytes align 1:1 with logical input slices.
    let oenc = encode_outboard(&master, &input, BAO_ONLY)?;
    let bao_ob = oenc.verification_outboard.as_ref().unwrap();
    let key = carbonado_verification_key(BAO_ONLY);
    let bare_len = oenc.main.len() as u64;
    let tree = BaoTree::new(bare_len, BAO_BLOCK_SIZE);
    let ob = PostOrderMemOutboard {
        root: blake3::Hash::from_bytes(*oenc.hash.as_bytes()),
        tree,
        data: bao_ob.clone(),
    };

    const CHUNKS_PER_SLICE: u64 = 1 << BAO_BLOCK_SIZE.chunk_log();

    for index in [0u32, 1, 2] {
        let start = u64::from(index) * u64::from(SLICE_LEN);
        let end = (start + u64::from(SLICE_LEN)).min(bare_len);
        let chunk_start = ChunkNum(u64::from(index) * CHUNKS_PER_SLICE);
        let chunk_end = ChunkNum(u64::from(index + 1) * CHUNKS_PER_SLICE);
        let ranges = ChunkRanges::from(chunk_start..chunk_end);

        let mut validated_chunks = 0u64;
        for item in keyed_valid_ranges(&ob, oenc.main.as_slice(), &ranges, &key) {
            let range = item?;
            validated_chunks += range.end.0 - range.start.0;
        }
        assert!(
            validated_chunks >= CHUNKS_PER_SLICE,
            "keyed_valid_ranges must validate slice {index}"
        );

        let via_carbonado = verify_slice_outboard(
            oenc.main.as_slice(),
            bao_ob,
            bare_len,
            index,
            1,
            oenc.hash.as_bytes(),
            BAO_ONLY,
        )?;
        let off = start as usize;
        let want_len = (end - start) as usize;
        assert_eq!(
            &via_carbonado[..want_len],
            &input[off..off + want_len],
            "slice {index} content"
        );
    }
    Ok(())
}

/// Multi-chunk inboard: middle slice via seekable API matches logical input.
#[test]
fn keyed_inboard_partial_slice_roundtrip() -> Result<()> {
    let input = patterned(5 * SLICE_LEN as usize);
    let mut master = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut master);
    let encoded = encode(&master, &input, BAO_ONLY)?;
    let mid = 2u32;
    let slice = verify_slice(&encoded.0, mid, 1, encoded.1.as_bytes(), BAO_ONLY)?;
    let off = mid as usize * SLICE_LEN as usize;
    assert_eq!(&slice[..], &input[off..off + SLICE_LEN as usize]);
    Ok(())
}

/// Full outboard roundtrip still holds under keyed roots (c12 = Bao + RS).
#[test]
fn keyed_outboard_full_roundtrip_with_fec() -> Result<()> {
    let input = patterned(20_000);
    let master = [11u8; 32];
    let oenc = encode_outboard(&master, &input, BAO_ZFEC)?;
    let rec = decode_outboard(
        &master,
        oenc.hash.as_bytes(),
        &oenc.main,
        oenc.verification_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        BAO_ZFEC,
    )?;
    assert_eq!(rec, input);

    let key = carbonado_verification_key(BAO_ZFEC);
    let fec_body = &oenc.main;
    let direct = PostOrderMemOutboard::create_keyed(fec_body, BAO_BLOCK_SIZE, &key);
    assert_eq!(oenc.hash.as_bytes(), direct.root.as_bytes());
    Ok(())
}

/// Encrypted + Bao (c5) still keys on the format bitmask byte, not plaintext pipeline alone.
#[test]
fn encrypted_bao_still_keyed_on_format_byte() -> Result<()> {
    let input = b"encrypted bao keyed root binding";
    let master = [5u8; 32];
    let o4 = encode_outboard(&master, input, BAO_ONLY)?;
    let o5 = encode_outboard(&master, input, 0x05)?;
    assert_ne!(
        o4.hash, o5.hash,
        "encrypted c5 must differ from public c4 keyed root"
    );
    Ok(())
}
