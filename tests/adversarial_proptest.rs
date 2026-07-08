//! Phase 1B: adversarial proptest — random bytes must never panic on decode paths.
//!
//! Short-input guards for `file::decode_outboard` (header path) are consolidated here;
//! see also `tests/header_tamper.rs::decode_outboard_short_header_returns_invalid_header_length_not_panic`.

use carbonado::{
    decode_outboard,
    error::CarbonadoError,
    file::{self, Header},
};
use proptest::prelude::*;
use rand::RngCore;

fn random_master() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

proptest! {
    #[test]
    fn prop_header_try_from_never_panics(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = Header::try_from(data.as_slice());
    }

    #[test]
    fn prop_file_decode_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..4096),
        key in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let _ = file::decode(&key, &data);
    }

    #[test]
    fn prop_decode_outboard_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..4096),
        hash in prop::collection::vec(any::<u8>(), 0..64),
        key in prop::collection::vec(any::<u8>(), 0..64),
        format in any::<u8>(),
        padding in any::<u32>(),
    ) {
        let _ = decode_outboard(&key, &hash, &data, None, None, padding, format);
    }

    #[test]
    fn prop_file_decode_outboard_header_path_never_panics(
        header in prop::collection::vec(any::<u8>(), 0..4096),
        main in prop::collection::vec(any::<u8>(), 0..4096),
        hash in prop::collection::vec(any::<u8>(), 0..64),
        key in prop::collection::vec(any::<u8>(), 0..64),
        format in any::<u8>(),
        padding in any::<u32>(),
    ) {
        let _ = file::decode_outboard(
            &key,
            &hash,
            Some(&header),
            &main,
            None,
            None,
            padding,
            format,
        );
    }
}

#[test]
fn adversarial_short_inputs_return_err_not_panic() {
    let key = random_master();
    let empty: &[u8] = &[];

    let err = file::decode(&key, empty).unwrap_err();
    assert!(matches!(err, CarbonadoError::InvalidHeaderLength));

    let err2 = Header::try_from(empty).unwrap_err();
    assert!(matches!(err2, CarbonadoError::InvalidHeaderLength));

    // file::decode_outboard header path: empty and almost-header inputs.
    let (hdr_opt, oenc) =
        file::encode_outboard(&key, b"short input consolidation", 14, None).unwrap();
    let hdr = hdr_opt.unwrap();
    let hash = hdr.hash.as_bytes();

    let err3 = file::decode_outboard(
        &key,
        hash,
        Some(empty),
        &oenc.main,
        oenc.bao_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        14,
    )
    .unwrap_err();
    assert!(
        matches!(err3, CarbonadoError::InvalidHeaderLength),
        "empty header to decode_outboard must give InvalidHeaderLength"
    );

    let almost = vec![0u8; Header::LEN - 1];
    let err4 = file::decode_outboard(
        &key,
        hash,
        Some(&almost),
        &oenc.main,
        oenc.bao_outboard.as_deref(),
        oenc.fec_parity.as_deref(),
        oenc.info.padding_len,
        14,
    )
    .unwrap_err();
    assert!(
        matches!(err4, CarbonadoError::InvalidHeaderLength),
        "almost-header to decode_outboard must give InvalidHeaderLength"
    );
}
