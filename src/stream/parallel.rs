//! CPU parallelism for streaming encode hot paths (Phase 3).
//!
//! Enabled by default via the `parallel` Cargo feature. Disable with
//! `--no-default-features` (and re-enable needed features) for serial-only `rs.encode`.
//! Parallel output is bit-identical to the serial reference path.

use std::sync::OnceLock;

use reed_solomon_erasure::galois_8::{mul_slice, mul_slice_xor, ReedSolomon};

use crate::{
    constants::{FEC_K, FEC_M},
    error::CarbonadoError,
};

/// Minimum `chunk_len` (bytes per RS shard) before fork-join parity encoding is used.
///
/// Defensive threshold for direct callers of [`encode_rs_parity_with_config`]. Carbonado
/// inboard/outboard FEC (`calc_padding_len`) always yields `chunk_len >= 4096` for non-empty
/// logical input, so [`FecInboardEncoder`] stripes parallelize whenever `max_threads > 1`.
pub const RS_PARITY_PARALLEL_MIN_CHUNK_LEN: usize = 4096;

/// Thread-count policy for RS parity fork-join (cap at 4 parity shards).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParallelConfig {
    /// Maximum concurrent scoped workers per wave when parallelizing parity generation.
    /// Capped at `FEC_M - FEC_K` (4). Values `<= 1` force the serial path.
    pub max_threads: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            max_threads: default_max_threads(),
        }
    }
}

/// Returns `std::thread::available_parallelism().min(4)`, or `1` when unavailable.
pub fn default_max_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().min(FEC_M - FEC_K))
        .unwrap_or(1)
}

/// Whether the parallel RS parity path would run for the given stripe geometry.
#[doc(hidden)]
pub fn rs_parity_parallelism_active(chunk_len: usize, config: ParallelConfig) -> bool {
    should_parallelize_rs_parity(chunk_len, config.max_threads)
}

/// Cached RS parity coefficient rows for Carbonado's fixed 4/8 geometry.
#[derive(Clone, Debug)]
struct RsParityMatrix {
    rows: [[u8; FEC_K]; FEC_M - FEC_K],
}

impl RsParityMatrix {
    fn from_codec(rs: &ReedSolomon) -> Result<Self, CarbonadoError> {
        let mut rows = [[0u8; FEC_K]; FEC_M - FEC_K];
        for i in 0..FEC_K {
            let mut data: Vec<Vec<u8>> = vec![vec![0u8; 1]; FEC_K];
            data[i][0] = 1;
            let mut parity: Vec<Vec<u8>> = vec![vec![0u8; 1]; FEC_M - FEC_K];
            rs.encode_sep(&data, &mut parity)
                .map_err(CarbonadoError::FecError)?;
            for (p, par) in parity.iter().enumerate() {
                rows[p][i] = par[0];
            }
        }
        Ok(Self { rows })
    }
}

static RS_PARITY_MATRIX: OnceLock<RsParityMatrix> = OnceLock::new();

fn parity_matrix() -> Result<&'static RsParityMatrix, CarbonadoError> {
    if let Some(matrix) = RS_PARITY_MATRIX.get() {
        return Ok(matrix);
    }
    let rs = ReedSolomon::new(FEC_K, FEC_M - FEC_K).map_err(CarbonadoError::FecError)?;
    let matrix = RsParityMatrix::from_codec(&rs)?;
    let _ = RS_PARITY_MATRIX.set(matrix);
    RS_PARITY_MATRIX.get().ok_or_else(|| {
        CarbonadoError::InternalStateError("RS parity matrix initialization failed".into())
    })
}

fn encode_one_parity_shard(coeffs: &[u8; FEC_K], data_shards: &[&[u8]], out: &mut [u8]) {
    debug_assert_eq!(data_shards.len(), FEC_K);
    debug_assert!(data_shards.iter().all(|s| s.len() == out.len()));

    out.fill(0);
    for (i, shard) in data_shards.iter().enumerate() {
        if i == 0 {
            mul_slice(coeffs[i], shard, out);
        } else {
            mul_slice_xor(coeffs[i], shard, out);
        }
    }
}

/// Serial RS parity generation (canonical reference for determinism tests).
pub fn encode_rs_parity_serial(
    rs: &ReedSolomon,
    shards: &mut [Vec<u8>],
) -> Result<(), CarbonadoError> {
    let (data, parity) = shards.split_at_mut(FEC_K);
    let data_refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    rs.encode_sep(&data_refs, parity)
        .map_err(CarbonadoError::FecError)
}

/// Encode RS parity shards for one stripe.
///
/// With `parallel` on native targets, `max_threads > 1`, and
/// `chunk_len >= RS_PARITY_PARALLEL_MIN_CHUNK_LEN`, parity shards are computed via
/// `std::thread::scope` fork-join in waves of at most `max_threads` workers (deterministic
/// shard index order). Otherwise delegates to [`encode_rs_parity_serial`].
pub fn encode_rs_parity(
    rs: &ReedSolomon,
    shards: &mut [Vec<u8>],
    chunk_len: usize,
) -> Result<(), CarbonadoError> {
    encode_rs_parity_with_config(rs, shards, chunk_len, ParallelConfig::default())
}

/// Like [`encode_rs_parity`] with an explicit per-wave worker cap.
pub fn encode_rs_parity_with_config(
    rs: &ReedSolomon,
    shards: &mut [Vec<u8>],
    chunk_len: usize,
    config: ParallelConfig,
) -> Result<(), CarbonadoError> {
    if !should_parallelize_rs_parity(chunk_len, config.max_threads) {
        return encode_rs_parity_serial(rs, shards);
    }

    let matrix = parity_matrix()?;
    let (data, parity) = shards.split_at_mut(FEC_K);
    let data_refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    let parity_count = FEC_M - FEC_K;
    let workers = config.max_threads.clamp(1, parity_count);

    let mut wave_start = 0usize;
    while wave_start < parity_count {
        let wave_end = (wave_start + workers).min(parity_count);
        std::thread::scope(|scope| {
            let wave = &mut parity[wave_start..wave_end];
            for (local_i, out) in wave.iter_mut().enumerate() {
                let p = wave_start + local_i;
                let coeffs = matrix.rows[p];
                let inputs = data_refs.clone();
                scope.spawn(move || encode_one_parity_shard(&coeffs, &inputs, out));
            }
        });
        wave_start = wave_end;
    }

    Ok(())
}

fn should_parallelize_rs_parity(chunk_len: usize, max_threads: usize) -> bool {
    #[cfg(all(feature = "parallel", not(target_arch = "wasm32")))]
    {
        chunk_len >= RS_PARITY_PARALLEL_MIN_CHUNK_LEN && max_threads > 1
    }
    #[cfg(not(all(feature = "parallel", not(target_arch = "wasm32"))))]
    {
        let _ = (chunk_len, max_threads);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterned_stripe(logical_len: usize) -> Vec<Vec<u8>> {
        let input: Vec<u8> = (0..logical_len).map(|i| (i % 251) as u8).collect();
        let (padding_total, chunk_len) = crate::utils::calc_padding_len(logical_len);
        let padded_len = logical_len + padding_total as usize;
        let chunk_len = chunk_len as usize;
        let mut shards = Vec::with_capacity(FEC_M);
        for _ in 0..FEC_M {
            shards.push(vec![0u8; chunk_len]);
        }
        let mut pos = 0usize;
        for byte in input {
            let shard_idx = pos / chunk_len;
            let shard_off = pos % chunk_len;
            if shard_idx < FEC_K {
                shards[shard_idx][shard_off] = byte;
            }
            pos += 1;
        }
        while pos < padded_len {
            let shard_idx = pos / chunk_len;
            let shard_off = pos % chunk_len;
            if shard_idx < FEC_K {
                shards[shard_idx][shard_off] = 0;
            }
            pos += 1;
        }
        shards
    }

    fn synthetic_pre_parity_shards(chunk_len: usize) -> Vec<Vec<u8>> {
        let mut shards = Vec::with_capacity(FEC_M);
        for i in 0..FEC_M {
            shards.push(vec![(i as u8).wrapping_mul(17); chunk_len]);
        }
        shards
    }

    #[test]
    fn serial_parity_matches_reed_solomon_encode() {
        for logical_len in [1usize, 4096, 16_384, 65_536] {
            let rs = ReedSolomon::new(FEC_K, FEC_M - FEC_K).expect("rs");
            let mut serial = patterned_stripe(logical_len);
            let mut oracle = serial.clone();
            rs.encode(&mut oracle).expect("oracle encode");

            encode_rs_parity_serial(&rs, &mut serial).expect("serial parity");
            assert_eq!(serial, oracle, "logical_len={logical_len}");
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn parallel_parity_matches_serial_for_representative_sizes() {
        for logical_len in [4096usize, 16_384, 65_536, 262_144] {
            let rs = ReedSolomon::new(FEC_K, FEC_M - FEC_K).expect("rs");
            let mut serial = patterned_stripe(logical_len);
            let mut parallel = serial.clone();

            encode_rs_parity_serial(&rs, &mut serial).expect("serial");
            let chunk_len = serial[0].len();
            encode_rs_parity_with_config(
                &rs,
                &mut parallel,
                chunk_len,
                ParallelConfig { max_threads: 4 },
            )
            .expect("parallel");
            assert_eq!(parallel, serial, "logical_len={logical_len}");
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn carbonado_geometry_chunk_len_is_at_least_4096_for_nonempty_input() {
        for logical_len in [1usize, 4095, 4096, 16_384, 65_536] {
            let (_, chunk_len) = crate::utils::calc_padding_len(logical_len);
            if logical_len == 0 {
                assert_eq!(chunk_len, 0);
            } else {
                assert!(
                    chunk_len >= RS_PARITY_PARALLEL_MIN_CHUNK_LEN as u32,
                    "logical_len={logical_len}"
                );
            }
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn below_threshold_chunk_len_uses_serial_path_via_direct_api() {
        let rs = ReedSolomon::new(FEC_K, FEC_M - FEC_K).expect("rs");
        let chunk_len = 1024usize;
        let mut shards = synthetic_pre_parity_shards(chunk_len);
        let mut expected = shards.clone();
        encode_rs_parity_serial(&rs, &mut expected).expect("serial");

        assert!(
            !rs_parity_parallelism_active(chunk_len, ParallelConfig { max_threads: 4 }),
            "sub-threshold chunk_len must not activate parallel path"
        );
        encode_rs_parity_with_config(
            &rs,
            &mut shards,
            chunk_len,
            ParallelConfig { max_threads: 4 },
        )
        .expect("encode_rs_parity");
        assert_eq!(shards, expected);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn max_threads_caps_concurrent_workers_without_changing_output() {
        let rs = ReedSolomon::new(FEC_K, FEC_M - FEC_K).expect("rs");
        let chunk_len = 4096usize;
        let template = synthetic_pre_parity_shards(chunk_len);

        let mut serial = template.clone();
        encode_rs_parity_serial(&rs, &mut serial).expect("serial");

        let mut two_workers = template.clone();
        encode_rs_parity_with_config(
            &rs,
            &mut two_workers,
            chunk_len,
            ParallelConfig { max_threads: 2 },
        )
        .expect("two workers");

        let mut four_workers = template.clone();
        encode_rs_parity_with_config(
            &rs,
            &mut four_workers,
            chunk_len,
            ParallelConfig { max_threads: 4 },
        )
        .expect("four workers");

        assert_eq!(two_workers, serial);
        assert_eq!(four_workers, serial);
        assert!(rs_parity_parallelism_active(
            chunk_len,
            ParallelConfig { max_threads: 2 }
        ));
    }

    #[cfg(all(feature = "parallel", target_arch = "wasm32"))]
    #[test]
    fn wasm32_rs_parity_parallelism_stays_disabled() {
        assert!(!rs_parity_parallelism_active(
            16_384,
            ParallelConfig { max_threads: 4 }
        ));
    }
}
