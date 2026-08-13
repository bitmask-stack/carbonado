//! Async adapter for inboard decode — stages encoded body, then dual-aware sync decode (R10).

use crate::{
    constants::Format,
    error::CarbonadoError,
    stream::{
        io::{
            async_copy_all, async_copy_bounded, async_reject_trailing, AsyncPipelineSink,
            AsyncPipelineSource, BoundedCopyTruncation,
        },
        spool::SeekableSpool,
        stream_decode,
    },
};

/// Async inboard decode from [`AsyncPipelineSource`] to [`AsyncPipelineSink`].
///
/// Same high-level semantics as [`super::stream_decode`]: Bao verify → FEC reverse → decrypt →
/// decompress (embedded-nonce layout).
///
/// ## Dual-backend policy (R10 closed)
///
/// | Concern | Policy |
/// |---------|--------|
/// | Dual freeze / `just test-lean-ci` | **Never requires `async`** — permanent. Features stay `"backend-lean,pqc,ots,cli"`. |
/// | `tests/streaming_async.rs` | `#![cfg(feature = "async")]` → **0 tests** under freeze (feature-gated; not dual-suite red). |
/// | Engine after spool | Calls dual-aware [`super::stream_decode`] (R5 E1), **not** pure-Rust-only `stream_decode_inboard_pipeline`. |
/// | `backend-rust` + `async` | Same S4 inboard pipeline as sync `stream_decode`. |
/// | `backend-lean` + `async` | Spool → E1 `stream_decode` → Lean `decode` (see costs; not stream E2). |
/// | WASM + `async` | [`CarbonadoError::NotImplemented`] (host temp spool). |
///
/// Sync stream dual E1 remains the dual-suite contract for streaming. Async is an optional
/// concurrency adapter (disk spool bridge), not part of the freeze bar.
///
/// Optional dual smoke (not freeze):
/// `cargo test --no-default-features --features "backend-lean,pqc,ots,async,async-tokio" --test streaming_async`
/// with `CARBONADO_LEAN_LIB` / `LD_LIBRARY_PATH` set.
///
/// ## Phase 2 materialization tradeoff
///
/// Unlike sync [`super::stream_decode`] under `backend-rust`, which streams incrementally from
/// [`std::io::Read`] into Bao/FEC (S4), this adapter **fully stages the encoded body** to a
/// disk-backed [`SeekableSpool`] before invoking the sync path. Every async decode therefore pays
/// **O(encoded_body)** disk write + read for the input boundary, plus a plaintext spool before
/// [`async_copy_all`].
///
/// **Peak costs (honest):**
/// - **Disk (all engines):** O(encoded) staging + O(logical) plaintext spool traffic.
/// - **`backend-rust` peak RAM:** spool/chunk-oriented (FEC verification still O(FEC body)
///   shard buffers on the sync S4 path where applicable).
/// - **`backend-lean` peak RAM:** O(**encoded** + **logical**) — E1 `read_encoded_body`
///   materializes a full body `Vec` before Lean decode, then O(logical) plaintext. Do **not**
///   treat lean+async as O(logical) RAM only.
///
/// Not stream E2 / true chunked async Bao.
///
/// ## Executor blocking
///
/// The dual-aware sync path ([`super::stream_decode`]) runs as a **blocking** section inside
/// this `async fn`. On Tokio/async-std this can starve the executor for large payloads.
/// Integrators should either:
/// - enable the `async-tokio` feature (uses `tokio::task::spawn_blocking` for the sync section), or
/// - call this from `tokio::task::spawn_blocking` / a dedicated thread pool themselves.
///
/// Pass `encoded_body_len` when the reader may contain trailing bytes after the encoded body
/// (FEC c8, compressed c4, verification c12/c14). When `Some`, excess or truncated input is rejected.
///
/// ## Truncation error taxonomy (spool bridge)
///
/// Non-verification formats (c4, c8) surface staging truncation as
/// `StdIoError(UnexpectedEof, "truncated encoded body")` or `"truncated FEC body"` — aligned with
/// sync `take(limit)` paths. **Verification formats (c6/c12/c14/c15):**
/// - **`backend-rust`:** sync fails during incremental Bao (`BaoResponseTruncated`); this
///   adapter fails earlier at [`async_copy_bounded`] with the encoded-body staging message.
/// - **`backend-lean`:** both fail closed **before Bao**, but **not** at the same site/message —
///   async fails at adapter staging (`"truncated encoded body"`); sync E1 fails later in
///   `read_encoded_body` / `read_exact` as generic `UnexpectedEof` (`"failed to fill whole buffer"`).
///
/// Callers must not assume identical error variants or messages across sync/async or engines.
#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
pub async fn stream_decode_async<R, W>(
    master_key: &[u8],
    hash: &[u8],
    mut input: R,
    padding: u32,
    format: u8,
    encoded_body_len: Option<u64>,
    output: &mut W,
) -> Result<u64, CarbonadoError>
where
    R: AsyncPipelineSource + Unpin,
    W: AsyncPipelineSink + Unpin,
{
    let fmt = Format::from(format);
    let truncation = if fmt.contains(Format::Fec) && !fmt.contains(Format::Verification) {
        BoundedCopyTruncation::FecBody
    } else {
        BoundedCopyTruncation::EncodedBody
    };

    let mut encoded_spool = SeekableSpool::new()?;
    async_copy_bounded(&mut input, &mut encoded_spool, encoded_body_len, truncation).await?;
    if let Some(declared) = encoded_body_len {
        async_reject_trailing(&mut input, declared).await?;
    }
    encoded_spool.rewind()?;

    // Body length already enforced by staging; pass None so dual-aware stream_decode
    // (R5 E1 under backend-lean, S4 pipeline under backend-rust) reads the whole spool.
    let (nbytes, mut plaintext_spool) =
        run_sync_stream_decode(master_key, hash, encoded_spool, padding, format).await?;
    async_copy_all(&mut plaintext_spool, output).await?;
    Ok(nbytes)
}

/// WASM: `SeekableSpool` requires host temp files; async decode is unsupported at runtime.
#[cfg(all(feature = "async", target_arch = "wasm32"))]
pub async fn stream_decode_async<R, W>(
    _master_key: &[u8],
    _hash: &[u8],
    _input: R,
    _padding: u32,
    _format: u8,
    _encoded_body_len: Option<u64>,
    _output: &mut W,
) -> Result<u64, CarbonadoError>
where
    R: AsyncPipelineSource + Unpin,
    W: AsyncPipelineSink + Unpin,
{
    Err(CarbonadoError::NotImplemented)
}

/// Blocking dual-aware inboard decode after async staging.
///
/// Uses [`stream_decode`] so `backend-lean` hits Lean E1 (no silent pure-Rust pipeline).
#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
async fn run_sync_stream_decode(
    master_key: &[u8],
    hash: &[u8],
    encoded_spool: SeekableSpool,
    padding: u32,
    format: u8,
) -> Result<(u64, SeekableSpool), CarbonadoError> {
    #[cfg(feature = "async-tokio")]
    {
        let master_key: [u8; 32] = master_key
            .try_into()
            .map_err(|_| CarbonadoError::InvalidKeyLength)?;
        let hash_len = hash.len();
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| CarbonadoError::HashDecodeError(32, hash_len))?;
        tokio::task::spawn_blocking(move || {
            let mut plaintext_spool = SeekableSpool::new()?;
            let nbytes = stream_decode(
                &master_key,
                &hash,
                encoded_spool,
                padding,
                format,
                None,
                &mut plaintext_spool,
            )?;
            plaintext_spool.rewind()?;
            Ok((nbytes, plaintext_spool))
        })
        .await
        .map_err(|e| {
            CarbonadoError::InternalStateError(format!("spawn_blocking join failed: {e}"))
        })?
    }

    #[cfg(not(feature = "async-tokio"))]
    {
        let mut plaintext_spool = SeekableSpool::new()?;
        let nbytes = stream_decode(
            master_key,
            hash,
            encoded_spool,
            padding,
            format,
            None,
            &mut plaintext_spool,
        )?;
        plaintext_spool.rewind()?;
        Ok((nbytes, plaintext_spool))
    }
}
