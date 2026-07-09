//! Async adapter for inboard decode — delegates to the canonical sync pipeline (Phase 2).

use crate::{
    constants::Format,
    error::CarbonadoError,
    stream::{
        decode::stream_decode_inboard_pipeline,
        io::{
            async_copy_all, async_copy_bounded, async_reject_trailing, AsyncPipelineSink,
            AsyncPipelineSource, BoundedCopyTruncation,
        },
        spool::SeekableSpool,
    },
};

/// Async inboard decode from [`AsyncPipelineSource`] to [`AsyncPipelineSink`].
///
/// Same semantics as [`super::stream_decode`]: Bao verify → FEC reverse → decrypt → decompress.
///
/// ## Phase 2 materialization tradeoff
///
/// Unlike sync [`super::stream_decode`], which streams incrementally from [`std::io::Read`]
/// into Bao/FEC (S4), this adapter **fully stages the encoded body** to a disk-backed
/// [`SeekableSpool`] before invoking the sync pipeline. Every async decode therefore pays
/// **O(encoded_body)** disk write + read for the input boundary, plus a plaintext spool before
/// [`async_copy_all`]. Peak RAM stays O(chunk) via spool files, but disk I/O is higher than sync
/// incremental decode. Phase 3 will stream Bao via `bao_tree::io::fsm` (or equivalent) to
/// eliminate the encoded-body spool where possible.
///
/// ## Executor blocking
///
/// The sync pipeline (`stream_decode_inboard_pipeline`) runs as a **blocking** section inside
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
/// sync `take(limit)` paths. **Verification formats (c6/c12/c14/c15)** diverge: sync
/// [`super::stream_decode`] fails during incremental Bao read (`BaoResponseTruncated`), while this
/// adapter fails earlier at [`async_copy_bounded`] staging with the encoded-body message. Callers
/// must not assume identical error variants across sync/async for verification truncated bodies.
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

    let (nbytes, mut plaintext_spool) =
        run_sync_inboard_pipeline(master_key, hash, encoded_spool, padding, format).await?;
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

#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
async fn run_sync_inboard_pipeline(
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
            let nbytes = stream_decode_inboard_pipeline(
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
        let nbytes = stream_decode_inboard_pipeline(
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
