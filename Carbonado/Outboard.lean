/-
  Outboard body encode/decode (Program G).

  Matches Rust `encoding::encode_outboard` / `decoding::decode_outboard` pure surface:
  * compress → encrypt (embedded nonce layout when encrypted) → bare main
  * FEC parity is a **sidecar** (parity shards only); main is unpadded logical body
  * keyed Bao **post-order outboard** over bare main when Verification bit set

  Directory segments always use Verification|Fec (c12–c15). Catalogs use inboard
  headered path (`Pipeline.encodeHeadered`), not this module.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Crypto.EtM
import Carbonado.Fec.Inboard
import Carbonado.Fec.RS
import Carbonado.Bao.Product
import Carbonado.Pipeline
import Carbonado.Compress

namespace Carbonado.Outboard

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Crypto.EtM
open Carbonado.Fec.Inboard
open Carbonado.Fec.RS
open Carbonado.Bao.Product
open Carbonado.Pipeline
open Carbonado.Compress

/-- Outboard encode result (bare main + optional sidecars). -/
structure OutboardEncoded where
  main : ByteArray
  verificationOutboard : ByteArray
  fecParity : ByteArray
  baoHash : ByteArray
  paddingLen : Nat
  chunkLen : Nat
  /-- Post-compress size when Compression bit set; else 0 (matches Rust `EncodeInfo`). -/
  bytesCompressed : Nat
  /-- Post-encrypt size when Encrypted bit set; else 0. -/
  bytesEncrypted : Nat
  deriving DecidableEq

/--
  Encode FEC parity sidecar only; main remains unpadded input.

  Returns `(parity_concat of shards 4..7, padding_len, chunk_len)`.
-/
def encodeOutboardParity (input : ByteArray) : Except PipelineError (ByteArray × Nat × Nat) :=
  if input.size == 0 then
    .ok (ByteArray.empty, 0, 0)
  else
    match encodeInboard input with
    | .error e => .error (ofFecError e)
    | .ok (body, pad, chunk) =>
      -- body = 8 × chunk; parity = last 4 shards
      let parityStart := fecK * chunk
      if body.size != fecM * chunk then
        .error .unevenShards
      else
        .ok (body.extract parityStart body.size, pad, chunk)

/--
  Empty-archive policy for outboard FEC (matches Rust `fec_with_parity`).

  Both main and parity empty → empty logical payload, **padding ignored**.
  Shared by `decodeOutboardFec` and (via that helper) `decodeOutboardBody`.
-/
def emptyOutboardFecArchive : Except PipelineError ByteArray :=
  .ok ByteArray.empty

/--
  Decode with main + parity sidecars (matches Rust `decoding::fec_with_parity`).

  Stripe geometry comes from the parity sidecar (`shard_len = parity_len / (m-k)`),
  not from truncated main length. Data shards that are fully present in `main`
  (end ≤ min(main.size, logical_len)) are kept; any partial, missing, or
  padding-boundary data column is an **erasure** (`none`) so RS can reconstruct
  from intact parity. Zero-padding truncated main and treating all data shards
  as present would silently feed zeroed columns into RS and corrupt recovery.

  Empty main + empty parity: always empty (see `emptyOutboardFecArchive`); padding
  is not validated in that branch (Rust ignores it too).
-/
def decodeOutboardFec (main parity : ByteArray) (padding : Nat) :
    Except PipelineError ByteArray :=
  if main.size == 0 && parity.size == 0 then
    emptyOutboardFecArchive
  else if parity.size == 0 then
    .error .emptyShard
  else if parity.size % (fecM - fecK) != 0 then
    .error .unevenShards
  else
    let shardLen := parity.size / (fecM - fecK)
    if shardLen == 0 then
      .error .emptyShard
    else
      let paddedTotal := shardLen * fecK
      if padding > paddedTotal then
        .error .paddingTooLarge
      else
        let logicalLen := paddedTotal - padding
        -- Present prefix of logical body only (not zero-filled pad tail).
        let copyLen := min main.size logicalLen
        Id.run do
          let mut opts : Array (Option ByteArray) := Array.mkEmpty fecM
          for i in [:fecK] do
            let start := i * shardLen
            let stop := start + shardLen
            if stop ≤ copyLen then
              opts := opts.push (some (main.extract start stop))
            else
              -- Truncated / partial / padding-region data column — erasure.
              opts := opts.push none
          for j in [:fecM - fecK] do
            let start := j * shardLen
            opts := opts.push (some (parity.extract start (start + shardLen)))
          match reconstructLogical opts padding with
          | .error e => pure (.error (ofFecError e))
          | .ok data => pure (.ok data)

/--
  Outboard encode body.

  `headerPath = true`  → encrypted bare main is `[tag|ct]` (nonce out-of-band; matches
  `file::encode_outboard` / `stream_encode_outboard_buffer(..., Some(nonce))`).
  `headerPath = false` → encrypted bare main is `[nonce|tag|ct]` (matches low-level
  `encoding::encode_outboard`).

  `nonce` is required when `format.encrypted` (pure model has no CSPRNG).
-/
def encodeOutboardBody (master nonce plaintext : ByteArray) (format : FormatBits)
    (headerPath : Bool) : Except PipelineError OutboardEncoded :=
  let formatByte := format.toUInt8
  match compressStep plaintext format.compression with
  | .error e => .error e
  | .ok (afterComp, bytesCompressed) =>
    let encRes : Except PipelineError ByteArray :=
      if format.encrypted then
        encryptStep master nonce afterComp headerPath
      else
        .ok afterComp
    match encRes with
    | .error e => .error e
    | .ok bareMain =>
      let bytesEncrypted := if format.encrypted then bareMain.size else 0
      match
        (if format.fec then encodeOutboardParity bareMain
         else .ok (ByteArray.empty, 0, 0))
      with
      | .error e => .error e
      | .ok (fecParity, paddingLen, chunkLen) =>
        if format.verification then
          let (root, ob) := encodeOutboardForFormat formatByte bareMain
          .ok {
            main := bareMain
            verificationOutboard := ob
            fecParity := fecParity
            baoHash := root
            paddingLen := paddingLen
            chunkLen := chunkLen
            bytesCompressed := bytesCompressed
            bytesEncrypted := bytesEncrypted
          }
        else
          .ok {
            main := bareMain
            verificationOutboard := ByteArray.empty
            fecParity := fecParity
            baoHash := zeroHash
            paddingLen := paddingLen
            chunkLen := chunkLen
            bytesCompressed := bytesCompressed
            bytesEncrypted := bytesEncrypted
          }

/--
  Outboard decode: Bao verify → FEC reconstruct → decrypt → decompress.

  `headerPath` / `nonce` must match encode-time layout:
  * headerPath → decrypt with explicit `nonce` over `[tag|ct]`
  * !headerPath → embedded-nonce decrypt (nonce arg unused)

  `padding` must match encode-time padding (directory uses `calcPaddingLen main_len`).
-/
def decodeOutboardBody (master root main verOutboard fecParity : ByteArray)
    (padding : Nat) (format : FormatBits) (headerPath : Bool) (nonce : ByteArray) :
    Except PipelineError ByteArray :=
  let formatByte := format.toUInt8
  -- Bao verify first when verification bit set (empty post-order outboard is valid for single-leaf).
  let afterBao : Except PipelineError ByteArray :=
    if format.verification then
      match verifyOutboardForFormat formatByte root main verOutboard with
      | .error e => .error (ofBaoError e)
      | .ok () => .ok main
    else
      .ok main
  match afterBao with
  | .error e => .error e
  | .ok main' =>
    let afterFec : Except PipelineError ByteArray :=
      if format.fec then
        -- Single policy: empty+empty → empty; empty main + parity → reconstruct;
        -- truncated/partial data shards → erasures (see `decodeOutboardFec`).
        decodeOutboardFec main' fecParity padding
      else
        .ok main'
    match afterFec with
    | .error e => .error e
    | .ok afterF =>
      let decNonce := if headerPath then nonce else ByteArray.empty
      match decryptStep master decNonce afterF format.encrypted headerPath with
      | .error e => .error e
      | .ok afterDec =>
        decompressStep afterDec format.compression

/-- Round-trip outboard for a format (embedded-nonce layout; low-level parity). -/
def roundtripOutboard (master nonce plaintext : ByteArray) (format : FormatBits) :
    Except PipelineError Bool :=
  match encodeOutboardBody master nonce plaintext format false with
  | .error e => .error e
  | .ok enc =>
    match decodeOutboardBody master enc.baoHash enc.main enc.verificationOutboard
        enc.fecParity enc.paddingLen format false ByteArray.empty with
    | .error e => .error e
    | .ok pt => .ok (ctEq pt plaintext)

/-- Round-trip outboard with header-path encrypt (nonce out-of-band). -/
def roundtripOutboardHeaderPath (master nonce plaintext : ByteArray) (format : FormatBits) :
    Except PipelineError Bool :=
  match encodeOutboardBody master nonce plaintext format true with
  | .error e => .error e
  | .ok enc =>
    match decodeOutboardBody master enc.baoHash enc.main enc.verificationOutboard
        enc.fecParity enc.paddingLen format true nonce with
    | .error e => .error e
    | .ok pt => .ok (ctEq pt plaintext)

/-- Padding for directory segment decode: `calcPaddingLen(main_len)` when FEC. -/
def paddingForMainLen (mainLen : Nat) (fec : Bool) : Nat :=
  if !fec || mainLen == 0 then 0
  else (calcPaddingLen mainLen).paddingLen

end Carbonado.Outboard
