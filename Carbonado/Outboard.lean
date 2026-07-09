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
  Decode with main + parity sidecars (undamaged path: all data present in main).

  Pads main to stripe geometry, rebuilds k data + m-k parity shards, reconstructs,
  strips padding.
-/
def decodeOutboardFec (main parity : ByteArray) (padding : Nat) :
    Except PipelineError ByteArray :=
  if main.size == 0 && padding == 0 then
    if parity.size == 0 then .ok ByteArray.empty
    else .error .unevenShards
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
        -- Copy main into padded buffer (zeros after main).
        let padded :=
          if main.size ≥ paddedTotal then
            main.extract 0 paddedTotal
          else
            padWithZeros main paddedTotal
        Id.run do
          let mut opts : Array (Option ByteArray) := Array.mkEmpty fecM
          for i in [:fecK] do
            let start := i * shardLen
            opts := opts.push (some (padded.extract start (start + shardLen)))
          for j in [:fecM - fecK] do
            let start := j * shardLen
            opts := opts.push (some (parity.extract start (start + shardLen)))
          match reconstructLogical opts padding with
          | .error e => pure (.error (ofFecError e))
          | .ok data => pure (.ok data)

/--
  Outboard encode body (embedded-nonce encrypt when Encrypted).

  `nonce` is required when `format.encrypted` (pure model has no CSPRNG).
-/
def encodeOutboardBody (master nonce plaintext : ByteArray) (format : FormatBits) :
    Except PipelineError OutboardEncoded :=
  let formatByte := format.toUInt8
  match compressStep plaintext format.compression with
  | .error e => .error e
  | .ok (afterComp, _) =>
    let encRes : Except PipelineError ByteArray :=
      if format.encrypted then
        -- Embedded layout for bare mains (matches encoding::encode_outboard).
        encryptStep master nonce afterComp false
      else
        .ok afterComp
    match encRes with
    | .error e => .error e
    | .ok bareMain =>
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
          }
        else
          .ok {
            main := bareMain
            verificationOutboard := ByteArray.empty
            fecParity := fecParity
            baoHash := zeroHash
            paddingLen := paddingLen
            chunkLen := chunkLen
          }

/--
  Outboard decode: Bao verify → FEC reconstruct → decrypt embedded → decompress.

  `padding` must match encode-time padding (directory uses `calcPaddingLen main_len`).
-/
def decodeOutboardBody (master root main verOutboard fecParity : ByteArray)
    (padding : Nat) (format : FormatBits) : Except PipelineError ByteArray :=
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
        if main'.size == 0 then
          .ok ByteArray.empty
        else if fecParity.size == 0 then
          .error .emptyShard
        else
          decodeOutboardFec main' fecParity padding
      else
        .ok main'
    match afterFec with
    | .error e => .error e
    | .ok afterF =>
      -- Embedded-nonce decrypt when encrypted.
      match decryptStep master ByteArray.empty afterF format.encrypted false with
      | .error e => .error e
      | .ok afterDec =>
        decompressStep afterDec format.compression

/-- Round-trip outboard for a format. -/
def roundtripOutboard (master nonce plaintext : ByteArray) (format : FormatBits) :
    Except PipelineError Bool :=
  match encodeOutboardBody master nonce plaintext format with
  | .error e => .error e
  | .ok enc =>
    match decodeOutboardBody master enc.baoHash enc.main enc.verificationOutboard
        enc.fecParity enc.paddingLen format with
    | .error e => .error e
    | .ok pt => .ok (ctEq pt plaintext)

/-- Padding for directory segment decode: `calcPaddingLen(main_len)` when FEC. -/
def paddingForMainLen (mainLen : Nat) (fec : Bool) : Nat :=
  if !fec || mainLen == 0 then 0
  else (calcPaddingLen mainLen).paddingLen

end Carbonado.Outboard
