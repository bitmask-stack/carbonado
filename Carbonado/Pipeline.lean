/-
  Full Carbonado encode/decode pipeline (Programs E–F).

  Normative stage order (AGENTS.md):
    encode:  compress → encrypt → FEC → keyed Bao
    decode:  keyed Bao → FEC → decrypt → decompress

  Compression (Program F): zstd level 20 when the Compression bit is set
  (`Carbonado.Compress`; AOT links real zstd; interpreter uses identity fallback —
  see LIMITS). Format bit still affects keyed Bao roots (verification key domain).

  Nonce layouts:
  * `headerPathEncrypt = true`  → `[tag|ct]` (Header carries `payload_nonce`)
  * `headerPathEncrypt = false` → `[nonce|tag|ct]` (low-level / encoding::encode)

  **MAC-before-decrypt:** payload EtM is verified only after Bao/FEC reverse, and
  `decryptWithNonce` / `decryptEmbeddedNonce` still refuse keystream until MAC ok.
  **Header-MAC-before-body:** `decodeHeadered` verifies header before body decode.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Crypto.EtM
import Carbonado.Fec.RS
import Carbonado.Fec.Inboard
import Carbonado.Bao.Tree
import Carbonado.Bao.Product
import Carbonado.Header
import Carbonado.Compress

namespace Carbonado.Pipeline

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Crypto.EtM
open Carbonado.Fec.RS
open Carbonado.Fec.Inboard
open Carbonado.Bao.Tree
open Carbonado.Bao.Product
open Carbonado.Header
open Carbonado.Compress

/-- Strict pipeline error taxonomy (exact-match in tests; no lumped diagnostics). -/
inductive PipelineError where
  -- Header
  | invalidHeaderLength
  | badMagic
  | headerAuthenticationFailed
  | invalidFieldLength
  /-- Body shorter than authenticated `encoded_len` (Rust maps this to InvalidHeaderLength). -/
  | truncatedBody
  -- Crypto / EtM
  | invalidKeyLength
  | invalidCiphertextLength
  | invalidNonceLength
  | payloadAuthenticationFailed
  -- FEC
  | unevenShards
  | tooFewShards
  | emptyShard
  | incorrectShardSize
  | badGeometry
  | paddingTooLarge
  | singularMatrix
  -- Bao
  | baoAuthenticationFailed
  | truncatedResponse
  | trailingData
  | invalidPrefix
  | invalidRootLength
  | invalidSliceIndex
  | invalidSliceCount
  -- Compress (Program F)
  | compressionFailed
  | decompressionFailed
  | decompressOutputTooLarge
  /-- Invalid zstd input/params (encode or decode; not compress-only). -/
  | zstdInvalidInput
  -- Scrub / shard
  | scrubRequiresVerification
  | unnecessaryScrub
  | invalidScrubbedHash
  | invalidChunkSequence
  | emptySegment
  /-- Caller supplied fewer nonces than segments (distinct from per-nonce size ≠ 16). -/
  | insufficientNonces
  deriving DecidableEq, Repr

def ofHeaderError : HeaderError → PipelineError
  | .invalidHeaderLength => .invalidHeaderLength
  | .badMagic => .badMagic
  | .headerAuthenticationFailed => .headerAuthenticationFailed
  | .invalidKeyLength => .invalidKeyLength
  | .invalidFieldLength => .invalidFieldLength

def ofCryptoError : CryptoError → PipelineError
  | .invalidKeyLength => .invalidKeyLength
  | .invalidCiphertextLength => .invalidCiphertextLength
  | .invalidNonceLength => .invalidNonceLength
  | .authenticationFailed => .payloadAuthenticationFailed

def ofFecError : FecError → PipelineError
  | .unevenShards => .unevenShards
  | .tooFewShards => .tooFewShards
  | .emptyShard => .emptyShard
  | .incorrectShardSize => .incorrectShardSize
  | .badGeometry => .badGeometry
  | .paddingTooLarge => .paddingTooLarge
  | .singularMatrix => .singularMatrix

def ofBaoError : BaoError → PipelineError
  | .authenticationFailed => .baoAuthenticationFailed
  | .truncatedResponse => .truncatedResponse
  | .trailingData => .trailingData
  | .invalidPrefix => .invalidPrefix
  | .invalidRootLength => .invalidRootLength
  | .invalidSliceIndex => .invalidSliceIndex
  | .invalidSliceCount => .invalidSliceCount

/-- Map zstd errors without collapsing distinct modes. -/
def ofZstdError : ZstdError → PipelineError
  | .compressionFailed => .compressionFailed
  | .decompressionFailed => .decompressionFailed
  | .outputTooLarge => .decompressOutputTooLarge
  | .invalidInput => .zstdInvalidInput

/-- Encode bookkeeping (Rust `EncodeInfo`; factors omitted as pure-Nat model). -/
structure EncodeInfo where
  inputLen : Nat
  outputLen : Nat
  bytesCompressed : Nat
  bytesEncrypted : Nat
  bytesEcc : Nat
  bytesVerifiable : Nat
  paddingLen : Nat
  chunkLen : Nat
  verifiableSliceCount : Nat
  chunkSliceCount : Nat
  deriving DecidableEq, Repr

/-- Body encode result (inboard; no Header prepended). -/
structure Encoded where
  body : ByteArray
  /-- Keyed Bao root when verification bit set; else 32 zero bytes. -/
  baoHash : ByteArray
  info : EncodeInfo
  deriving DecidableEq

/-- Zero hash used when Verification bit is clear. -/
def zeroHash : ByteArray := replicate hashLen 0

/-- Zero SLH public key slot. -/
def zeroSlhPk : ByteArray := replicate slhPublicKeyLen 0

/-- Zero metadata. -/
def zeroMeta : ByteArray := replicate 8 0

/--
  Compress step: zstd-20 when bit set.

  **AOT product:** calls `compressLevel20` (real zstd via `@[extern]`).
  **native_decide / elaborator:** do not evaluate this on compression formats —
  CarbonadoTest format-matrix theorems use non-compression formats; AOT Main
  exercises c2/c6/c14/c15 with real zstd (LIMITS).
-/
def compressStep (plaintext : ByteArray) (compression : Bool) :
    Except PipelineError (ByteArray × Nat) :=
  if !compression then
    .ok (plaintext, 0)
  else
    match compressLevel20 plaintext with
    | .error e => .error (ofZstdError e)
    | .ok ct => .ok (ct, ct.size)

/-- Decompress step: zstd when bit set (same AOT / native_decide caveats). -/
def decompressStep (data : ByteArray) (compression : Bool) :
    Except PipelineError ByteArray :=
  if !compression then
    .ok data
  else
    match decompress data with
    | .error e => .error (ofZstdError e)
    | .ok pt => .ok pt

/-- Encrypt step (header-path or embedded). -/
def encryptStep (master nonce plaintext : ByteArray) (headerPath : Bool) :
    Except PipelineError ByteArray :=
  if headerPath then
    match encryptWithNonce master nonce plaintext with
    | .error e => .error (ofCryptoError e)
    | .ok blob => .ok blob
  else
    match encryptEmbeddedNonce master nonce plaintext with
    | .error e => .error (ofCryptoError e)
    | .ok blob => .ok blob

/-- Decrypt step after Bao/FEC reverse (MAC-before-decrypt inside EtM). -/
def decryptStep (master nonceOrEmpty ciphertext : ByteArray) (encrypted headerPath : Bool) :
    Except PipelineError ByteArray :=
  if !encrypted then
    .ok ciphertext
  else if headerPath then
    match decryptWithNonce master nonceOrEmpty ciphertext with
    | .ok pt => .ok pt
    | .error e => .error (ofCryptoError e)
  else
    match decryptEmbeddedNonce master ciphertext with
    | .ok pt => .ok pt
    | .error e => .error (ofCryptoError e)

/-- FEC encode step. -/
def fecEncodeStep (input : ByteArray) (fec : Bool) :
    Except PipelineError (ByteArray × Nat × Nat × Nat) :=
  if !fec then
    .ok (input, 0, 0, 0)
  else
    match Carbonado.Fec.Inboard.encodeInboard input with
    | .error e => .error (ofFecError e)
    | .ok (body, pad, chunk) =>
      .ok (body, pad, chunk, body.size)

/-- FEC decode step. -/
def fecDecodeStep (body : ByteArray) (padding : Nat) (fec : Bool) :
    Except PipelineError ByteArray :=
  if !fec then
    .ok body
  else
    match Carbonado.Fec.Inboard.decodeInboard body padding with
    | .error e => .error (ofFecError e)
    | .ok pt => .ok pt

/-- Bao inboard encode step (format byte keys the tree). -/
def baoEncodeStep (data : ByteArray) (formatByte : UInt8) (verification : Bool) :
    ByteArray × ByteArray × Nat :=
  if !verification then
    (data, zeroHash, data.size)
  else
    let (root, art) := encodeInboardForFormat formatByte data
    (art, root, art.size)

/-- Bao inboard decode/verify step. -/
def baoDecodeStep (body root : ByteArray) (formatByte : UInt8) (verification : Bool) :
    Except PipelineError ByteArray :=
  if !verification then
    .ok body
  else
    match decodeInboardForFormat formatByte root body with
    | .error e => .error (ofBaoError e)
    | .ok data => .ok data

/--
  Encode logical plaintext through the format pipeline (body only).

  Matches `encoding::encode` / `stream_encode_buffer` when `headerPathEncrypt = false`.
  Nonce is required when `format.encrypted` (caller-supplied; pure model has no CSPRNG).
-/
def encodeBody (master nonce plaintext : ByteArray) (format : FormatBits)
    (headerPathEncrypt : Bool) : Except PipelineError Encoded :=
  let formatByte := format.toUInt8
  let inputLen := plaintext.size
  match compressStep plaintext format.compression with
  | .error e => .error e
  | .ok (afterComp, bytesCompressed) =>
    let encRes : Except PipelineError ByteArray :=
      if format.encrypted then
        encryptStep master nonce afterComp headerPathEncrypt
      else
        .ok afterComp
    match encRes with
    | .error e => .error e
    | .ok encryptedBody =>
      let bytesEncrypted := if format.encrypted then encryptedBody.size else 0
      match fecEncodeStep encryptedBody format.fec with
      | .error e => .error e
      | .ok (afterFec, paddingLen, chunkLen, bytesEcc) =>
        let (verifiable, baoHash, bytesVerifiable) :=
          baoEncodeStep afterFec formatByte format.verification
        let verifiableSliceCount :=
          if format.fec then bytesEcc / sliceLen else 0
        let chunkSliceCount :=
          if format.fec then verifiableSliceCount / fecM else 0
        .ok {
          body := verifiable
          baoHash := baoHash
          info := {
            inputLen := inputLen
            outputLen := bytesVerifiable
            bytesCompressed := bytesCompressed
            bytesEncrypted := bytesEncrypted
            bytesEcc := bytesEcc
            bytesVerifiable := bytesVerifiable
            paddingLen := paddingLen
            chunkLen := chunkLen
            verifiableSliceCount := verifiableSliceCount
            chunkSliceCount := chunkSliceCount
          }
        }

/--
  Decode body (reverse pipeline).

  `padding` is the encode-time padding (from Header / EncodeInfo).
  `nonce` is used only for header-path encrypted decrypt; ignored for embedded layout.
-/
def decodeBody (master nonce hash body : ByteArray) (padding : Nat) (format : FormatBits)
    (headerPathEncrypt : Bool) : Except PipelineError ByteArray :=
  let formatByte := format.toUInt8
  match baoDecodeStep body hash formatByte format.verification with
  | .error e => .error e
  | .ok afterBao =>
    match fecDecodeStep afterBao padding format.fec with
    | .error e => .error e
    | .ok afterFec =>
      match decryptStep master nonce afterFec format.encrypted headerPathEncrypt with
      | .error e => .error e
      | .ok afterDec =>
        decompressStep afterDec format.compression

/-- Max value for u32 length fields (`UInt32.toNat (UInt32.ofNat n)` identity). -/
def u32Max : Nat := 4294967295

/-- Encode Nat length into UInt32 if in range; else `invalidFieldLength`. -/
def natToU32Field (n : Nat) : Except PipelineError UInt32 :=
  if n > u32Max then .error .invalidFieldLength
  else .ok (UInt32.ofNat n)

/-- Headered encode: body + authenticated 177-byte Header (header-path encrypt). -/
def encodeHeadered (master nonce plaintext : ByteArray) (format : FormatBits)
    (chunkIndex : UInt32) (slhPublicKey metadata : ByteArray) :
    Except PipelineError (Header × ByteArray) :=
  match encodeBody master nonce plaintext format true with
  | .error e => .error e
  | .ok enc =>
    match natToU32Field enc.info.outputLen, natToU32Field enc.info.paddingLen with
    | .error e, _ => .error e
    | _, .error e => .error e
    | .ok encLenU32, .ok padU32 =>
      match Header.new master nonce enc.baoHash slhPublicKey format.toUInt8
          chunkIndex encLenU32 padU32 metadata with
      | .error e => .error (ofHeaderError e)
      | .ok hdr =>
        match hdr.toBytes with
        | .error e => .error (ofHeaderError e)
        | .ok hdrBytes =>
          .ok (hdr, appendBA hdrBytes enc.body)

/--
  Headered decode: **header MAC verified first**, then body with `payload_nonce`.

  Enforces authenticated `encoded_len` (Rust `file::decode`): body must be ≥
  `encoded_len`; only the first `encoded_len` bytes enter the pipeline (trailers
  ignored). Short body → `truncatedBody`.
-/
def decodeHeadered (master archive : ByteArray) : Except PipelineError ByteArray :=
  if archive.size < headerLen then
    .error .invalidHeaderLength
  else
    let hdrBytes := archive.extract 0 headerLen
    let bodyAll := archive.extract headerLen archive.size
    match parseAndVerify master hdrBytes with
    | .error e => .error (ofHeaderError e)
    | .ok hdr =>
      let need := UInt32.toNat hdr.encodedLen
      if bodyAll.size < need then
        .error .truncatedBody
      else
        let body := bodyAll.extract 0 need
        let format := FormatBits.ofUInt8 hdr.format
        let padding := UInt32.toNat hdr.paddingLen
        decodeBody master hdr.payloadNonce hdr.hash body padding format true

/--
  Headered decode returning the verified Header (for sharding: authenticated
  `chunk_index` rebinding). Same `encoded_len` bound as `decodeHeadered`.
-/
def decodeHeaderedWithHeader (master archive : ByteArray) :
    Except PipelineError (Header × ByteArray) :=
  if archive.size < headerLen then
    .error .invalidHeaderLength
  else
    let hdrBytes := archive.extract 0 headerLen
    let bodyAll := archive.extract headerLen archive.size
    match parseAndVerify master hdrBytes with
    | .error e => .error (ofHeaderError e)
    | .ok hdr =>
      let need := UInt32.toNat hdr.encodedLen
      if bodyAll.size < need then
        .error .truncatedBody
      else
        let body := bodyAll.extract 0 need
        let format := FormatBits.ofUInt8 hdr.format
        let padding := UInt32.toNat hdr.paddingLen
        match decodeBody master hdr.payloadNonce hdr.hash body padding format true with
        | .error e => .error e
        | .ok pt => .ok (hdr, pt)

/-- Round-trip helper for format matrix (body, embedded nonce when encrypted). -/
def roundtripBody (master nonce plaintext : ByteArray) (format : FormatBits) :
    Except PipelineError Bool :=
  match encodeBody master nonce plaintext format false with
  | .error e => .error e
  | .ok enc =>
    match decodeBody master nonce enc.baoHash enc.body enc.info.paddingLen format false with
    | .error e => .error e
    | .ok pt => .ok (ctEq pt plaintext)

/-- Round-trip headered archive. -/
def roundtripHeadered (master nonce plaintext : ByteArray) (format : FormatBits) :
    Except PipelineError Bool :=
  match encodeHeadered master nonce plaintext format 0 zeroSlhPk zeroMeta with
  | .error e => .error e
  | .ok (_hdr, archive) =>
    match decodeHeadered master archive with
    | .error e => .error e
    | .ok pt => .ok (ctEq pt plaintext)

/-- All 16 format codes as FormatBits. -/
def allFormats : List FormatBits :=
  (List.range 16).map (fun n => FormatBits.ofUInt8 (UInt8.ofNat n))

/--
  Roundtrip every format (zstd when Compression bit set; encrypted uses given nonce).

  Propagates the first `PipelineError` (does not swallow errors into `.ok false`).
  Returns `.ok false` only when a roundtrip succeeds but plaintext mismatches.
-/
def formatMatrixRoundtrip (master nonce plaintext : ByteArray) : Except PipelineError Bool :=
  Id.run do
    let mut err : Option PipelineError := none
    let mut allMatch := true
    for fmt in allFormats do
      if err.isNone then
        match roundtripBody master nonce plaintext fmt with
        | .error e => err := some e
        | .ok b => if !b then allMatch := false
    match err with
    | some e => pure (.error e)
    | none => pure (.ok allMatch)

/-- Unencrypted formats are even (restate Constants invariant for pipeline). -/
theorem encrypted_bit_is_odd (f : FormatBits) :
    f.encrypted = true → f.toUInt8 % 2 = 1 := by
  intro h
  cases f with
  | mk e c v z =>
    simp [FormatBits.toUInt8, formatBitEncrypted, formatBitCompression,
      formatBitVerification, formatBitFec] at h ⊢
    subst h
    cases c <;> cases v <;> cases z <;> native_decide

end Carbonado.Pipeline
