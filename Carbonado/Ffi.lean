/-
  C ABI surface for dual-backend parity (docs/ABI.md).

  Pure helpers map Pipeline results to ABI error codes. `@[export]` entry points
  return packed ByteArrays for the C glue in `nix/native/carbonado_abi.c`:

    status-prefixed:  [u32 LE status][payload…]
    encode body:      [u32 LE status][u32 LE padding][u32 LE chunk_len]
                      [u32 LE bytes_ecc][u32 LE verifiable_slice_count]
                      [u32 LE bytes_compressed][u32 LE bytes_encrypted]
                      [32-byte hash][body…]
                      (success prefix 60 bytes; error = [status:4] only)
    encode headered:  [u32 LE status][u32 LE padding][u32 LE chunk_len]
                      [u32 LE bytes_ecc][u32 LE verifiable_slice_count]
                      [u32 LE bytes_compressed][u32 LE bytes_encrypted]
                      [archive…]
                      (success prefix 28 bytes; error = [status:4] only)
    encode outboard:  [u32 LE status][u32 LE padding][u32 LE chunk_len]
                      [u32 LE bytes_compressed][u32 LE bytes_encrypted]
                      [32 hash][u32 main_len][main][u32 ob_len][ob]
                      [u32 par_len][par]
                      (fixed prefix before segments: 52 bytes)

  C wrappers initialize the Lean runtime, convert buffers ↔ ByteArray, and expose
  the stable `carbonado_*` symbols in `include/carbonado.h`.

  Phase 2 adds outboard / scrub / slice exports (additive on ABI version 1).
  R3 adds compress/encrypt stage counters on encode packs (ABI version stays 1).
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Bao.Product
import Carbonado.Header
import Carbonado.Pipeline
import Carbonado.Outboard
import Carbonado.Scrub

namespace Carbonado.Ffi

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Bao.Product
open Carbonado.Header
open Carbonado.Pipeline
open Carbonado.Outboard
open Carbonado.Scrub

/-- ABI version (must match `include/carbonado.h` / docs/ABI.md). -/
def abiVersion : UInt32 := 1

/-- Stable C error codes (docs/ABI.md). -/
def ok : UInt32 := 0
def errInvalidArgument : UInt32 := 1
def errInvalidKeyLength : UInt32 := 2
def errAuthentication : UInt32 := 3
def errInvalidMagic : UInt32 := 4
def errInvalidHeader : UInt32 := 5
def errFec : UInt32 := 6
def errBao : UInt32 := 7
def errZstd : UInt32 := 8
def errScrubUnnecessary : UInt32 := 9
def errScrubFailed : UInt32 := 10
def errNotImplemented : UInt32 := 11
def errInternal : UInt32 := 12
/-- Distinct from scrub recovery failure (docs/ABI.md Phase 2). -/
def errScrubRequiresVerification : UInt32 := 13

/-- Collapse `PipelineError` into ABI codes (exhaustive; docs/ABI.md).

  R4 fidelity: Bao auth / short inboard prefix must not collapse into a single
  `errBao` diagnostic — dual-suite `matches!` expects `AuthenticationFailed` and
  `InvalidHeaderLength` respectively (same as pure Rust). `invalidSliceIndex`
  stays `errBao` at the C boundary; Rust `lean::verify_slice` applies geometry
  pre-checks to surface `InvalidSliceIndex { index, content_len }`.
-/
def ofPipelineError : PipelineError → UInt32
  | .invalidKeyLength => errInvalidKeyLength
  | .payloadAuthenticationFailed | .headerAuthenticationFailed
  | .baoAuthenticationFailed => errAuthentication
  | .badMagic => errInvalidMagic
  | .invalidHeaderLength | .truncatedBody | .invalidFieldLength
  | .invalidPrefix => errInvalidHeader
  | .unevenShards | .tooFewShards | .emptyShard | .incorrectShardSize
  | .badGeometry | .paddingTooLarge | .singularMatrix => errFec
  | .truncatedResponse | .trailingData
  | .invalidRootLength | .invalidSliceIndex | .invalidSliceCount => errBao
  | .compressionFailed | .decompressionFailed | .decompressOutputTooLarge
  | .zstdInvalidInput => errZstd
  | .unnecessaryScrub => errScrubUnnecessary
  | .invalidScrubbedHash => errScrubFailed
  | .scrubRequiresVerification => errScrubRequiresVerification
  | .invalidCiphertextLength | .invalidNonceLength | .insufficientNonces => errInvalidArgument
  | .invalidChunkSequence | .emptySegment => errInvalidArgument

def masterOk (master : ByteArray) : Bool :=
  master.size == 32 || master.size == 64

/-- Append u32 little-endian. -/
def pushU32LE (out : ByteArray) (x : UInt32) : ByteArray :=
  out.push (UInt8.ofNat (UInt32.toNat x % 256))
    |>.push (UInt8.ofNat (UInt32.toNat (x >>> 8) % 256))
    |>.push (UInt8.ofNat (UInt32.toNat (x >>> 16) % 256))
    |>.push (UInt8.ofNat (UInt32.toNat (x >>> 24) % 256))

/-- Pack `[u32 LE status][payload]`. -/
def packStatus (code : UInt32) (payload : ByteArray) : ByteArray :=
  appendBA (pushU32LE ByteArray.empty code) payload

/-- Pack encode body error: `[u32 LE status]` only (C parses status-first; see carbonado_abi.c). -/
def packEncodeErr (code : UInt32) : ByteArray :=
  pushU32LE ByteArray.empty code

/-- Encode metadata fields returned with body/headered/outboard success packs. -/
structure EncodeMeta where
  padding : UInt32
  chunkLen : UInt32
  bytesEcc : UInt32
  verifiableSliceCount : UInt32
  bytesCompressed : UInt32
  bytesEncrypted : UInt32
  deriving DecidableEq

/-- Convert pipeline `EncodeInfo` length fields to u32 `EncodeMeta` (fail-closed on overflow). -/
def encodeMetaOf (info : EncodeInfo) : Except UInt32 EncodeMeta :=
  match natToU32Field info.paddingLen with
  | .error e => .error (ofPipelineError e)
  | .ok pad =>
    match natToU32Field info.chunkLen with
    | .error e => .error (ofPipelineError e)
    | .ok cl =>
      match natToU32Field info.bytesEcc with
      | .error e => .error (ofPipelineError e)
      | .ok be =>
        match natToU32Field info.verifiableSliceCount with
        | .error e => .error (ofPipelineError e)
        | .ok vsc =>
          match natToU32Field info.bytesCompressed with
          | .error e => .error (ofPipelineError e)
          | .ok bc =>
            match natToU32Field info.bytesEncrypted with
            | .error e => .error (ofPipelineError e)
            | .ok be2 =>
              .ok {
                padding := pad
                chunkLen := cl
                bytesEcc := be
                verifiableSliceCount := vsc
                bytesCompressed := bc
                bytesEncrypted := be2
              }

/-- Pack six u32 EncodeMeta fields after status (24 bytes). -/
def pushEncodeMeta (out : ByteArray) (em : EncodeMeta) : ByteArray :=
  pushU32LE
    (pushU32LE
      (pushU32LE
        (pushU32LE
          (pushU32LE
            (pushU32LE out em.padding)
            em.chunkLen)
          em.bytesEcc)
        em.verifiableSliceCount)
      em.bytesCompressed)
    em.bytesEncrypted

/-- Pack encode body success:
  `[u32 LE status=0][padding:4][chunk_len:4][bytes_ecc:4][vsc:4]
   [bytes_compressed:4][bytes_encrypted:4][32 hash][body]`.

  Requires `hash.size = 32`; otherwise packs `errInternal` (defensive layout guard).
  Header size after status: 24 + 32 = 56; total prefix 60 bytes.
-/
def packEncodeOk (em : EncodeMeta) (hash body : ByteArray) : ByteArray :=
  if hash.size != 32 then
    packEncodeErr errInternal
  else
    let hdr := pushEncodeMeta (pushU32LE ByteArray.empty ok) em
    appendBA (appendBA hdr hash) body

/-- Pack headered encode success:
  `[status:4][pad:4][chunk:4][ecc:4][vsc:4][comp:4][enc:4][archive…]`.

  Total meta prefix 28 bytes (status + EncodeMeta).
-/
def packHeaderedOk (em : EncodeMeta) (archive : ByteArray) : ByteArray :=
  appendBA (pushEncodeMeta (pushU32LE ByteArray.empty ok) em) archive

/-- Pack length-prefixed segment: `[u32 LE len][bytes]`, or `none` if len overflows u32. -/
def packLenPrefixed? (payload : ByteArray) : Option ByteArray :=
  match natToU32Field payload.size with
  | .error _ => none
  | .ok n => some (appendBA (pushU32LE ByteArray.empty n) payload)

/-- Pack outboard encode success:
  `[status:4][padding:4][chunk_len:4][bytes_compressed:4][bytes_encrypted:4][hash:32]
   [u32 main_len][main][u32 ob_len][ob][u32 par_len][par]`.

  Fixed prefix before segments: 52 bytes. Oversized segments → `errInternal`.
-/
def packOutboardOk (padding chunkLen bytesCompressed bytesEncrypted : UInt32)
    (hash main ob par : ByteArray) : ByteArray :=
  if hash.size != 32 then
    packEncodeErr errInternal
  else
    match packLenPrefixed? main with
    | none => packEncodeErr errInternal
    | some m =>
      match packLenPrefixed? ob with
      | none => packEncodeErr errInternal
      | some o =>
        match packLenPrefixed? par with
        | none => packEncodeErr errInternal
        | some p =>
          let hdr :=
            pushU32LE
              (pushU32LE
                (pushU32LE
                  (pushU32LE (pushU32LE ByteArray.empty ok) padding)
                  chunkLen)
                bytesCompressed)
              bytesEncrypted
          let withHash := appendBA hdr hash
          appendBA (appendBA (appendBA withHash m) o) p

/-- Pure headered encode for FFI (explicit nonce; optional SLH pk + 8-byte metadata).

  Header always carries a 16-byte `payload_nonce` (Rust `file::encode`). Encrypted
  formats require a caller-supplied 16-byte nonce; public formats use zeros when
  nonce is empty/absent.

  `slhPublicKey` must be empty or 32 bytes (empty → zeros). `metadata` must be empty
  or 8 bytes (empty → zeros). Wrong lengths → `errInvalidArgument`.

  Returns full archive + stage-counter `EncodeMeta` (R3).
-/
def encodeHeaderedBytes (master nonce plaintext slhPublicKey metadataBytes : ByteArray)
    (format : UInt8) : Except UInt32 (ByteArray × EncodeMeta) :=
  if !masterOk master then .error errInvalidKeyLength
  else if !(slhPublicKey.size == 0 || slhPublicKey.size == 32) then
    .error errInvalidArgument
  else if !(metadataBytes.size == 0 || metadataBytes.size == 8) then
    .error errInvalidArgument
  else
    let fmt := FormatBits.ofUInt8 format
    let n :=
      if fmt.encrypted then nonce
      else if nonce.size == nonceLen then nonce
      else replicate nonceLen 0
    let slh := if slhPublicKey.size == 32 then slhPublicKey else replicate 32 0
    let metaBytes := if metadataBytes.size == 8 then metadataBytes else replicate 8 0
    if n.size != nonceLen then
      .error errInvalidArgument
    else
      match encodeHeadered master n plaintext fmt 0 slh metaBytes with
      | .error e => .error (ofPipelineError e)
      | .ok (_hdr, archive, info) =>
        match encodeMetaOf info with
        | .error e => .error e
        | .ok em => .ok (archive, em)

/-- Pure headered decode for FFI. -/
def decodeHeaderedBytes (master archive : ByteArray) : Except UInt32 ByteArray :=
  if !masterOk master then .error errInvalidKeyLength
  else
    match decodeHeadered master archive with
    | .error e => .error (ofPipelineError e)
    | .ok pt => .ok pt

/-- Low-level body encode (embedded-nonce encrypt path; `headerPathEncrypt = false`). -/
def encodeBodyBytes (master nonce plaintext : ByteArray) (format : UInt8) :
    Except UInt32 (ByteArray × ByteArray × EncodeMeta) :=
  if !masterOk master then .error errInvalidKeyLength
  else
    let fmt := FormatBits.ofUInt8 format
    if fmt.encrypted && nonce.size != nonceLen then
      .error errInvalidArgument
    else
      let n := if fmt.encrypted then nonce else ByteArray.empty
      match encodeBody master n plaintext fmt false with
      | .error e => .error (ofPipelineError e)
      | .ok enc =>
        match encodeMetaOf enc.info with
        | .error e => .error e
        | .ok em => .ok (enc.body, enc.baoHash, em)

/-- Low-level body decode. -/
def decodeBodyBytes (master hash body : ByteArray) (padding : UInt32) (format : UInt8) :
    Except UInt32 ByteArray :=
  if !masterOk master then .error errInvalidKeyLength
  else if hash.size != 32 then .error errInvalidArgument
  else
    let fmt := FormatBits.ofUInt8 format
    -- Nonce unused for public / embedded-nonce decrypt (passed empty).
    match decodeBody master ByteArray.empty hash body padding.toNat fmt false with
    | .error e => .error (ofPipelineError e)
    | .ok pt => .ok pt

/-- Outboard encode.

  `headerPath ≠ 0` → encrypted bare main is `[tag|ct]` (nonce out-of-band).
  `headerPath = 0` → encrypted bare main is `[nonce|tag|ct]` (embedded).

  Returns main/ob/par/hash + pad/chunk + compress/encrypt stage counters (R3).
-/
def encodeOutboardBytes (master nonce plaintext : ByteArray) (format headerPath : UInt8) :
    Except UInt32
      (ByteArray × ByteArray × ByteArray × ByteArray × UInt32 × UInt32 × UInt32 × UInt32) :=
  if !masterOk master then .error errInvalidKeyLength
  else
    let fmt := FormatBits.ofUInt8 format
    if fmt.encrypted && nonce.size != nonceLen then
      .error errInvalidArgument
    else
      let n := if fmt.encrypted then nonce else ByteArray.empty
      let hp := headerPath != 0
      match encodeOutboardBody master n plaintext fmt hp with
      | .error e => .error (ofPipelineError e)
      | .ok enc =>
        match natToU32Field enc.paddingLen with
        | .error e => .error (ofPipelineError e)
        | .ok pad =>
          match natToU32Field enc.chunkLen with
          | .error e => .error (ofPipelineError e)
          | .ok cl =>
            match natToU32Field enc.bytesCompressed with
            | .error e => .error (ofPipelineError e)
            | .ok bc =>
              match natToU32Field enc.bytesEncrypted with
              | .error e => .error (ofPipelineError e)
              | .ok be =>
                .ok (enc.main, enc.verificationOutboard, enc.fecParity, enc.baoHash,
                  pad, cl, bc, be)

/-- Outboard decode. `headerPath`/`nonce` must match encode-time layout. -/
def decodeOutboardBytes (master hash main verOutboard fecParity : ByteArray)
    (padding : UInt32) (format headerPath : UInt8) (nonce : ByteArray) :
    Except UInt32 ByteArray :=
  if !masterOk master then .error errInvalidKeyLength
  else if hash.size != 32 then .error errInvalidArgument
  else
    let fmt := FormatBits.ofUInt8 format
    let hp := headerPath != 0
    if hp && fmt.encrypted && nonce.size != nonceLen then
      .error errInvalidArgument
    else
      let n := if hp && fmt.encrypted then nonce else ByteArray.empty
      match decodeOutboardBody master hash main verOutboard fecParity padding.toNat fmt hp n with
      | .error e => .error (ofPipelineError e)
      | .ok pt => .ok pt

/-- Inboard scrub (returns recovered body bytes). -/
def scrubBytes (body hash : ByteArray) (padding : UInt32) (format : UInt8) :
    Except UInt32 ByteArray :=
  if hash.size != 32 then .error errInvalidArgument
  else
    let fmt := FormatBits.ofUInt8 format
    match scrubInboard body hash padding.toNat fmt with
    | .error e => .error (ofPipelineError e)
    | .ok recovered => .ok recovered

/-- Outboard scrub (returns recovered bare main). -/
def scrubOutboardBytes (main verOutboard fecParity hash : ByteArray)
    (padding chunkLen : UInt32) (format : UInt8) : Except UInt32 ByteArray :=
  if hash.size != 32 then .error errInvalidArgument
  else
    let fmt := FormatBits.ofUInt8 format
    match scrubOutboard main verOutboard fecParity hash padding.toNat chunkLen.toNat fmt with
    | .error e => .error (ofPipelineError e)
    | .ok bare => .ok bare

/-- Inboard verify_slice / extract_slice (W4a: auth-first O(slice) retain; full body at C).

  Product path walks the full inboard artifact from offset 8 (no second response copy;
  O(N) time) but retains only the requested slice bytes (O(slice) output). C ABI still
  takes the full inboard body buffer as input. `count == 0` still authenticates first
  (Lean C auth-first contract), unlike the Rust lean wrapper which short-circuits empty
  success before C (parity with pure-Rust `verify_slice_inboard_seekable`).
-/
def verifySliceBytes (body hash : ByteArray) (index count : UInt32) (format : UInt8) :
    Except UInt32 ByteArray :=
  if hash.size != 32 then .error errInvalidArgument
  else if count.toNat == 0 then
    match verifySliceInboardForFormat format hash body 0 0 with
    | .error e => .error (ofPipelineError (ofBaoError e))
    | .ok data => .ok data
  else
    match verifySliceInboardForFormat format hash body index.toNat count.toNat with
    | .error e => .error (ofPipelineError (ofBaoError e))
    | .ok data => .ok data

/-- Seekable outboard verify_slice (O(slice + height) hash; full buffers at C ABI — W4b permanent). -/
def verifySliceOutboardBytes (main outboard hash : ByteArray)
    (index count : UInt32) (format : UInt8) : Except UInt32 ByteArray :=
  if hash.size != 32 then .error errInvalidArgument
  else
    match verifySliceOutboardForFormat format hash main outboard index.toNat count.toNat with
    | .error e => .error (ofPipelineError (ofBaoError e))
    | .ok data => .ok data

/-- Format verification key (32 bytes). -/
def verificationKeyBytes (format : UInt8) : ByteArray :=
  carbonadoVerificationKey format

/-- Round-trip self-check (public or encrypted with given nonce). -/
def roundtripHeaderedOk (master nonce plaintext : ByteArray) (format : UInt8) : Bool :=
  match encodeHeaderedBytes master nonce plaintext ByteArray.empty ByteArray.empty format with
  | .error _ => false
  | .ok (arch, _em) =>
    match decodeHeaderedBytes master arch with
    | .error _ => false
    | .ok pt => ctEq pt plaintext

---------------------------------------------------------------------------
-- @[export] surface for C glue (namespaced `l_` to avoid clashing with C ABI)
---------------------------------------------------------------------------

/-- Packed: always 32-byte key (status implied OK). -/
@[export l_carbonado_verification_key]
def l_carbonado_verification_key (format : UInt8) : ByteArray :=
  verificationKeyBytes format

/-- Packed success: EncodeMeta + archive; error: `[status:4]` only.
  Optional `slhPublicKey` (0 or 32 B) and `metadataBytes` (0 or 8 B). -/
@[export l_carbonado_encode_headered]
def l_carbonado_encode_headered (master nonce plaintext slhPublicKey metadataBytes : ByteArray)
    (format : UInt8) : ByteArray :=
  match encodeHeaderedBytes master nonce plaintext slhPublicKey metadataBytes format with
  | .error e => packEncodeErr e
  | .ok (arch, em) => packHeaderedOk em arch

/-- Packed: `[status:4][plaintext…]`. -/
@[export l_carbonado_decode_headered]
def l_carbonado_decode_headered (master archive : ByteArray) : ByteArray :=
  match decodeHeaderedBytes master archive with
  | .error e => packStatus e ByteArray.empty
  | .ok pt => packStatus ok pt

/-- Packed success: encode meta + hash + body; error: `[status:4]` only. -/
@[export l_carbonado_encode]
def l_carbonado_encode (master nonce plaintext : ByteArray) (format : UInt8) : ByteArray :=
  match encodeBodyBytes master nonce plaintext format with
  | .error e => packEncodeErr e
  | .ok (body, hash, em) =>
    if hash.size != 32 then packEncodeErr errInternal
    else packEncodeOk em hash body

/-- Packed: `[status:4][plaintext…]`. -/
@[export l_carbonado_decode]
def l_carbonado_decode (master hash body : ByteArray) (padding : UInt32) (format : UInt8) : ByteArray :=
  match decodeBodyBytes master hash body padding format with
  | .error e => packStatus e ByteArray.empty
  | .ok pt => packStatus ok pt

/-- Packed outboard encode success layout; error `[status:4]`.

  `headerPath ≠ 0` → header-path `[tag|ct]` encrypt; `0` → embedded-nonce.
-/
@[export l_carbonado_encode_outboard]
def l_carbonado_encode_outboard (master nonce plaintext : ByteArray)
    (format headerPath : UInt8) : ByteArray :=
  match encodeOutboardBytes master nonce plaintext format headerPath with
  | .error e => packEncodeErr e
  | .ok (main, ob, par, hash, pad, cl, bc, be) =>
    packOutboardOk pad cl bc be hash main ob par

/-- Packed: `[status:4][plaintext…]`.

  `headerPath ≠ 0` requires 16-byte `nonce` for encrypted formats.
-/
@[export l_carbonado_decode_outboard]
def l_carbonado_decode_outboard (master hash main verOutboard fecParity : ByteArray)
    (padding : UInt32) (format headerPath : UInt8) (nonce : ByteArray) : ByteArray :=
  match decodeOutboardBytes master hash main verOutboard fecParity padding format headerPath nonce with
  | .error e => packStatus e ByteArray.empty
  | .ok pt => packStatus ok pt

/-- Packed: `[status:4][recovered…]`. -/
@[export l_carbonado_scrub]
def l_carbonado_scrub (body hash : ByteArray) (padding : UInt32) (format : UInt8) : ByteArray :=
  match scrubBytes body hash padding format with
  | .error e => packStatus e ByteArray.empty
  | .ok rec => packStatus ok rec

/-- Packed: `[status:4][recovered bare…]`. -/
@[export l_carbonado_scrub_outboard]
def l_carbonado_scrub_outboard (main verOutboard fecParity hash : ByteArray)
    (padding chunkLen : UInt32) (format : UInt8) : ByteArray :=
  match scrubOutboardBytes main verOutboard fecParity hash padding chunkLen format with
  | .error e => packStatus e ByteArray.empty
  | .ok bare => packStatus ok bare

/-- Packed: `[status:4][slice bytes…]`. -/
@[export l_carbonado_verify_slice]
def l_carbonado_verify_slice (body hash : ByteArray) (index count : UInt32) (format : UInt8) :
    ByteArray :=
  match verifySliceBytes body hash index count format with
  | .error e => packStatus e ByteArray.empty
  | .ok data => packStatus ok data

/-- Packed: `[status:4][slice bytes…]` from bare main + post-order outboard. -/
@[export l_carbonado_verify_slice_outboard]
def l_carbonado_verify_slice_outboard (main outboard hash : ByteArray)
    (index count : UInt32) (format : UInt8) : ByteArray :=
  match verifySliceOutboardBytes main outboard hash index count format with
  | .error e => packStatus e ByteArray.empty
  | .ok data => packStatus ok data

theorem abiVersion_eq : abiVersion = 1 := by native_decide

theorem masterOk_32 : masterOk (replicate 32 0) = true := by native_decide

theorem masterOk_31 : masterOk (replicate 31 0) = false := by native_decide

end Carbonado.Ffi
