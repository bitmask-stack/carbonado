/-
  C ABI surface for dual-backend parity (docs/ABI.md).

  Pure helpers map Pipeline results to ABI error codes. `@[export]` entry points
  are thin wrappers for the Lean AOT static library (`libcarbonado`).
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Bao.Product
import Carbonado.Header
import Carbonado.Pipeline

namespace Carbonado.Ffi

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Bao.Product
open Carbonado.Header
open Carbonado.Pipeline

/-- ABI version (must match `include/carbonado.h` / docs/ABI.md). -/
def abiVersion : UInt32 := 1

@[export carbonado_abi_version]
def carbonado_abi_version : UInt32 := abiVersion

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

/-- Collapse `PipelineError` into ABI codes (exhaustive; docs/ABI.md). -/
def ofPipelineError : PipelineError → UInt32
  | .invalidKeyLength => errInvalidKeyLength
  | .payloadAuthenticationFailed | .headerAuthenticationFailed => errAuthentication
  | .badMagic => errInvalidMagic
  | .invalidHeaderLength | .truncatedBody | .invalidFieldLength => errInvalidHeader
  | .unevenShards | .tooFewShards | .emptyShard | .incorrectShardSize
  | .badGeometry | .paddingTooLarge | .singularMatrix => errFec
  | .baoAuthenticationFailed | .truncatedResponse | .trailingData
  | .invalidPrefix | .invalidRootLength | .invalidSliceIndex | .invalidSliceCount => errBao
  | .compressionFailed | .decompressionFailed | .decompressOutputTooLarge
  | .zstdInvalidInput => errZstd
  | .unnecessaryScrub => errScrubUnnecessary
  | .scrubRequiresVerification | .invalidScrubbedHash => errScrubFailed
  | .invalidCiphertextLength | .invalidNonceLength | .insufficientNonces => errInvalidArgument
  | .invalidChunkSequence | .emptySegment => errInvalidArgument

def masterOk (master : ByteArray) : Bool :=
  master.size == 32 || master.size == 64

/-- Pure headered encode for FFI (explicit nonce; zero SLH/meta). -/
def encodeHeaderedBytes (master nonce plaintext : ByteArray) (format : UInt8) :
    Except UInt32 ByteArray :=
  if !masterOk master then .error errInvalidKeyLength
  else if (FormatBits.ofUInt8 format).encrypted && nonce.size != nonceLen then
    .error errInvalidArgument
  else
    let fmt := FormatBits.ofUInt8 format
    let n := if fmt.encrypted then nonce else ByteArray.mkEmpty 0
    match encodeHeadered master n plaintext fmt 0 (ByteArray.mkEmpty 32) (ByteArray.mkEmpty 8) with
    | .error e => .error (ofPipelineError e)
    | .ok (_hdr, archive) => .ok archive

/-- Pure headered decode for FFI. -/
def decodeHeaderedBytes (master archive : ByteArray) : Except UInt32 ByteArray :=
  if !masterOk master then .error errInvalidKeyLength
  else
    match decodeHeadered master archive with
    | .error e => .error (ofPipelineError e)
    | .ok pt => .ok pt

/-- Format verification key (32 bytes). -/
def verificationKeyBytes (format : UInt8) : ByteArray :=
  carbonadoVerificationKey format

/-- Round-trip self-check (public or encrypted with given nonce). -/
def roundtripHeaderedOk (master nonce plaintext : ByteArray) (format : UInt8) : Bool :=
  match encodeHeaderedBytes master nonce plaintext format with
  | .error _ => false
  | .ok arch =>
    match decodeHeaderedBytes master arch with
    | .error _ => false
    | .ok pt => ctEq pt plaintext

theorem abiVersion_eq : abiVersion = 1 := by native_decide

theorem masterOk_32 : masterOk (ByteArray.mkArray 32 0) = true := by native_decide

theorem masterOk_31 : masterOk (ByteArray.mkArray 31 0) = false := by native_decide

end Carbonado.Ffi
