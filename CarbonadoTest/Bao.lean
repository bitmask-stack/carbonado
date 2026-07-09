/-
  Program D — keyed Bao tests: BLAKE3, verification keys, roots, inboard/outboard,
  stream slice decode, strict error paths (every BaoError variant exact-matched).

  Dependency direction: CarbonadoTest → Carbonado only.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Bao
import CarbonadoTest.Scaffold

namespace CarbonadoTest.Bao

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Bao.Blake3
open Carbonado.Bao.Tree
open Carbonado.Bao.Product

/-! ## Geometry -/

theorem leaf_eq_slice : leafBytes = sliceLen := leafBytes_eq_sliceLen

theorem slice_len_4096 : sliceLen = 4096 := by native_decide

theorem bao_chunk_log_2 : baoChunkLog = 2 := by native_decide

/-! ## BLAKE3 goldens -/

theorem blake3_empty :
    toHex (hash ByteArray.empty) =
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" :=
  hash_empty

theorem blake3_abc :
    toHex (hash (utf8 "abc")) =
      "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85" :=
  hash_abc

/-! ## Verification keys (format domain) -/

theorem vkey_c4 :
    toHex (carbonadoVerificationKey 4) =
      "6f1b6d31098f44f98e31231fe4244d532d1263556a45fe370d74cae1a447ffbf" := by
  native_decide

theorem vkey_c6 :
    toHex (carbonadoVerificationKey 6) =
      "3923848b90f499febc394b34cbac1f3c2d9a98a89b93beb4bb6361d1db5d4615" := by
  native_decide

theorem vkey_domain :
    toHex (carbonadoVerificationKey 4) ≠ toHex (carbonadoVerificationKey 6) :=
  verification_key_format_domain

theorem root_format_domain :
    let data := ofList [0, 1, 2, 3, 4]
    toHex (rootForFormat 4 data) ≠ toHex (rootForFormat 6 data) :=
  root_commits_to_format

/-! ## Roots -/

theorem hello_root :
    toHex (rootForFormat 4 (utf8 "hello")) =
      "f8a7892045a78f933cca82f9ef17046c453ad166e5463e5e93c88cf614443d86" := by
  native_decide

theorem hello_root_is_keyed_hash :
    let data := utf8 "hello"
    let key := carbonadoVerificationKey 4
    toHex (rootForFormat 4 data) = toHex (keyedHash key data) :=
  hello_root_eq_keyed_hash

private def pat100 : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    for i in [:100] do
      out := out.push (UInt8.ofNat (i % 251))
    pure out

theorem pat100_root_c4 :
    toHex (rootForFormat 4 pat100) =
      "27e8845ee8cfeed082734d4409991f9db4e9e4d0476de3ed196d89f4a2f37077" := by
  native_decide

theorem pat100_root_c6 :
    toHex (rootForFormat 6 pat100) =
      "1e478e01260caf8df6ad29f09c754a5e8423ee5ceceee4209db543828416147f" := by
  native_decide

/-! ## Inboard goldens + roundtrip -/

theorem empty_inboard_roundtrip :
    (match encodeInboardForFormat 4 ByteArray.empty with
     | (root, art) =>
         match decodeInboardForFormat 4 root art with
         | .ok d => d.size == 0
         | .error _ => false) = true :=
  encode_decode_empty_c4

theorem hello_inboard_artifact :
    (let (_root, art) := encodeInboardForFormat 4 (utf8 "hello")
     toHex art = "050000000000000068656c6c6f") = true := by
  native_decide

theorem pat100_inboard_roundtrip :
    (let (root, art) := encodeInboardForFormat 4 pat100
     match decodeInboardForFormat 4 root art with
     | .ok d => toHex d == toHex pat100
     | .error _ => false) = true := by
  native_decide

/-- Encode is deterministic. -/
theorem encode_deterministic_hello :
    (let a := encodeInboardForFormat 4 (utf8 "hello")
     let b := encodeInboardForFormat 4 (utf8 "hello")
     toHex a.1 == toHex b.1 && toHex a.2 == toHex b.2) = true := by
  native_decide

/-- Stream slice decode recovers authenticated bytes (pat100 = single leaf, full range). -/
theorem stream_slice_decode_pat100 :
    (let (root, _art) := encodeInboardForFormat 4 pat100
     let (_r, resp) := encodeSliceForFormat 4 pat100 0 1
     match decodeSliceForFormat 4 root 100 0 1 resp with
     | .ok d => toHex d == toHex pat100
     | .error _ => false) = true := by
  native_decide

/-! ## Strict error observers (every BaoError constructor) -/

private def isAuthFail : Except BaoError α → Bool
  | .error .authenticationFailed => true
  | _ => false

private def isTrunc : Except BaoError α → Bool
  | .error .truncatedResponse => true
  | _ => false

private def isTrailing : Except BaoError α → Bool
  | .error .trailingData => true
  | _ => false

private def isInvalidPrefix : Except BaoError α → Bool
  | .error .invalidPrefix => true
  | _ => false

private def isInvalidRoot : Except BaoError α → Bool
  | .error .invalidRootLength => true
  | _ => false

private def isInvalidSlice : Except BaoError α → Bool
  | .error .invalidSliceIndex => true
  | _ => false

private def isInvalidCount : Except BaoError α → Bool
  | .error .invalidSliceCount => true
  | _ => false

theorem wrong_format_auth_fail :
    (let (root, art) := encodeInboardForFormat 4 pat100
     isAuthFail (decodeInboardForFormat 6 root art)) = true := by
  native_decide

theorem short_prefix_error :
    isInvalidPrefix (contentLenPrefix (ofList [1, 2, 3])) = true := by
  native_decide

theorem invalid_root_length_error :
    (let (_root, art) := encodeInboardForFormat 4 pat100
     isInvalidRoot (decodeInboardForFormat 4 (ofList [0]) art)) = true := by
  native_decide

theorem invalid_slice_index_error :
    (let (root, art) := encodeInboardForFormat 4 pat100
     isInvalidSlice (verifySliceInboardForFormat 4 root art 5 1)) = true := by
  native_decide

/-- content_len claims 100 bytes but response only has 99 → truncatedResponse. -/
theorem truncated_body_is_trunc :
    (let (root, art) := encodeInboardForFormat 4 pat100
     let short := art.extract 0 (art.size - 1)
     isTrunc (decodeInboardForFormat 4 root short)) = true := by
  native_decide

/-- Extra byte after valid inboard → trailingData (not truncatedResponse). -/
theorem trailing_body_is_trailing :
    (let (root, art) := encodeInboardForFormat 4 pat100
     let long := art.push 0xaa
     isTrailing (decodeInboardForFormat 4 root long)) = true := by
  native_decide

theorem tampered_body_auth_fail :
    (let (root, art) := encodeInboardForFormat 4 pat100
     let bad := art.set! 10 (art.get! 10 ^^^ 0x01)
     isAuthFail (decodeInboardForFormat 4 root bad)) = true := by
  native_decide

/-- Stream decode count=0 → invalidSliceCount. -/
theorem slice_count_zero_error :
    (let (root, _art) := encodeInboardForFormat 4 pat100
     let (_r, resp) := encodeSliceForFormat 4 pat100 0 1
     isInvalidCount (decodeSliceForFormat 4 root 100 0 0 resp)) = true := by
  native_decide

/-- Corrupt inboard + count=0 extract must not succeed (auth-first). -/
theorem count_zero_corrupt_inboard_auth_fail :
    (let (root, art) := encodeInboardForFormat 4 pat100
     let bad := art.set! 10 (art.get! 10 ^^^ 0x01)
     isAuthFail (verifySliceInboardForFormat 4 root bad 0 0)) = true := by
  native_decide

/-- Stream slice wrong format key → authenticationFailed. -/
theorem stream_slice_wrong_key_auth_fail :
    (let (root, _art) := encodeInboardForFormat 4 pat100
     let (_r, resp) := encodeSliceForFormat 4 pat100 0 1
     isAuthFail (decodeSliceForFormat 6 root 100 0 1 resp)) = true := by
  native_decide

/-- Stream slice truncated → truncatedResponse. -/
theorem stream_slice_truncated :
    (let (root, _art) := encodeInboardForFormat 4 pat100
     let (_r, resp) := encodeSliceForFormat 4 pat100 0 1
     let short := resp.extract 0 (min 3 resp.size)
     isTrunc (decodeSliceForFormat 4 root 100 0 1 short)) = true := by
  native_decide

/-- Stream slice trailing garbage → trailingData. -/
theorem stream_slice_trailing :
    (let (root, _art) := encodeInboardForFormat 4 pat100
     let (_r, resp) := encodeSliceForFormat 4 pat100 0 1
     let long := resp.push 0xcc
     isTrailing (decodeSliceForFormat 4 root 100 0 1 long)) = true := by
  native_decide

end CarbonadoTest.Bao
