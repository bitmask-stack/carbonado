/-
  Carbonado product-facing keyed Bao API.

  Format-byte verification key:
    blake3::derive_key("carbonado-v2/verification", &[format])
  (see AGENTS.md / Rust `crypto::carbonado_verification_key`).
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Bao.Blake3
import Carbonado.Bao.Tree

namespace Carbonado.Bao.Product

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Bao.Blake3
open Carbonado.Bao.Tree

/-- Derive the 32-byte keyed-Bao BLAKE3 key for format level `format` (c0–c15). -/
def carbonadoVerificationKey (format : UInt8) : ByteArray :=
  deriveKey verificationContext (ofList [format])

/-- Keyed Bao root for logical `data` under Carbonado format byte. -/
def rootForFormat (format : UInt8) (data : ByteArray) : ByteArray :=
  keyedRoot (carbonadoVerificationKey format) data

/-- Encode inboard `[u64le|response]` for format; returns `(root, artifact)`. -/
def encodeInboardForFormat (format : UInt8) (data : ByteArray) : ByteArray × ByteArray :=
  encodeInboard (carbonadoVerificationKey format) data

/-- Decode/verify inboard under format + expected root. -/
def decodeInboardForFormat (format : UInt8) (root input : ByteArray) :
    Except BaoError ByteArray :=
  decodeInboard (carbonadoVerificationKey format) root input

/-- Verify inboard only. -/
def verifyInboardForFormat (format : UInt8) (root input : ByteArray) :
    Except BaoError Unit :=
  verifyInboard (carbonadoVerificationKey format) root input

/-- Post-order outboard `(root, sidecar)` for format. -/
def encodeOutboardForFormat (format : UInt8) (data : ByteArray) : ByteArray × ByteArray :=
  createOutboard (carbonadoVerificationKey format) data

/-- Verify bare main + outboard sidecar under format. -/
def verifyOutboardForFormat (format : UInt8) (root bare outboard : ByteArray) :
    Except BaoError Unit :=
  verifyOutboard (carbonadoVerificationKey format) root bare outboard

/-- Encode slice response for format. -/
def encodeSliceForFormat (format : UInt8) (data : ByteArray) (index count : Nat) :
    ByteArray × ByteArray :=
  encodeSliceResponse (carbonadoVerificationKey format) data index count

/-- Stream-authenticate slice response under format (no full plaintext required).

  `contentLen` is the logical file size (from header / out-of-band), not derived from
  the untrusted response body.
-/
def decodeSliceForFormat (format : UInt8) (root : ByteArray) (contentLen index count : Nat)
    (response : ByteArray) : Except BaoError ByteArray :=
  decodeSliceResponse (carbonadoVerificationKey format) root contentLen index count response

/-- Extract/verify slice from full inboard under format (auth-first). -/
def verifySliceInboardForFormat (format : UInt8) (root input : ByteArray)
    (index count : Nat) : Except BaoError ByteArray :=
  verifySliceInboard (carbonadoVerificationKey format) root input index count

/-- Different format bytes yield different verification keys. -/
theorem verification_key_format_domain :
    toHex (carbonadoVerificationKey 4) ≠ toHex (carbonadoVerificationKey 6) := by
  native_decide

/-- Root commits to format: same data, different format → different root. -/
theorem root_commits_to_format :
    let data := ofList [0, 1, 2, 3, 4]
    toHex (rootForFormat 4 data) ≠ toHex (rootForFormat 6 data) := by
  native_decide

/-- Empty inboard roundtrip under c4. -/
theorem encode_decode_empty_c4 :
    (match encodeInboardForFormat 4 ByteArray.empty with
     | (root, art) =>
         match decodeInboardForFormat 4 root art with
         | .ok d => d.size == 0
         | .error _ => false) = true := by
  native_decide

/-- Hello inboard root matches keyed_hash under c4. -/
theorem hello_root_eq_keyed_hash :
    let data := utf8 "hello"
    let key := carbonadoVerificationKey 4
    toHex (rootForFormat 4 data) = toHex (keyedHash key data) := by
  native_decide

end Carbonado.Bao.Product
