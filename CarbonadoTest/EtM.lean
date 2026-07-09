/-
  Program B — EtM tests: structural theorems + golden / failure-mode checks.

  Dependency direction: CarbonadoTest → Carbonado only.
-/
import Carbonado.Constants
import Carbonado.Crypto
import CarbonadoTest.Scaffold

namespace CarbonadoTest.EtM

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Crypto.SHA512
open Carbonado.Crypto.HMAC
open Carbonado.Crypto.AESCTR
open Carbonado.Crypto.EtM

/-! ## Re-export MAC-before-decrypt theorems into the test tree -/

theorem mac_tag_fail_is_auth_error
    (aesKey macKey nonce tag ct : ByteArray)
    (h : ctEq tag (computePayloadTag macKey nonce ct) = false) :
    decryptAfterMacCheck aesKey macKey nonce tag ct = .error .authenticationFailed :=
  decryptAfterMacCheck_tag_fail aesKey macKey nonce tag ct h

theorem mac_ok_implies_ctEq
    (aesKey macKey nonce tag ct pt : ByteArray)
    (h : decryptAfterMacCheck aesKey macKey nonce tag ct = .ok pt) :
    ctEq tag (computePayloadTag macKey nonce ct) = true :=
  decryptAfterMacCheck_ok_implies_mac aesKey macKey nonce tag ct pt h

theorem auth_fail_plaintext_none
    (aesKey macKey nonce tag ct : ByteArray)
    (h : ctEq tag (computePayloadTag macKey nonce ct) = false) :
    (decryptAfterMacCheck aesKey macKey nonce tag ct).plaintext? = none :=
  decryptAfterMacCheck_auth_fail_no_plaintext aesKey macKey nonce tag ct h

theorem short_input_is_invalidCiphertextLength
    (master nonce input : ByteArray)
    (hs : (input.size < hmacTagLen) = true) :
    decryptWithNonce master nonce input = .error .invalidCiphertextLength :=
  decryptWithNonce_short_input master nonce input hs

theorem short_master_is_invalidKeyLength
    (master nonce input : ByteArray)
    (hs : (input.size < hmacTagLen) = false)
    (hm : (master.size < minMasterLen) = true) :
    decryptWithNonce master nonce input = .error .invalidKeyLength :=
  decryptWithNonce_short_master master nonce input hs hm

theorem bad_nonce_is_invalidNonceLength
    (master nonce input : ByteArray)
    (hs : (input.size < hmacTagLen) = false)
    (hm : (master.size < minMasterLen) = false)
    (hn : (nonce.size != nonceLen) = true) :
    decryptWithNonce master nonce input = .error .invalidNonceLength :=
  decryptWithNonce_bad_nonce master nonce input hs hm hn

/-! ## Bool observers for `native_decide` (DecryptResult has no DecidableEq). -/

private def isAuthFailed : DecryptResult → Bool
  | .error .authenticationFailed => true
  | _ => false

private def isInvalidCiphertextLength : DecryptResult → Bool
  | .error .invalidCiphertextLength => true
  | _ => false

private def isInvalidKeyLength : DecryptResult → Bool
  | .error .invalidKeyLength => true
  | _ => false

private def isInvalidNonceLength : DecryptResult → Bool
  | .error .invalidNonceLength => true
  | _ => false

private def encryptOkHex (master nonce pt : ByteArray) : String :=
  match encryptWithNonce master nonce pt with
  | .ok blob => toHex blob
  | .error _ => ""

private def encryptErrIsInvalidNonce (master nonce pt : ByteArray) : Bool :=
  match encryptWithNonce master nonce pt with
  | .error .invalidNonceLength => true
  | _ => false

private def roundtripOk (master nonce pt : ByteArray) : Bool :=
  match encryptWithNonce master nonce pt with
  | .error _ => false
  | .ok blob =>
    match decryptWithNonce master nonce blob with
    | .ok pt' => toHex pt' == toHex pt
    | .error _ => false

private def embeddedRoundtripOk (master nonce pt : ByteArray) : Bool :=
  match encryptEmbeddedNonce master nonce pt with
  | .error _ => false
  | .ok blob =>
    match decryptEmbeddedNonce master blob with
    | .ok pt' => toHex pt' == toHex pt
    | .error _ => false

private def tamperTagFails (master nonce pt : ByteArray) : Bool :=
  match encryptWithNonce master nonce pt with
  | .error _ => false
  | .ok blob =>
    let bad := blob.set! 0 (blob.get! 0 ^^^ 1)
    isAuthFailed (decryptWithNonce master nonce bad)

private def tamperBodyFails (master nonce pt : ByteArray) : Bool :=
  match encryptWithNonce master nonce pt with
  | .error _ => false
  | .ok blob =>
    if blob.size ≤ hmacTagLen then false
    else
      let bad := blob.set! hmacTagLen (blob.get! hmacTagLen ^^^ 1)
      isAuthFailed (decryptWithNonce master nonce bad)

private def wrongKeyFails (master wrong nonce pt : ByteArray) : Bool :=
  match encryptWithNonce master nonce pt with
  | .error _ => false
  | .ok blob => isAuthFailed (decryptWithNonce wrong nonce blob)

private def headerMacHex (master auth : ByteArray) : String :=
  match computeHeaderMac master auth with
  | .ok tag => toHex tag
  | .error _ => ""

private def verifyHeaderMacBool (master auth tag : ByteArray) : Bool :=
  match verifyHeaderMac master auth tag with
  | .ok b => b
  | .error _ => false

private def master42 : ByteArray := replicate 32 0x42
private def nonce11 : ByteArray := replicate 16 0x11

private def nistKey : ByteArray := ofList [
  0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4]

private def nistCtr : ByteArray := ofList [
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]

private def nistPt : ByteArray := ofList [
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10]

/-- Empty SHA-512 digest (FIPS). -/
theorem sha512_empty_hex :
    toHex (Carbonado.Crypto.SHA512.hash ByteArray.empty) =
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" := by
  native_decide

/-- SHA-512("abc"). -/
theorem sha512_abc_hex :
    toHex (hashString "abc") =
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" := by
  native_decide

/-- HMAC-SHA512 RFC 4231 test case 1. -/
theorem hmac_rfc4231_1 :
    toHex (hmacSHA512 (replicate 20 0x0b) (utf8 "Hi There")) =
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" := by
  native_decide

/-- AES-256-CTR NIST SP 800-38A F.5.5. -/
theorem aes_ctr_nist_f55 :
    toHex (ctrXor nistKey nistCtr nistPt) =
      "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6" := by
  native_decide

/-- Subkey `aes-ctr` under master 0x42×32. -/
theorem subkey_aes_ctr_golden :
    (match deriveSubkey master42 "aes-ctr" with
     | .ok sk => toHex sk
     | .error _ => "") =
      "6f15fb9936ca3e4d2ecc5bd80bcc06c12d67361b72dcf5e8edc8312092f42a28494d106e3340595717f67ab0ec91b0b8d0ea653853ca129a4515ea6df74a5ca7" := by
  native_decide

/-- Subkey `etm-hmac` under master 0x42×32. -/
theorem subkey_etm_hmac_golden :
    (match deriveSubkey master42 "etm-hmac" with
     | .ok sk => toHex sk
     | .error _ => "") =
      "d9795accc69d8966b12f051575d3efc53725697a14d8117ffcef149eea20bb859e025d2e76f5b47bb1bc73af3c34aceb317ba0d5d00e5b3f36e7f21accae3609" := by
  native_decide

/-- Subkey `header-auth` under master 0x42×32. -/
theorem subkey_header_auth_golden :
    (match deriveSubkey master42 "header-auth" with
     | .ok sk => toHex sk
     | .error _ => "") =
      "af1f7d5c23422538fab14c8343eaef42918230ba04fef171176b3c01a89e9bab0ae60b90586d9863f4a4231d91eb984516f0be04c20d4c7e784f0fe459de2b19" := by
  native_decide

/-- EtM empty plaintext header-path golden. -/
theorem etm_empty_golden :
    encryptOkHex master42 nonce11 ByteArray.empty =
      "74e137726bc9f0a9e55add833d1ac0c187bb366f22f0a2be1189536828d77dfc2d021e8aad99fab802c664db3b8ec1e0c46198f44dd3f3e9321bded8263a6aa2" := by
  native_decide

/-- EtM `hello` golden. -/
theorem etm_hello_golden :
    encryptOkHex master42 nonce11 (utf8 "hello") =
      "1d05aa600755696228225aeada6672b65266554ef6a2e2b5f4a083870ad00f534747fbd18d98f4c6e449a4b64e954b77f65bd63eba1a9a0e080cca3c296760b08f0a0e143c" := by
  native_decide

/-- EtM multi-block golden (fox sentence). -/
theorem etm_multi_golden :
    encryptOkHex master42 nonce11 (utf8 "The quick brown fox jumps over the lazy dog") =
      "38cddad202dc0f7daacd53b35573b43a3c79bbcfa44aee039d661c92d5be8f16701b996b7474d66610627fb714376524cfcbb4aa30d8e7062ca9b61cf32eccd9b307075822eda7e16b52f04354c83f70cd6b5a9ab6817560693ae25a0cdd1883752eeccaff8bb0228d84c6" := by
  native_decide

/-- EtM empty roundtrip. -/
theorem etm_empty_roundtrip :
    roundtripOk master42 nonce11 ByteArray.empty = true := by
  native_decide

/-- EtM hello roundtrip. -/
theorem etm_hello_roundtrip :
    roundtripOk master42 nonce11 (utf8 "hello") = true := by
  native_decide

/-- Embedded-nonce hello roundtrip. -/
theorem etm_embedded_hello_roundtrip :
    embeddedRoundtripOk master42 nonce11 (utf8 "hello") = true := by
  native_decide

/-- Embedded short input → `invalidCiphertextLength`. -/
theorem etm_embedded_short_ct :
    isInvalidCiphertextLength (decryptEmbeddedNonce master42 (replicate 20 0)) = true := by
  native_decide

/-- Tampered tag fails with `authenticationFailed`. -/
theorem etm_tampered_tag_auth_failed :
    tamperTagFails master42 nonce11 (utf8 "hi") = true := by
  native_decide

/-- Ciphertext-body tamper fails with `authenticationFailed`. -/
theorem etm_tampered_body_auth_failed :
    tamperBodyFails master42 nonce11 (utf8 "hello") = true := by
  native_decide

/-- Wrong master fails with `authenticationFailed`. -/
theorem etm_wrong_key_auth_failed :
    wrongKeyFails master42 (replicate 32 0x43) nonce11 (utf8 "hi") = true := by
  native_decide

/-- Short ciphertext → `invalidCiphertextLength`. -/
theorem etm_short_ct_length :
    isInvalidCiphertextLength (decryptWithNonce master42 nonce11 (replicate 8 0)) = true := by
  native_decide

/-- Dual-invalid short master + short CT → CT length first (Rust parity). -/
theorem etm_dual_short_prefers_ct_length :
    isInvalidCiphertextLength
      (decryptWithNonce (replicate 16 0x42) nonce11 (replicate 8 0)) = true := by
  native_decide

/-- Short master (CT long enough) → `invalidKeyLength`. -/
theorem etm_short_master_key :
    isInvalidKeyLength (decryptWithNonce (replicate 16 0x42) nonce11 (replicate 64 0)) = true := by
  native_decide

/-- Bad nonce length on encrypt → `invalidNonceLength`. -/
theorem etm_encrypt_bad_nonce :
    encryptErrIsInvalidNonce master42 (replicate 8 0x11) (utf8 "hi") = true := by
  native_decide

/-- Bad nonce length on decrypt → `invalidNonceLength`. -/
theorem etm_decrypt_bad_nonce :
    isInvalidNonceLength (decryptWithNonce master42 (replicate 8 0x11) (replicate 64 0)) = true := by
  native_decide

/-- Empty master rejected by deriveSubkey. -/
theorem derive_empty_master :
    (match deriveSubkey ByteArray.empty "aes-ctr" with
     | .error .invalidKeyLength => true
     | _ => false) = true := by
  native_decide

/-- Header MAC over MAGIC golden. -/
theorem header_mac_magic_golden :
    headerMacHex master42 (utf8 "CARBONADO20\n") =
      "c02b40016162e5abf37a007183f2117a46fb74175529188dc98786c9cab370691c7903dcf552765f7764ec2c392af0863b618ea295ed026e8a47b304f0127937" := by
  native_decide

/-- `verifyHeaderMac` false path on flipped tag. -/
theorem header_mac_verify_false :
    (match computeHeaderMac master42 (utf8 "CARBONADO20\n") with
     | .ok tag =>
         verifyHeaderMacBool master42 (utf8 "CARBONADO20\n")
           (tag.set! 0 (tag.get! 0 ^^^ 1)) = false
     | .error _ => false) = true := by
  native_decide

/-- Digest length is full 64 bytes; tag constant matches. -/
theorem digest_and_tag_len :
    (Carbonado.Crypto.SHA512.hash ByteArray.empty).size = 64 ∧ hmacTagLen = 64 := by
  native_decide

end CarbonadoTest.EtM
