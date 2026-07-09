/-
  Program F — SLH1 wire + Bao-root binding theorems.

  Large 7856-byte signature roundtrips are AOT Main only (not native_decide).
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Slh
import CarbonadoTest.Scaffold

namespace CarbonadoTest.Slh

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Slh

theorem sidecar_len : slh1SidecarLen = 7860 := slh1_sidecar_len
theorem sig_len : slh1SignatureLen = 7856 := slh1_sig_len
theorem magic_ascii : slh1Magic = [0x53, 0x4c, 0x48, 0x31] := slh1_magic_bytes

theorem short_sidecar :
    (match parseSidecar (ofList [0x53, 0x4c, 0x48, 0x31]) with
     | .error .invalidSidecarLength => true
     | _ => false) = true := parse_short_length

theorem empty_sidecar :
    (match parseSidecar ByteArray.empty with
     | .error .invalidSidecarLength => true
     | _ => false) = true := parse_empty

/-- badSlhMagic path (exact-length magic gate; full 7860 B also in AOT Main). -/
theorem bad_magic_prefix :
    (match parseMagicAtExactLen (ofList [0, 0, 0, 0]) with
     | .error .badSlhMagic => true
     | _ => false) = true := parse_magic_bad

theorem good_magic_prefix :
    (match parseMagicAtExactLen slh1MagicBA with
     | .ok b => b.size == 0
     | .error _ => false) = true := parse_magic_good_empty_payload

theorem zeros_not_magic : slh1MagicPrefix (ofList [0, 0, 0, 0]) = false :=
  zeros_not_slh1_magic

theorem build_bad_len :
    (match buildSidecar (ofList [1, 2, 3]) with
     | .error .invalidSignatureLength => true
     | _ => false) = true := build_bad_sig_len

theorem bad_pk :
    (match mkBinding (ofList [1]) (replicate hashLen 0) (ofList [1]) with
     | .error .invalidPublicKeyLength => true
     | _ => false) = true := bind_bad_pk

theorem bad_root :
    (match mkBinding (replicate slhPublicKeyLen 0) (ofList [1]) (ofList [1]) with
     | .error .invalidRootLength => true
     | _ => false) = true := bind_bad_root

theorem bad_sig :
    (match mkBinding (replicate slhPublicKeyLen 0) (replicate hashLen 0) (ofList [1]) with
     | .error .invalidSignatureLength => true
     | _ => false) = true := bind_bad_sig

theorem wrong_root_path :
    (let rootA := replicate hashLen 0xaa
     let rootB := replicate hashLen 0xbb
     let pk := replicate slhPublicKeyLen 0x11
     let sig := ofList [0xcd]
     match verifyBoundToExpected (mockOracleFor rootA sig) pk rootA rootB sig with
     | .error .verificationFailed => true
     | _ => false) = true := wrong_root_fails

theorem sign_unavail :
    (match signRoot (replicate 128 0x42) (replicate hashLen 0) with
     | .error .signatureUnavailable => true
     | _ => false) = true := sign_unavailable

theorem sign_bad_root_len :
    (match signRoot (replicate 128 0x42) (ofList [1]) with
     | .error .invalidRootLength => true
     | _ => false) = true := sign_bad_root

/-- bindingFromSidecar: short file → invalidSidecarLength. -/
theorem binding_short_sidecar :
    (match bindingFromSidecar (replicate slhPublicKeyLen 0) (replicate hashLen 0)
        (ofList [1, 2, 3]) with
     | .error .invalidSidecarLength => true
     | _ => false) = true := by
  native_decide

/-- Long sidecar (5 bytes) → invalidSidecarLength. -/
theorem parse_too_long_short :
    (match parseSidecar (ofList [0, 1, 2, 3, 4]) with
     | .error .invalidSidecarLength => true
     | _ => false) = true := by
  native_decide

end CarbonadoTest.Slh
