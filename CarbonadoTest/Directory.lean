/-
  Program G — Adamantine, Filepack, Directory tests.

  Dependency: CarbonadoTest → Carbonado only.

  Exact-match every product-reachable DirectoryError / FilepackError path where
  cheap; FEC-heavy tamper cases are AOT-gated in Main.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Adamantine
import Carbonado.Filepack
import Carbonado.Outboard
import Carbonado.Directory
import Carbonado.Pipeline
import CarbonadoTest.Scaffold

namespace CarbonadoTest.Directory

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Adamantine
open Carbonado.Filepack
open Carbonado.Outboard
open Carbonado.Directory
open Carbonado.Pipeline

private def pubMaster : ByteArray := replicate 32 0
private def master42 : ByteArray := replicate 32 0x42

/-! ## Adamantine wire -/

theorem adam_magic_len : adamantineMagic.length = 13 := adamantineMagic_length

theorem adam_header_19 : adamantineHeaderLen = 19 := adamantineHeaderLen_eq

theorem adam_roundtrip_empty :
    (match decodeAdamantine (encodeAdamantine ByteArray.empty adamantineFmtPublic 0) with
     | .ok (p, h) => p.size == 0 && h.carbonadoFmt == adamantineFmtPublic && h.flags == 0
     | .error _ => false) = true :=
  encode_decode_empty_public

theorem adam_invalid_flags :
    (match decodeAdamantine (encodeAdamantine ByteArray.empty adamantineFmtPublic 2) with
     | .error (.invalidFlags 2) => true
     | _ => false) = true :=
  invalid_flags_bit1

theorem adam_invalid_fmt :
    (match decodeAdamantine (encodeAdamantine ByteArray.empty 0 0) with
     | .error (.invalidCarbonadoFormat 0) => true
     | _ => false) = true :=
  invalid_fmt_c0

theorem adam_short :
    (match decodeAdamantine (ofList [1, 2, 3]) with
     | .error .invalidHeader => true
     | _ => false) = true :=
  short_header

theorem adam_dev_v2 :
    (match decodeAdamantine (appendBA adamantineMagicDevV2 (replicate 7 0)) with
     | .error (.unsupportedVersion 2 0) => true
     | _ => false) = true :=
  dev_v2_rejected

/-! ## Path rules (fail-closed) -/

theorem path_empty :
    (match validateRelPath "" with | .error .emptyRelPath => true | _ => false) = true :=
  rel_empty

theorem path_traversal :
    (match validateRelPath "a/../b" with | .error .relPathTraversal => true | _ => false) = true :=
  rel_traversal

theorem path_absolute :
    (match validateRelPath "/etc/passwd" with | .error .relPathAbsolute => true | _ => false) =
      true :=
  rel_absolute

theorem path_backslash :
    (match validateRelPath "a\\b" with | .error .relPathBackslash => true | _ => false) = true :=
  rel_backslash

theorem path_ok :
    (match validateRelPath "src/main.lean" with | .ok () => true | _ => false) = true :=
  rel_ok

theorem path_empty_comp :
    (match validateRelPath "a//b" with | .error .relPathEmptyComponent => true | _ => false) =
      true :=
  rel_empty_component

theorem path_null :
    (match validateRelPath ("a" ++ String.singleton (Char.ofNat 0) ++ "b") with
     | .error .relPathNullByte => true
     | _ => false) = true :=
  rel_null

/-! ## Error maps (1:1, no collapse) -/

theorem map_traversal : ofFilepackError .relPathTraversal = .pathTraversal := ofFilepack_traversal

theorem map_absolute : ofFilepackError .relPathAbsolute = .pathAbsolute := ofFilepack_absolute

theorem map_backslash : ofFilepackError .relPathBackslash = .pathBackslash := ofFilepack_backslash

theorem map_null : ofFilepackError .relPathNullByte = .pathNullByte := ofFilepack_null

theorem map_empty_component :
    ofFilepackError .relPathEmptyComponent = .pathEmptyComponent := ofFilepack_empty_component

theorem map_too_many_segments :
    ofFilepackError .tooManySegments = .tooManySegments := ofFilepack_too_many_segments

theorem map_ots_too_large :
    ofFilepackError .otsProofTooLarge = .otsProofTooLarge := ofFilepack_ots_too_large

theorem map_adam_flags :
    ofAdamantineError (.invalidFlags 2) = .invalidAdamantineFlags 2 := ofAdamantine_flags

theorem map_adam_magic : ofAdamantineError .invalidMagic = .invalidAdamantineMagic :=
  ofAdamantine_magic

/-! ## Filepack / policy -/

theorem cfp2_magic :
    cfp2Magic = [0x43, 0x46, 0x50, 0x32] := by
  native_decide

theorem filepack_legacy_c4 :
    (match validateSegmentFormat 0x04 false with
     | .error (.legacySegmentFormat 0x04) => true
     | _ => false) = true := by
  native_decide

theorem filepack_seg_enc_mismatch :
    (match validateSegmentFormat segmentFormatPublicRaw true with
     | .error (.segmentFormatMismatch 0x0C) => true
     | _ => false) = true := by
  native_decide

theorem filepack_seg_enc_mismatch_named :
    (match validateSegmentFormat (0x0C : UInt8) true with
     | .error (.segmentFormatMismatch 0x0C) => true
     | _ => false) = true := by
  native_decide

/-! ## Master policy + path at encode (cheap) -/

theorem directory_zero_master_encrypted :
    (match encodeDirectory pubMaster
        #[{ relPath := "a", content := utf8 "z" }]
        { catalogEncrypted := true, segmentPolicy := .forceRaw }
        #[replicate 16 1, replicate 16 2] with
     | .error .zeroMasterKeyNotAllowed => true
     | _ => false) = true := by
  native_decide

theorem directory_nonzero_master_public :
    (match encodeDirectory master42
        #[{ relPath := "a", content := utf8 "z" }]
        { catalogEncrypted := false, segmentPolicy := .forceRaw }
        #[] with
     | .error .encryptedDirectoryNotRequested => true
     | _ => false) = true := by
  native_decide

theorem directory_rejects_traversal :
    (match encodeDirectory pubMaster
        #[{ relPath := "../x", content := utf8 "z" }]
        { catalogEncrypted := false, segmentPolicy := .forceRaw }
        #[] with
     | .error .pathTraversal => true
     | _ => false) = true := by
  native_decide

theorem directory_rejects_absolute :
    (match encodeDirectory pubMaster
        #[{ relPath := "/etc/passwd", content := utf8 "z" }]
        { catalogEncrypted := false, segmentPolicy := .forceRaw }
        #[] with
     | .error .pathAbsolute => true
     | _ => false) = true := by
  native_decide

theorem directory_rejects_backslash :
    (match encodeDirectory pubMaster
        #[{ relPath := "a\\b", content := utf8 "z" }]
        { catalogEncrypted := false, segmentPolicy := .forceRaw }
        #[] with
     | .error .pathBackslash => true
     | _ => false) = true := by
  native_decide

theorem directory_empty_path :
    (match encodeDirectory pubMaster
        #[{ relPath := "", content := utf8 "z" }]
        { catalogEncrypted := false, segmentPolicy := .forceRaw }
        #[] with
     | .error .pathEmpty => true
     | _ => false) = true := by
  native_decide

theorem directory_null_path :
    (match encodeDirectory pubMaster
        #[{ relPath := "a" ++ String.singleton (Char.ofNat 0) ++ "b", content := utf8 "z" }]
        { catalogEncrypted := false, segmentPolicy := .forceRaw }
        #[] with
     | .error .pathNullByte => true
     | _ => false) = true := by
  native_decide

/-- requireOts rejected at encode (no undecodeable archives). -/
theorem directory_require_ots_encode_rejected :
    (match encodeDirectory pubMaster
        #[{ relPath := "a", content := utf8 "z" }]
        { catalogEncrypted := false, segmentPolicy := .forceRaw, requireOts := true }
        #[] with
     | .error .otsFeatureRequired => true
     | _ => false) = true := by
  native_decide

/-! ## FEC geometry -/

theorem padding_main_zero :
    paddingForMainLen 0 true = 0 := by
  native_decide

theorem padding_main_one :
    paddingForMainLen 1 true = 16383 := by
  native_decide

theorem expected_fec_parity_empty : expectedFecParityLen 0 = 0 := by native_decide

theorem expected_fec_parity_one : expectedFecParityLen 1 = 16384 := by native_decide

/-- Empty main + nonzero FEC parity → unexpectedFecParity. -/
theorem bundle_sem_zero_main_with_fec :
    (match validateSegmentBundleSemantics segmentFormatPublicRaw {
        segmentBaoRoot := replicate 32 0
        chunkIndex := 0
        mainLen := 0
        verificationOutboardOffset := 0
        verificationOutboardLen := 0
        fecParityOffset := 0
        fecParityLen := 1
      } with
     | .error .unexpectedFecParity => true
     | _ => false) = true := by
  native_decide

/-- Nonzero main + zero FEC parity → missingFecParity. -/
theorem bundle_sem_missing_fec :
    (match validateSegmentBundleSemantics segmentFormatPublicRaw {
        segmentBaoRoot := replicate 32 0
        chunkIndex := 0
        mainLen := 1
        verificationOutboardOffset := 0
        verificationOutboardLen := 0
        fecParityOffset := 0
        fecParityLen := 0
      } with
     | .error .missingFecParity => true
     | _ => false) = true := by
  native_decide

/-- Wrong FEC parity length → fecParityLenMismatch. -/
theorem bundle_sem_fec_len_mismatch :
    (match validateSegmentBundleSemantics segmentFormatPublicRaw {
        segmentBaoRoot := replicate 32 0
        chunkIndex := 0
        mainLen := 1
        verificationOutboardOffset := 0
        verificationOutboardLen := 0
        fecParityOffset := 0
        fecParityLen := 1
      } with
     | .error .fecParityLenMismatch => true
     | _ => false) = true := by
  native_decide

/-- FEC present on non-FEC format → unexpectedFecParity. -/
theorem bundle_sem_fec_on_non_fec_format :
    (match validateSegmentBundleSemantics 0x04 {
        segmentBaoRoot := replicate 32 0
        chunkIndex := 0
        mainLen := 1
        verificationOutboardOffset := 0
        verificationOutboardLen := 0
        fecParityOffset := 0
        fecParityLen := 16
      } with
     | .error .unexpectedFecParity => true
     | _ => false) = true := by
  native_decide

/-- Catalog name too short → invalidCatalogPath. -/
theorem catalog_name_short :
    (match parseCatalogName "aa.adam.c14" with
     | .error .invalidCatalogPath => true
     | _ => false) = true := by
  native_decide

/-- contentBlake3Mismatch exact (wrong hash). -/
theorem content_blake3_mismatch :
    (match checkContentBlake3 (utf8 "x") (replicate 32 0) with
     | .error .contentBlake3Mismatch => true
     | _ => false) = true := by
  native_decide

/-- contentBlake3 ok path for empty. -/
theorem content_blake3_empty_ok :
    (match checkContentBlake3 ByteArray.empty (Carbonado.Bao.Blake3.hash ByteArray.empty) with
     | .ok () => true
     | _ => false) = true := by
  native_decide

/-- invalidHashLength when expected hash size wrong. -/
theorem content_blake3_bad_hash_len :
    (match checkContentBlake3 (utf8 "x") (ofList [1, 2, 3]) with
     | .error .invalidHashLength => true
     | _ => false) = true := by
  native_decide

end CarbonadoTest.Directory
