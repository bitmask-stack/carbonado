/-
  Program C — RS 4/8 FEC tests: geometry theorems, goldens, reconstruct, errors.

  Dependency direction: CarbonadoTest → Carbonado only.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Fec
import CarbonadoTest.Scaffold

namespace CarbonadoTest.Fec

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Fec.Galois
open Carbonado.Fec.Matrix
open Carbonado.Fec.RS
open Carbonado.Fec.Inboard

/-! ## Re-export geometry theorems -/

theorem padding_zero : calcPaddingLen 0 = { paddingLen := 0, chunkLen := 0 } :=
  calcPaddingLen_zero

theorem padding_one : calcPaddingLen 1 = { paddingLen := 16383, chunkLen := 4096 } :=
  calcPaddingLen_one

theorem padding_stripe : calcPaddingLen 16384 = { paddingLen := 0, chunkLen := 4096 } :=
  calcPaddingLen_stripe

theorem padding_stripe_plus :
    calcPaddingLen 16385 = { paddingLen := 16383, chunkLen := 8192 } :=
  calcPaddingLen_stripe_plus_one

theorem padding_100 : calcPaddingLen 100 = { paddingLen := 16284, chunkLen := 4096 } :=
  calcPaddingLen_100

theorem padding_4096 : calcPaddingLen 4096 = { paddingLen := 12288, chunkLen := 4096 } :=
  calcPaddingLen_4096

theorem padded_aligns :
    (List.map paddedLen [1, 100, 4096, 16384, 16385]).all
      (fun p => p % stripeUnit == 0) = true :=
  paddedLen_aligns_samples

theorem rs_geometry :
    carbonadoRS.dataShards = fecK ∧ carbonadoRS.parityShards = fecM - fecK :=
  carbonadoRS_geometry

theorem rs_constructs :
    (match carbonadoRSExcept with | .ok _ => true | .error _ => false) = true :=
  carbonadoRS_constructs

/-! ## GF goldens -/

theorem gf_mul_53_ca : mul 0x53 0xca = 0x8f := mul_0x53_0xca
theorem gf_div_2_3 : div 2 3 = 0xf5 := div_2_3
theorem gf_exp_2_3 : exp 2 3 = 8 := exp_2_3

/-! ## Bool observers for strict error matches (FecError has DecidableEq). -/

private def isUneven : Except FecError α → Bool
  | .error .unevenShards => true
  | _ => false

private def isTooFew : Except FecError α → Bool
  | .error .tooFewShards => true
  | _ => false

private def isEmptyShard : Except FecError α → Bool
  | .error .emptyShard => true
  | _ => false

private def isIncorrectSize : Except FecError α → Bool
  | .error .incorrectShardSize => true
  | _ => false

private def isBadGeometry : Except FecError α → Bool
  | .error .badGeometry => true
  | _ => false

private def isPaddingTooLarge : Except FecError α → Bool
  | .error .paddingTooLarge => true
  | _ => false

private def isSingular : Except FecError α → Bool
  | .error .singularMatrix => true
  | _ => false

/-- Build 1-byte data shards [1],[2],[3],[4] + zero parity placeholders. -/
private def shardsLen1 : Array ByteArray :=
  #[ofList [1], ofList [2], ofList [3], ofList [4],
    ofList [0], ofList [0], ofList [0], ofList [0]]

/-- Encode 1-byte shards; parity must be 0x45 0x5e 0x67 0x78 (pin crate golden). -/
theorem encode_len1_parity :
    (match carbonadoRS.encode shardsLen1 with
     | .error _ => false
     | .ok enc =>
         (enc[4]!).get! 0 == 0x45 &&
         (enc[5]!).get! 0 == 0x5e &&
         (enc[6]!).get! 0 == 0x67 &&
         (enc[7]!).get! 0 == 0x78) = true := by
  native_decide

/-- Encode is deterministic: two encodes of the same data match. -/
theorem encode_deterministic_len1 :
    (match carbonadoRS.encode shardsLen1, carbonadoRS.encode shardsLen1 with
     | .ok a, .ok b =>
         (a[4]!).get! 0 == (b[4]!).get! 0 &&
         (a[5]!).get! 0 == (b[5]!).get! 0 &&
         (a[6]!).get! 0 == (b[6]!).get! 0 &&
         (a[7]!).get! 0 == (b[7]!).get! 0
     | _, _ => false) = true := by
  native_decide

/-- Reconstruct after dropping data shards 0 and 1. -/
private def optsDrop01 : Array (Option ByteArray) :=
  match carbonadoRS.encode shardsLen1 with
  | .error _ => #[]
  | .ok enc =>
      #[none, none, some (enc[2]!), some (enc[3]!),
        some (enc[4]!), some (enc[5]!), some (enc[6]!), some (enc[7]!)]

theorem reconstruct_drop_data_01 :
    (match carbonadoRS.reconstruct optsDrop01 with
     | .error _ => false
     | .ok full =>
         (full[0]!).get! 0 == 1 &&
         (full[1]!).get! 0 == 2 &&
         (full[2]!).get! 0 == 3 &&
         (full[3]!).get! 0 == 4) = true := by
  native_decide

/-- Parity-only reconstruct (drop all four data shards). -/
private def optsParityOnly : Array (Option ByteArray) :=
  match carbonadoRS.encode shardsLen1 with
  | .error _ => #[]
  | .ok enc =>
      #[none, none, none, none,
        some (enc[4]!), some (enc[5]!), some (enc[6]!), some (enc[7]!)]

theorem reconstruct_parity_only :
    (match carbonadoRS.reconstruct optsParityOnly with
     | .error _ => false
     | .ok full =>
         (full[0]!).get! 0 == 1 &&
         (full[1]!).get! 0 == 2 &&
         (full[2]!).get! 0 == 3 &&
         (full[3]!).get! 0 == 4) = true := by
  native_decide

/-- Mixed knockout {0,2,5,7} via reconstructAfterKnockout (cheap len-1 shards). -/
private def encodedLen1 : Array ByteArray :=
  match carbonadoRS.encode shardsLen1 with
  | .error _ => #[]
  | .ok enc => enc

theorem reconstruct_mixed_knockout :
    (match reconstructAfterKnockout encodedLen1 [0, 2, 5, 7] 0 with
     | .error _ => false
     | .ok pt =>
         pt.size == 4 &&
         pt.get! 0 == 1 && pt.get! 1 == 2 && pt.get! 2 == 3 && pt.get! 3 == 4) = true := by
  native_decide

/-- Too few shards → `tooFewShards`. -/
theorem too_few_shards_error :
    isTooFew (carbonadoRS.reconstruct
      #[some (ofList [1]), some (ofList [2]), some (ofList [3]),
        none, none, none, none, none]) = true := by
  native_decide

/-- Empty present shard → `emptyShard`. -/
theorem empty_shard_error :
    isEmptyShard (carbonadoRS.reconstruct
      #[some ByteArray.empty, some (ofList [1]), some (ofList [2]),
        some (ofList [3]), none, none, none, none]) = true := by
  native_decide

/-- Uneven shard sizes → `incorrectShardSize`. -/
theorem incorrect_shard_size_error :
    isIncorrectSize (carbonadoRS.reconstruct
      #[some (ofList [1]), some (ofList [1, 2]), some (ofList [3]),
        some (ofList [4]), none, none, none, none]) = true := by
  native_decide

/-- Wrong shard count → `badGeometry`. -/
theorem bad_geometry_error :
    isBadGeometry (carbonadoRS.reconstruct
      #[some (ofList [1]), some (ofList [2])]) = true := by
  native_decide

/-- Uneven inboard body length → `unevenShards`. -/
theorem uneven_inboard_error :
    isUneven (decodeInboard (ofList [1, 2, 3]) 0) = true := by
  native_decide

/-- Padding larger than reconstructed data → `paddingTooLarge`. -/
theorem padding_too_large_error :
    (match carbonadoRS.encode shardsLen1 with
     | .error _ => false
     | .ok enc =>
         isPaddingTooLarge (stripPadding
           #[enc[0]!, enc[1]!, enc[2]!, enc[3]!] 5)) = true := by
  native_decide

/-- Zero matrix invert → `singularMatrix` (taxonomy surface; product RS rows stay invertible). -/
theorem singular_matrix_error :
    isSingular (invertOrSingular (Matrix.zeros 2 2)) = true := by
  native_decide

theorem singular_matrix_exact :
    (match invertOrSingular (Matrix.zeros 2 2) with
     | .error .singularMatrix => true
     | _ => false) = true :=
  invertOrSingular_zeros

/-- `ReedSolomon.new` zero data/parity → `badGeometry`. -/
theorem new_zero_data_badGeometry :
    isBadGeometry (ReedSolomon.new 0 4) = true := by
  native_decide

theorem new_zero_parity_badGeometry :
    isBadGeometry (ReedSolomon.new 4 0) = true := by
  native_decide

/-- Encode wrong shard count → `badGeometry`. -/
theorem encode_bad_geometry :
    isBadGeometry (carbonadoRS.encode #[ofList [1], ofList [2]]) = true := by
  native_decide

/-- Encode empty first shard → `emptyShard`. -/
theorem encode_empty_shard :
    isEmptyShard (carbonadoRS.encode
      #[ByteArray.empty, ofList [1], ofList [2], ofList [3],
        ofList [0], ofList [0], ofList [0], ofList [0]]) = true := by
  native_decide

/-- Encode mismatched lengths → `incorrectShardSize`. -/
theorem encode_incorrect_size :
    isIncorrectSize (carbonadoRS.encode
      #[ofList [1], ofList [1, 2], ofList [3], ofList [4],
        ofList [0], ofList [0], ofList [0], ofList [0]]) = true := by
  native_decide

/-- Out-of-range knockout index → `badGeometry`. -/
theorem knockout_oob_badGeometry :
    isBadGeometry (reconstructAfterKnockout encodedLen1 [0, 8] 0) = true := by
  native_decide

/-- Empty encode/decode roundtrip. -/
theorem empty_inboard_roundtrip :
    (match encodeInboard ByteArray.empty with
     | .ok (body, pad, chunk) =>
         body.size == 0 && pad == 0 && chunk == 0 &&
         (match decodeInboard body 0 with
          | .ok pt => pt.size == 0
          | _ => false)
     | _ => false) = true := by
  native_decide

/-- Small 8-byte sequential shard encode golden (pin crate). -/
private def shardsSeq8 : Array ByteArray :=
  #[ofList [0,1,2,3,4,5,6,7],
    ofList [8,9,10,11,12,13,14,15],
    ofList [16,17,18,19,20,21,22,23],
    ofList [24,25,26,27,28,29,30,31],
    ofList [0,0,0,0,0,0,0,0],
    ofList [0,0,0,0,0,0,0,0],
    ofList [0,0,0,0,0,0,0,0],
    ofList [0,0,0,0,0,0,0,0]]

theorem encode_seq8_parity0 :
    (match carbonadoRS.encode shardsSeq8 with
     | .error _ => false
     | .ok enc =>
         (enc[4]!).get! 0 == 0x20 &&
         (enc[4]!).get! 1 == 0x21 &&
         (enc[4]!).get! 7 == 0x27 &&
         (enc[7]!).get! 0 == 0x38 &&
         (enc[7]!).get! 7 == 0x3f) = true := by
  native_decide

/-- verify returns true on well-formed encode output. -/
theorem verify_good_len1 :
    (match carbonadoRS.encode shardsLen1 with
     | .error _ => false
     | .ok enc =>
         match carbonadoRS.verify enc with
         | .ok true => true
         | _ => false) = true := by
  native_decide

/-- verify returns false when a parity byte is flipped. -/
theorem verify_bad_parity_len1 :
    (match carbonadoRS.encode shardsLen1 with
     | .error _ => false
     | .ok enc =>
         let flipped := ofList [(enc[4]!).get! 0 ^^^ 0x01]
         let bad := enc.set! 4 flipped
         match carbonadoRS.verify bad with
         | .ok false => true
         | _ => false) = true := by
  native_decide

end CarbonadoTest.Fec
