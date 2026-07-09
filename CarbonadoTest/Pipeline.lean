/-
  Program E — pipeline, header, stream bounds, scrub, shard tests.

  Dependency direction: CarbonadoTest → Carbonado only.

  Coverage:
  * Path tests for product-reachable PipelineError variants (encode/decode/scrub/shard).
  * Map `rfl` theorems for lower-layer injections (of*Error).
  * Residual map-only variants not reachable without fabricated lower-layer inputs:
    tooFewShards, emptyShard, incorrectShardSize, singularMatrix,
    invalidSliceIndex, invalidSliceCount (documented in SPEC-MATRIX).
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Header
import Carbonado.Compress
import Carbonado.Pipeline
import Carbonado.Stream
import Carbonado.Scrub
import Carbonado.Shard
import Carbonado.Fec.Inboard
import Carbonado.Bao.Product
import CarbonadoTest.Scaffold

namespace CarbonadoTest.Pipeline

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Header
open Carbonado.Compress
open Carbonado.Pipeline
open Carbonado.Stream
open Carbonado.Scrub
open Carbonado.Shard
open Carbonado.Fec.Inboard
open Carbonado.Bao.Product

private def master42 : ByteArray := replicate 32 0x42
private def nonce11 : ByteArray := replicate 16 0x11

private def pat (n : Nat) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    for i in [:n] do
      out := out.push (UInt8.ofNat (i % 251))
    pure out

/-! ## Stream bounds -/

theorem full_stripe_inboard : inboardStripeBytes stripeUnit = 2 * stripeUnit :=
  full_stripe_inboard_len

theorem full_stripe_ret : maxFecStripeRetain stripeUnit = 2 * stripeUnit :=
  full_stripe_retain

theorem empty_ret : maxFecStripeRetain 0 = 0 := empty_stripe_retain

theorem one_byte_ret : maxFecStripeRetain 1 = 32768 := one_byte_stripe_retain

theorem stripe_k_slices : stripeBytes = fecK * sliceLen := stripe_eq_k_slices

/-! ## Shard split -/

theorem split_budget_0 : (splitByBudget (ofList [1, 2, 3]) 0).size = 0 :=
  split_empty_budget

theorem split_hello_2 : (splitByBudget (utf8 "hello") 2).size = 3 :=
  split_hello_budget_2

theorem split_empty_pt : (splitByBudget ByteArray.empty 10).size = 1 :=
  split_empty_plaintext

/-! ## Header auth_data length -/

theorem auth_data_113 :
    magicBytes.length + nonceLen + hashLen + slhPublicKeyLen + 1 + 4 + 4 + 4 + 8 = 113 :=
  authData_len_formula

/-! ## Format matrix roundtrips (native_decide on small payloads) -/

theorem roundtrip_c0_hello :
    (match roundtripBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 0) with
     | .ok b => b
     | .error _ => false) = true := by
  native_decide

theorem roundtrip_c4_hello :
    (match roundtripBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 4) with
     | .ok b => b
     | .error _ => false) = true := by
  native_decide

theorem roundtrip_c5_hello :
    (match roundtripBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 5) with
     | .ok b => b
     | .error _ => false) = true := by
  native_decide

theorem roundtrip_c12_hello :
    (match roundtripBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 12) with
     | .ok b => b
     | .error _ => false) = true := by
  native_decide

/-- c13 = encrypted|verification|fec (no compression bit) — pure-decidable. -/
theorem roundtrip_c13_hello :
    (match roundtripBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 13) with
     | .ok b => b
     | .error _ => false) = true := by
  native_decide

/--
  Non-compression format matrix (c0,c1,c4,c5,c8,c9,c12,c13).
  Compression formats (bit 2) require AOT zstd `@[extern]` — gated in Main `demo`
  (c2/c6/c14/c15), not `native_decide` (LIMITS).
-/
private def nonCompressionFormats : List FormatBits :=
  [FormatBits.ofUInt8 0, FormatBits.ofUInt8 1, FormatBits.ofUInt8 4, FormatBits.ofUInt8 5,
   FormatBits.ofUInt8 8, FormatBits.ofUInt8 9, FormatBits.ofUInt8 12, FormatBits.ofUInt8 13]

private def nonCompressionMatrix (master nonce plaintext : ByteArray) : Bool :=
  Id.run do
    let mut allMatch := true
    for fmt in nonCompressionFormats do
      match roundtripBody master nonce plaintext fmt with
      | .error _ => allMatch := false
      | .ok b => if !b then allMatch := false
    pure allMatch

theorem format_matrix_no_compress_hi :
    nonCompressionMatrix master42 nonce11 (utf8 "hi") = true := by
  native_decide

theorem headered_c5_hello :
    (match roundtripHeadered master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 5) with
     | .ok b => b
     | .error _ => false) = true := by
  native_decide

/-! ## Header wire length -/

theorem header_new_wire_177 :
    (match Header.new master42 nonce11 (replicate 32 0xcd) (replicate 32 0) 5 0 100 0
        (replicate 8 0) with
     | .error _ => 0
     | .ok h =>
       match h.toBytes with
       | .ok b => b.size
       | .error _ => 0) = 177 := by
  native_decide

theorem header_verify_good :
    (match Header.new master42 nonce11 (replicate 32 0xcd) (replicate 32 0) 5 0 100 0
        (replicate 8 0) with
     | .error _ => false
     | .ok h =>
       match h.toBytes with
       | .error _ => false
       | .ok b =>
         match parseAndVerify master42 b with
         | .ok _ => true
         | .error _ => false) = true := by
  native_decide

/-! ## Strict PipelineError mapping (every variant reachable / distinct) -/

theorem map_header_invalid_len :
    ofHeaderError .invalidHeaderLength = .invalidHeaderLength := rfl

theorem map_header_bad_magic :
    ofHeaderError .badMagic = .badMagic := rfl

theorem map_header_auth :
    ofHeaderError .headerAuthenticationFailed = .headerAuthenticationFailed := rfl

theorem map_header_key :
    ofHeaderError .invalidKeyLength = .invalidKeyLength := rfl

theorem map_header_field :
    ofHeaderError .invalidFieldLength = .invalidFieldLength := rfl

theorem map_crypto_key :
    ofCryptoError .invalidKeyLength = .invalidKeyLength := rfl

theorem map_crypto_ct :
    ofCryptoError .invalidCiphertextLength = .invalidCiphertextLength := rfl

theorem map_crypto_nonce :
    ofCryptoError .invalidNonceLength = .invalidNonceLength := rfl

theorem map_crypto_auth :
    ofCryptoError .authenticationFailed = .payloadAuthenticationFailed := rfl

theorem map_fec_uneven :
    ofFecError .unevenShards = .unevenShards := rfl

theorem map_fec_too_few :
    ofFecError .tooFewShards = .tooFewShards := rfl

theorem map_fec_empty :
    ofFecError .emptyShard = .emptyShard := rfl

theorem map_fec_size :
    ofFecError .incorrectShardSize = .incorrectShardSize := rfl

theorem map_fec_geo :
    ofFecError .badGeometry = .badGeometry := rfl

theorem map_fec_pad :
    ofFecError .paddingTooLarge = .paddingTooLarge := rfl

theorem map_fec_sing :
    ofFecError .singularMatrix = .singularMatrix := rfl

theorem map_bao_auth :
    ofBaoError .authenticationFailed = .baoAuthenticationFailed := rfl

theorem map_bao_trunc :
    ofBaoError .truncatedResponse = .truncatedResponse := rfl

theorem map_bao_trail :
    ofBaoError .trailingData = .trailingData := rfl

theorem map_bao_prefix :
    ofBaoError .invalidPrefix = .invalidPrefix := rfl

theorem map_bao_root :
    ofBaoError .invalidRootLength = .invalidRootLength := rfl

theorem map_bao_slice_idx :
    ofBaoError .invalidSliceIndex = .invalidSliceIndex := rfl

theorem map_bao_slice_cnt :
    ofBaoError .invalidSliceCount = .invalidSliceCount := rfl

theorem map_zstd_compress :
    ofZstdError ZstdError.compressionFailed = PipelineError.compressionFailed := rfl

theorem map_zstd_decompress :
    ofZstdError ZstdError.decompressionFailed = PipelineError.decompressionFailed := rfl

theorem map_zstd_too_large :
    ofZstdError ZstdError.outputTooLarge = PipelineError.decompressOutputTooLarge := rfl

theorem map_zstd_invalid :
    ofZstdError ZstdError.invalidInput = PipelineError.zstdInvalidInput := rfl

/-! ## Pipeline error paths (exact match) -/

theorem short_header_decode :
    (match decodeHeadered master42 (ofList [1, 2, 3]) with
     | .error .invalidHeaderLength => true
     | _ => false) = true := by
  native_decide

theorem bad_magic_decode :
    (match parseAndVerify master42 (replicate headerLen 0) with
     | .error .badMagic => true
     | _ => false) = true := by
  native_decide

theorem bad_nonce_encrypt :
    (match encodeBody master42 (replicate 8 0) (utf8 "hi") (FormatBits.ofUInt8 1) false with
     | .error .invalidNonceLength => true
     | _ => false) = true := by
  native_decide

theorem short_master_encrypt :
    (match encodeBody (replicate 16 0) nonce11 (utf8 "hi") (FormatBits.ofUInt8 1) false with
     | .error .invalidKeyLength => true
     | _ => false) = true := by
  native_decide

theorem scrub_requires_v :
    (match scrubInboardArchive (utf8 "x") (replicate 32 0) (FormatBits.ofUInt8 0) with
     | .error .scrubRequiresVerification => true
     | _ => false) = true := by
  native_decide

theorem empty_segment_err :
    (match encodeShards master42 (utf8 "ab") (FormatBits.ofUInt8 0) 0 #[nonce11]
        zeroSlhPk zeroMeta with
     | .error .emptySegment => true
     | _ => false) = true := by
  native_decide

theorem invalid_chunk_seq :
    (match validateChunkSequence #[0, 0] with
     | .error .invalidChunkSequence => true
     | _ => false) = true := by
  native_decide

theorem invalid_field_header :
    (match Header.new master42 nonce11 (ofList [1]) (replicate 32 0) 0 0 0 0 (replicate 8 0) with
     | .error .invalidFieldLength => true
     | _ => false) = true := by
  native_decide

/-- Short body vs authenticated encoded_len → truncatedBody. -/
theorem truncated_body_path :
    (match encodeHeadered master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 0) 0
        zeroSlhPk zeroMeta with
     | .error _ => false
     | .ok (_h, arch) =>
       if arch.size ≤ headerLen + 1 then false
       else
         match decodeHeadered master42 (arch.extract 0 (headerLen + 1)) with
         | .error .truncatedBody => true
         | _ => false) = true := by
  native_decide

/-- Trailer after encoded_len ignored (c0). -/
theorem trailer_ignored_c0 :
    (match encodeHeadered master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 0) 0
        zeroSlhPk zeroMeta with
     | .error _ => false
     | .ok (_h, arch) =>
       match decodeHeadered master42 (appendBA arch (ofList [0xaa, 0xbb])) with
       | .ok pt => ctEq pt (utf8 "hello")
       | .error _ => false) = true := by
  native_decide

/-- Composition: short encrypted blob → invalidCiphertextLength. -/
theorem short_ct_composition :
    (match decodeBody master42 nonce11 zeroHash (replicate 10 0) 0
        (FormatBits.ofUInt8 1) false with
     | .error .invalidCiphertextLength => true
     | _ => false) = true := by
  native_decide

/-- Composition: FEC pad > empty body → paddingTooLarge. -/
theorem padding_too_large_composition :
    (match decodeBody master42 nonce11 zeroHash ByteArray.empty 5
        (FormatBits.ofUInt8 8) false with
     | .error .paddingTooLarge => true
     | _ => false) = true := by
  native_decide

/-- Composition: short Bao prefix → invalidPrefix. -/
theorem invalid_prefix_composition :
    (match encodeBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 4) false with
     | .error _ => false
     | .ok enc =>
       match decodeBody master42 nonce11 enc.baoHash (enc.body.extract 0 4)
           enc.info.paddingLen (FormatBits.ofUInt8 4) false with
       | .error .invalidPrefix => true
       | _ => false) = true := by
  native_decide

/-- Scrub knockout recovery for hello under c12 (V|F). -/
theorem scrub_knockout_hello :
    (match Carbonado.Fec.Inboard.encodeInboard (utf8 "hello") with
     | .error _ => false
     | .ok (fecBody, pad, _) =>
       let (root, art) := encodeInboardForFormat 12 fecBody
       match scrubWithMissing fecBody root pad 12 [0, 1, 2, 3] with
       | .ok rec => ctEq rec art
       | .error _ => false) = true := by
  native_decide

/-- Too many missing shards → invalidScrubbedHash (path test). -/
theorem scrub_invalid_hash_too_many :
    (match Carbonado.Fec.Inboard.encodeInboard (utf8 "hello") with
     | .error _ => false
     | .ok (fecBody, pad, _) =>
       let (root, _) := encodeInboardForFormat 12 fecBody
       match scrubWithMissing fecBody root pad 12 [0, 1, 2, 3, 4] with
       | .error .invalidScrubbedHash => true
       | _ => false) = true := by
  native_decide

/-- Empty FEC body scrub → badGeometry (no panic). -/
theorem scrub_empty_bad_geometry :
    (match scrubWithMissing ByteArray.empty (replicate 32 0) 0 12 [0] with
     | .error .badGeometry => true
     | _ => false) = true := by
  native_decide

/-- Unnecessary scrub when archive is pristine. -/
theorem scrub_pristine_unnecessary :
    (match encodeBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 4) false with
     | .error _ => false
     | .ok enc =>
       match scrubInboardArchive enc.body enc.baoHash (FormatBits.ofUInt8 4) with
       | .error .unnecessaryScrub => true
       | _ => false) = true := by
  native_decide

/-- Shards roundtrip small budget. -/
theorem shards_roundtrip :
    (match roundtripShards master42 (utf8 "abcdefghij") (FormatBits.ofUInt8 0) 4
        #[nonce11, replicate 16 0x22, replicate 16 0x33] with
     | .ok b => b
     | .error _ => false) = true := by
  native_decide

/-- Too few nonces → insufficientNonces (not invalidNonceLength). -/
theorem insufficient_nonces_path :
    (match encodeShards master42 (utf8 "abcdefghij") (FormatBits.ofUInt8 0) 4
        #[nonce11] zeroSlhPk zeroMeta with
     | .error .insufficientNonces => true
     | _ => false) = true := by
  native_decide

/-- Encrypted formats use odd codes. -/
theorem c15_odd : formatC15.toUInt8 % 2 = 1 := by native_decide

theorem c14_even : formatC14.toUInt8 % 2 = 0 := by native_decide

end CarbonadoTest.Pipeline
