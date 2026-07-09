/-
  Multi-segment sharding model (Program E).

  Matches Rust `stream/shard.rs` pure surface:
  * Split logical plaintext by `segmentPlaintextBudget`
  * Each segment encoded independently with `chunk_index` 0..n-1 bound under header_mac
  * Decode rebinds order from **verified** `header.chunkIndex` (not unauthenticated labels)
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Header
import Carbonado.Pipeline

namespace Carbonado.Shard

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Header
open Carbonado.Pipeline

/-- Default budget: u32::MAX = 2^32 - 1 (same bookkeeping ceiling as Rust). -/
def defaultSegmentPlaintextBudget : Nat := 4294967295

/-- One encoded shard (authenticated header + body).

  `chunkIndex` is a convenience label filled at encode time; **decode must not**
  trust it for ordering — use the verified Header inside `archive` instead.
-/
structure Shard where
  chunkIndex : UInt32
  header : Header
  /-- Full archive bytes: header wire || body. -/
  archive : ByteArray
  deriving DecidableEq, Inhabited

/-- Split plaintext into consecutive budget-sized segments (last may be short).

  `budget = 0` → empty list (caller should use a positive budget).
  Empty plaintext → single empty segment (one shard) so encode still produces chunk 0.
-/
def splitByBudget (plaintext : ByteArray) (budget : Nat) : Array ByteArray :=
  if budget == 0 then
    #[]
  else if plaintext.size == 0 then
    #[ByteArray.empty]
  else
    Id.run do
      let mut out : Array ByteArray := Array.mkEmpty ((plaintext.size + budget - 1) / budget)
      let mut off : Nat := 0
      while off < plaintext.size do
        let end_ := min (off + budget) plaintext.size
        out := out.push (plaintext.extract off end_)
        off := end_
      pure out

/--
  Encode multi-segment archive set.

  `nonces[i]` is the payload_nonce for segment `i` (header-path encrypt).
  Requires `nonces.size ≥` segment count after split.
  Too few nonces → `insufficientNonces` (not `invalidNonceLength`).
-/
def encodeShards (master plaintext : ByteArray) (format : FormatBits)
    (budget : Nat) (nonces : Array ByteArray)
    (slhPublicKey metadata : ByteArray) :
    Except PipelineError (Array Shard) :=
  let segments := splitByBudget plaintext budget
  if segments.size == 0 then
    .error .emptySegment
  else if nonces.size < segments.size then
    .error .insufficientNonces
  else
    Id.run do
      let mut out : Array Shard := Array.mkEmpty segments.size
      let mut err : Option PipelineError := none
      for i in [:segments.size] do
        if err.isNone then
          if i > u32Max then
            err := some .invalidFieldLength
          else
            let nonce := nonces[i]!
            let seg := segments[i]!
            match encodeHeadered master nonce seg format (UInt32.ofNat i) slhPublicKey metadata with
            | .error e => err := some e
            | .ok (hdr, archive) =>
              out := out.push {
                chunkIndex := UInt32.ofNat i
                header := hdr
                archive := archive
              }
      match err with
      | some e => pure (.error e)
      | none => pure (.ok out)

/-- Check indices form contiguous `0 .. n-1` (any order accepted after placement). -/
def validateChunkSequence (indices : Array UInt32) : Except PipelineError Unit :=
  if indices.size == 0 then
    .error .emptySegment
  else
    Id.run do
      let n := indices.size
      let mut seen : Array Bool := Array.mkEmpty n
      for _ in [:n] do
        seen := seen.push false
      let mut ok := true
      for i in [:n] do
        let idx := UInt32.toNat (indices[i]!)
        if idx ≥ n then
          ok := false
        else if seen[idx]! then
          ok := false
        else
          seen := seen.set! idx true
      for i in [:n] do
        if !seen[i]! then
          ok := false
      pure (if ok then .ok () else .error .invalidChunkSequence)

/--
  Decode shard set by **verified** header `chunk_index` under `header_mac`.

  Structure `Shard.chunkIndex` is ignored for ordering. If a non-empty external
  label is present and disagrees with the verified index, returns
  `invalidChunkSequence`. Concatenates plaintext in authenticated index order.
-/
def decodeShards (master : ByteArray) (shards : Array Shard) :
    Except PipelineError ByteArray :=
  if shards.size == 0 then
    .error .emptySegment
  else
    Id.run do
      let n := shards.size
      -- Decode each archive; collect (verifiedIndex, plaintext)
      let mut verifiedIndices : Array UInt32 := Array.mkEmpty n
      let mut plaintexts : Array ByteArray := Array.mkEmpty n
      let mut err : Option PipelineError := none
      for i in [:n] do
        if err.isNone then
          let s := shards[i]!
          match decodeHeaderedWithHeader master s.archive with
          | .error e => err := some e
          | .ok (hdr, pt) =>
            -- If structure label disagrees with authenticated index, fail.
            if s.chunkIndex != hdr.chunkIndex then
              err := some .invalidChunkSequence
            else
              verifiedIndices := verifiedIndices.push hdr.chunkIndex
              plaintexts := plaintexts.push pt
      match err with
      | some e => pure (.error e)
      | none =>
        match validateChunkSequence verifiedIndices with
        | .error e => pure (.error e)
        | .ok () =>
          -- Place plaintext by verified index
          let mut slots : Array (Option ByteArray) := Array.mkEmpty n
          for _ in [:n] do
            slots := slots.push none
          for i in [:n] do
            let idx := UInt32.toNat (verifiedIndices[i]!)
            slots := slots.set! idx (some (plaintexts[i]!))
          let mut out := ByteArray.empty
          let mut placeErr : Option PipelineError := none
          for i in [:n] do
            if placeErr.isNone then
              match slots[i]! with
              | none => placeErr := some .invalidChunkSequence
              | some pt => out := out.append pt
          match placeErr with
          | some e => pure (.error e)
          | none => pure (.ok out)

/-- Round-trip multi-segment encode/decode. -/
def roundtripShards (master plaintext : ByteArray) (format : FormatBits)
    (budget : Nat) (nonces : Array ByteArray) : Except PipelineError Bool :=
  match encodeShards master plaintext format budget nonces zeroSlhPk zeroMeta with
  | .error e => .error e
  | .ok shards =>
    match decodeShards master shards with
    | .error e => .error e
    | .ok pt => .ok (ctEq pt plaintext)

/-- Budget split theorems. -/
theorem split_empty_budget :
    (splitByBudget (ofList [1, 2, 3]) 0).size = 0 := by
  native_decide

theorem split_hello_budget_2 :
    (splitByBudget (utf8 "hello") 2).size = 3 := by
  native_decide

theorem split_empty_plaintext :
    (splitByBudget ByteArray.empty 10).size = 1 := by
  native_decide

end Carbonado.Shard
