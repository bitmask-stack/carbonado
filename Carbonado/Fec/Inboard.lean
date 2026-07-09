/-
  Carbonado FEC geometry and inboard encode/decode.

  Normative (matches `src/utils.rs` + `src/stream/fec.rs`):
  * `stripeUnit = sliceLen * fecK = 16384`
  * `calc_padding_len` pads logical length up to a multiple of `stripeUnit`
  * chunk_len = padded_len / fecK
  * Inboard body = 8 concatenated shards of length `chunk_len`
  * Decode: split → reconstruct any 4/8 → concat data → strip padding

  Memory (LIMITS): encode/decode materialize O(stripe) = O(padded logical × 2)
  for a single segment-wide stripe (same residual as Rust FEC path).
-/
import Carbonado.Constants
import Carbonado.Fec.RS

namespace Carbonado.Fec.Inboard

open Carbonado.Constants
open Carbonado.Fec.RS

/-- Result of padding geometry: `(padding_len, chunk_len)`. -/
structure PaddingInfo where
  paddingLen : Nat
  chunkLen : Nat
  deriving DecidableEq, Repr

/--
  `calc_padding_len` — pad to a multiple of `stripeUnit` (`sliceLen * fecK`).

  Empty input → `(0, 0)`. Otherwise:
  `target = ceil(input / stripeUnit) * stripeUnit`,
  `padding = target - input`,
  `chunk = target / fecK`.
-/
def calcPaddingLen (inputLen : Nat) : PaddingInfo :=
  if inputLen == 0 then
    { paddingLen := 0, chunkLen := 0 }
  else
    let stripe := stripeUnit
    let target := ((inputLen + stripe - 1) / stripe) * stripe
    let paddingLen := target - inputLen
    let chunkLen := target / fecK
    { paddingLen := paddingLen, chunkLen := chunkLen }

/-- Padded length for a logical payload. -/
def paddedLen (inputLen : Nat) : Nat :=
  let p := calcPaddingLen inputLen
  if inputLen == 0 then 0 else inputLen + p.paddingLen

/-- Zero-extend `input` to `targetLen`. -/
def padWithZeros (input : ByteArray) (targetLen : Nat) : ByteArray :=
  if input.size ≥ targetLen then
    input.extract 0 targetLen
  else
    Id.run do
      let mut out := input
      for _ in [:targetLen - input.size] do
        out := out.push 0
      pure out

/-- Split a padded buffer into `fecK` data shards of `chunkLen`. -/
def splitDataShards (padded : ByteArray) (chunkLen : Nat) : Except FecError (Array ByteArray) :=
  if chunkLen == 0 then
    .error .badGeometry
  else if padded.size != chunkLen * fecK then
    .error .unevenShards
  else
    Id.run do
      let mut shards : Array ByteArray := Array.mkEmpty fecK
      for i in [:fecK] do
        shards := shards.push (padded.extract (i * chunkLen) ((i + 1) * chunkLen))
      pure (.ok shards)

/-- Concatenate shards in order. -/
def concatShards (shards : Array ByteArray) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    for i in [:shards.size] do
      out := out.append (shards[i]!)
    pure out

/-- Split inboard body into `fecM` equal shards. -/
def splitInboard (body : ByteArray) : Except FecError (Array ByteArray) :=
  if body.size == 0 then
    .ok #[]
  else if body.size % fecM != 0 then
    .error .unevenShards
  else
    -- body.size > 0 ∧ divisible by fecM ⇒ chunkLen ≥ 1
    let chunkLen := body.size / fecM
    Id.run do
      let mut shards : Array ByteArray := Array.mkEmpty fecM
      for i in [:fecM] do
        shards := shards.push (body.extract (i * chunkLen) ((i + 1) * chunkLen))
      pure (.ok shards)

/--
  Encode logical bytes to inboard FEC body.

  Returns `(inboard_body, padding_len, chunk_len)`.
  Empty input → empty body, zero geometry.
-/
def encodeInboard (input : ByteArray) : Except FecError (ByteArray × Nat × Nat) :=
  if input.size == 0 then
    .ok (ByteArray.empty, 0, 0)
  else
    let geo := calcPaddingLen input.size
    let target := input.size + geo.paddingLen
    let padded := padWithZeros input target
    match splitDataShards padded geo.chunkLen with
    | .error e => .error e
    | .ok dataShards =>
      Id.run do
        let mut shards : Array ByteArray := dataShards
        for _ in [:fecM - fecK] do
          shards := shards.push (padWithZeros ByteArray.empty geo.chunkLen)
        match carbonadoRS.encode shards with
        | .error e => pure (.error e)
        | .ok encoded =>
          pure (.ok (concatShards encoded, geo.paddingLen, geo.chunkLen))

/-- Concatenate first `fecK` data shards and strip `padding` trailing zeros. -/
def stripPadding (dataShards : Array ByteArray) (padding : Nat) : Except FecError ByteArray :=
  let cat := concatShards dataShards
  if padding > cat.size then
    .error .paddingTooLarge
  else
    .ok (cat.extract 0 (cat.size - padding))

/--
  Decode full inboard body (all 8 shards present) with encode-time padding length.
-/
def decodeInboard (body : ByteArray) (padding : Nat) : Except FecError ByteArray :=
  if body.size == 0 then
    if padding == 0 then .ok ByteArray.empty
    else .error .paddingTooLarge
  else
    match splitInboard body with
    | .error e => .error e
    | .ok shards =>
      Id.run do
        let mut opts : Array (Option ByteArray) := Array.mkEmpty fecM
        for i in [:shards.size] do
          opts := opts.push (some (shards[i]!))
        match carbonadoRS.reconstruct opts with
        | .error e => pure (.error e)
        | .ok full =>
          let mut data : Array ByteArray := Array.mkEmpty fecK
          for i in [:fecK] do
            data := data.push (full[i]!)
          pure (stripPadding data padding)

/--
  Reconstruct logical payload from optional shards (scrub / chaos path).

  Requires at least `fecK` present shards of equal non-zero length.
  `padding` is the encode-time padding to strip from reconstructed data.
-/
def reconstructLogical (shards : Array (Option ByteArray)) (padding : Nat) :
    Except FecError ByteArray :=
  if shards.size != fecM then
    .error .badGeometry
  else
    match carbonadoRS.reconstruct shards with
    | .error e => .error e
    | .ok full =>
      Id.run do
        let mut data : Array ByteArray := Array.mkEmpty fecK
        for i in [:fecK] do
          data := data.push (full[i]!)
        pure (stripPadding data padding)

/--
  Knock out (erase) shards at the given indices and reconstruct.

  Pure scrub helper without Bao: validates that any 4 of 8 suffice when
  the remaining shards are intact.

  Every index in `missing` must be `< fecM`; out-of-range indices → `badGeometry`
  (no silent ignore).
-/
def reconstructAfterKnockout (encoded : Array ByteArray) (missing : List Nat) (padding : Nat) :
    Except FecError ByteArray :=
  if encoded.size != fecM then
    .error .badGeometry
  else if missing.any (fun i => decide (i ≥ fecM)) then
    .error .badGeometry
  else
    Id.run do
      let mut opts : Array (Option ByteArray) := Array.mkEmpty fecM
      for i in [:fecM] do
        if missing.contains i then
          opts := opts.push none
        else
          opts := opts.push (some (encoded[i]!))
      pure (reconstructLogical opts padding)

/-- Split encoded inboard body into an array of 8 shards (for knockout tests). -/
def inboardToShards (body : ByteArray) : Except FecError (Array ByteArray) :=
  splitInboard body

/-- Geometry theorems: padding identity. -/
theorem calcPaddingLen_zero : calcPaddingLen 0 = { paddingLen := 0, chunkLen := 0 } := by
  native_decide

theorem calcPaddingLen_one :
    calcPaddingLen 1 = { paddingLen := 16383, chunkLen := 4096 } := by
  native_decide

theorem calcPaddingLen_stripe :
    calcPaddingLen 16384 = { paddingLen := 0, chunkLen := 4096 } := by
  native_decide

theorem calcPaddingLen_stripe_plus_one :
    calcPaddingLen 16385 = { paddingLen := 16383, chunkLen := 8192 } := by
  native_decide

theorem calcPaddingLen_100 :
    calcPaddingLen 100 = { paddingLen := 16284, chunkLen := 4096 } := by
  native_decide

/-- One slice (4096): pad three remaining slices of the stripe. -/
theorem calcPaddingLen_4096 :
    calcPaddingLen 4096 = { paddingLen := 12288, chunkLen := 4096 } := by
  native_decide

/-- Concrete padded lengths align to `stripeUnit` (product-relevant sizes). -/
theorem paddedLen_aligns_samples :
    (List.map paddedLen [1, 100, 4096, 16384, 16385]).all
      (fun p => p % stripeUnit == 0) = true := by
  native_decide

end Carbonado.Fec.Inboard
