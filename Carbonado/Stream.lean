/-
  Pure stream / buffer-bounds model for Carbonado pipeline stages (Program E).

  This is **not** an async IO runtime. It records the chunk/stripe geometry the
  product uses so buffer ceilings are explicit and (where practical) proved.

  Memory axes (do not conflate — AGENTS.md):
  * Streaming / memory: O(chunk) spool residual; **O(stripe)** FEC residual
  * Bao slice stream decode: O(response) (Program D)
  * Parallelism / async: out of scope here
-/
import Carbonado.Constants
import Carbonado.Fec.Inboard
import Carbonado.Pipeline

namespace Carbonado.Stream

open Carbonado.Constants
open Carbonado.Fec.Inboard
open Carbonado.Pipeline

/-- One logical stripe unit (16 KiB plaintext before FEC expansion). -/
def stripeBytes : Nat := stripeUnit

/-- Bytes retained for one full inboard FEC stripe after encode (8 × chunk).

  For a full stripe of `stripeUnit` logical bytes: chunk = 4096, body = 32768 = 2×stripe.
-/
def inboardStripeBytes (logicalLen : Nat) : Nat :=
  let geo := calcPaddingLen logicalLen
  if logicalLen == 0 then 0 else geo.chunkLen * fecM

/-- Maximum retained buffer for a single-stripe FEC encode/decode residual. -/
def maxFecStripeRetain (logicalLen : Nat) : Nat :=
  inboardStripeBytes logicalLen

/-- Chunk / leaf size (4 KiB) for non-FEC streaming geometry. -/
def chunkBytes : Nat := sliceLen

/--
  Pure stripe transducer: map each `stripeUnit`-sized logical window through `f`.

  Concatenates results. Used as the abstract model of streaming FEC encode
  (product may implement multi-stripe later; single-segment residual is O(stripe)).
-/
def mapStripes (input : ByteArray) (f : ByteArray → Except PipelineError ByteArray) :
    Except PipelineError ByteArray :=
  if input.size == 0 then
    .ok ByteArray.empty
  else
    Id.run do
      let mut out := ByteArray.empty
      let mut off : Nat := 0
      let mut err : Option PipelineError := none
      while off < input.size && err.isNone do
        let end_ := min (off + stripeUnit) input.size
        let piece := input.extract off end_
        match f piece with
        | .error e => err := some e
        | .ok part => out := out.append part
        off := end_
      match err with
      | some e => pure (.error e)
      | none => pure (.ok out)

/-- Encode one logical window with FEC inboard (stripe residual). -/
def encodeFecStripe (window : ByteArray) : Except PipelineError ByteArray :=
  match Carbonado.Fec.Inboard.encodeInboard window with
  | .error e => .error (ofFecError e)
  | .ok (body, _, _) => .ok body

/-- Full multi-stripe FEC encode model (concat of per-stripe inboards).

  Note: Rust product currently uses segment-wide RS geometry (one pad for whole
  body). This multi-stripe model documents the streaming bound alternative;
  pipeline `encodeBody` still uses segment-wide `encodeInboard` for parity.
-/
def encodeFecStriped (input : ByteArray) : Except PipelineError ByteArray :=
  mapStripes input encodeFecStripe

/-- Bound: one full stripe expands to exactly `2 * stripeUnit` inboard bytes. -/
theorem full_stripe_inboard_len :
    inboardStripeBytes stripeUnit = 2 * stripeUnit := by
  native_decide

/-- Bound: one full stripe retain ceiling equals inboard length. -/
theorem full_stripe_retain :
    maxFecStripeRetain stripeUnit = 2 * stripeUnit := by
  native_decide

/-- Empty input retains nothing. -/
theorem empty_stripe_retain : maxFecStripeRetain 0 = 0 := by
  native_decide

/-- Single-byte logical pad geometry → one stripe of retain 32768. -/
theorem one_byte_stripe_retain :
    maxFecStripeRetain 1 = 32768 := by
  native_decide

/-- Chunk bound for non-FEC leaf processing is `sliceLen`. -/
theorem chunk_eq_slice : chunkBytes = sliceLen := rfl

/-- Stripe unit is `fecK` leaves. -/
theorem stripe_eq_k_slices : stripeBytes = fecK * sliceLen := by
  native_decide

end Carbonado.Stream
