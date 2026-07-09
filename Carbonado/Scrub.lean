/-
  Scrub: pure combinatorial FEC recovery + re-encode + keyed Bao root compare.

  Normative spirit (Rust `decoding::scrub`):
  * Requires Verification bit
  * Pristine inboard (Bao verifies) → `unnecessaryScrub`
  * Damaged: try subsets of FEC shards (≥ k present), reconstruct logical,
    re-encode FEC + Bao, accept first body whose root matches the oracle hash

  Pure model uses shard split of the **inboard FEC body** under the Bao artifact.
  When Verification is set, the on-disk body is Bao-inboard wrapping FEC bytes;
  scrub first peels Bao when possible via slice/extract. For the pure Lean model we
  support two entry points:
  1. `scrubFecBody` — FEC body already exposed (after successful partial extract)
  2. `scrubInboard` — full Bao+FEC inboard: try decode; on fail, brute-force over
     FEC-layer candidates obtained by re-encoding search from corrupted body
     interpreted as raw FEC concat when geometry matches

  For FEC+Verification formats the encode layout is Bao(FEC(data)). On damage,
  we search over RS subsets of the **inner** FEC body when the caller supplies it
  (`scrubFecThenBao`), which matches the Rust path after slice extract of chunks.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Fec.RS
import Carbonado.Fec.Inboard
import Carbonado.Bao.Product
import Carbonado.Pipeline

namespace Carbonado.Scrub

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Fec.RS
open Carbonado.Fec.Inboard
open Carbonado.Bao.Product
open Carbonado.Pipeline

/-- Popcount of a Nat mask (low 8 bits used). -/
def popcount8 (mask : Nat) : Nat :=
  Id.run do
    let mut c : Nat := 0
    for i in [:8] do
      if (mask >>> i) % 2 == 1 then
        c := c + 1
    pure c

/--
  Try one mask of present shard indices; reconstruct, re-encode FEC, re-Bao, compare root.
  Returns `some` recovered Bao-inboard body on success.

  Requires `shards.size = fecM` (caller must guard).
-/
def tryMask (shards : Array ByteArray) (padding : Nat) (formatByte : UInt8)
    (wantRoot : ByteArray) (mask : Nat) : Option ByteArray :=
  if shards.size != fecM then
    none
  else if popcount8 mask < fecK then
    none
  else
    Id.run do
      let mut opts : Array (Option ByteArray) := Array.mkEmpty fecM
      for i in [:fecM] do
        if (mask >>> i) % 2 == 1 then
          opts := opts.push (some (shards[i]!))
        else
          opts := opts.push none
      match reconstructLogical opts padding with
      | .error _ => pure none
      | .ok logical =>
        match Carbonado.Fec.Inboard.encodeInboard logical with
        | .error _ => pure none
        | .ok (fecBody, pad', _) =>
          if pad' != padding then
            pure none
          else
            let (root, art) := encodeInboardForFormat formatByte fecBody
            if ctEq root wantRoot then
              some art
            else
              none

/-- Search all 8-bit masks with ≥ k present shards. -/
def searchMasks (shards : Array ByteArray) (padding : Nat) (formatByte : UInt8)
    (wantRoot : ByteArray) : Option ByteArray :=
  if shards.size != fecM then
    none
  else
    Id.run do
      let mut found : Option ByteArray := none
      for mask in [:256] do
        if found.isNone then
          match tryMask shards padding formatByte wantRoot mask with
          | some art => found := some art
          | none => pure ()
      pure found

/-- Require exactly `fecM` shards (empty body from `inboardToShards` → badGeometry). -/
def requireFecShards (shards : Array ByteArray) : Except PipelineError Unit :=
  if shards.size != fecM then
    .error .badGeometry
  else
    .ok ()

/--
  Scrub from FEC inboard body (8-shard concat) + expected Bao root of re-encoded form.

  Used when FEC shards are already available (Rust: after slice extract).
  `wantRoot` is the keyed Bao root over the **FEC body** (same as archive hash when
  Verification wraps FEC only — i.e. format with V+FEC).
-/
def scrubFecThenBao (fecBody wantRoot : ByteArray) (padding : Nat) (formatByte : UInt8) :
    Except PipelineError ByteArray :=
  match inboardToShards fecBody with
  | .error e => .error (ofFecError e)
  | .ok shards =>
    match requireFecShards shards with
    | .error e => .error e
    | .ok () =>
      match searchMasks shards padding formatByte wantRoot with
      | some art => .ok art
      | none => .error .invalidScrubbedHash

/--
  Full scrub entry for Verification formats.

  * No verification bit → `scrubRequiresVerification`
  * Bao verifies → `unnecessaryScrub`
  * Else → `invalidScrubbedHash` (opaque Bao without FEC extract)
-/
def scrubInboardArchive (body wantRoot : ByteArray) (format : FormatBits) :
    Except PipelineError ByteArray :=
  if !format.verification then
    .error .scrubRequiresVerification
  else
    match decodeInboardForFormat format.toUInt8 wantRoot body with
    | .ok _ => .error .unnecessaryScrub
    | .error .authenticationFailed =>
      .error .invalidScrubbedHash
    | .error e => .error (ofBaoError e)

/--
  Scrub path for tests: zero-fill missing shard slots on the FEC body, then full mask search.

  Empty / short FEC body → `badGeometry` (no panic).
-/
def scrubAfterKnockout (fecBody wantRoot : ByteArray) (padding : Nat)
    (formatByte : UInt8) (missing : List Nat) : Except PipelineError ByteArray :=
  match inboardToShards fecBody with
  | .error e => .error (ofFecError e)
  | .ok shards =>
    match requireFecShards shards with
    | .error e => .error e
    | .ok () =>
      if missing.any (fun i => decide (i ≥ fecM)) then
        .error .badGeometry
      else
        Id.run do
          let mut damagedShards : Array ByteArray := Array.mkEmpty fecM
          for i in [:fecM] do
            if missing.contains i then
              damagedShards := damagedShards.push (replicate (shards[i]!).size 0)
            else
              damagedShards := damagedShards.push (shards[i]!)
          let damagedBody := concatShards damagedShards
          pure (scrubFecThenBao damagedBody wantRoot padding formatByte)

/-- Knockout recovery using only the complement of `missing` (no full-mask fallback).

  Returns `invalidScrubbedHash` when the chosen present set cannot reconstruct a body
  whose re-encoded Bao root matches `wantRoot` (e.g. more than 4 shards missing).
  Empty / short FEC body → `badGeometry` (no panic).
-/
def scrubWithMissing (fecBody wantRoot : ByteArray) (padding : Nat)
    (formatByte : UInt8) (missing : List Nat) : Except PipelineError ByteArray :=
  match inboardToShards fecBody with
  | .error e => .error (ofFecError e)
  | .ok shards =>
    match requireFecShards shards with
    | .error e => .error e
    | .ok () =>
      if missing.any (fun i => decide (i ≥ fecM)) then
        .error .badGeometry
      else
        Id.run do
          let mut mask : Nat := 0
          for i in [:fecM] do
            if !(missing.contains i) then
              mask := mask + (1 <<< i)
          match tryMask shards padding formatByte wantRoot mask with
          | some art => pure (.ok art)
          | none => pure (.error .invalidScrubbedHash)

end Carbonado.Scrub
