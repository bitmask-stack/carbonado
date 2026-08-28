/-
  Reed–Solomon erasure codec over GF(2^8), matching `reed-solomon-erasure` 5.0.3.

  Carbonado uses k=4 data + 4 parity (n=8). Encode fills parity from data;
  reconstruct recovers missing shards from any k present shards.
-/
import Carbonado.Constants
import Carbonado.Fec.Galois
import Carbonado.Fec.Matrix

namespace Carbonado.Fec.RS

open Carbonado.Constants
open Carbonado.Fec.Galois
open Carbonado.Fec.Matrix

/-- Strict FEC error taxonomy (distinct failure modes; match exactly in tests). -/
inductive FecError where
  /-- Input length does not divide evenly over shard count / stripe geometry. -/
  | unevenShards
  /-- Fewer than `dataShards` present shards for reconstruct. -/
  | tooFewShards
  /-- A present shard has zero length. -/
  | emptyShard
  /-- Present shards disagree on length. -/
  | incorrectShardSize
  /-- Wrong number of shards for the codec (not k+parity), or invalid knockout indices. -/
  | badGeometry
  /-- Padding length exceeds reconstructed data length. -/
  | paddingTooLarge
  /-- RS matrix inversion failed (singular submatrix). Unreachable for valid RS(4,4)
      with any k distinct generator rows; tested via `invertOrSingular` on singular matrices. -/
  | singularMatrix
  deriving DecidableEq, Repr

/-- Reed–Solomon codec parameters + precomputed systematic generator matrix. -/
structure ReedSolomon where
  dataShards : Nat
  parityShards : Nat
  /-- `totalShards × dataShards` systematic generator (top is identity). -/
  matrix : Matrix
  deriving Repr

def ReedSolomon.totalShards (rs : ReedSolomon) : Nat :=
  rs.dataShards + rs.parityShards

/-- Invert a matrix, mapping singular → `FecError.singularMatrix` (strict taxonomy surface). -/
def invertOrSingular (m : Matrix) : Except FecError Matrix :=
  match m.invert with
  | none => .error .singularMatrix
  | some inv => .ok inv

/-- Construct a codec. Fails on zero data/parity or total > 256. -/
def ReedSolomon.new (dataShards parityShards : Nat) : Except FecError ReedSolomon :=
  if dataShards == 0 || parityShards == 0 then
    .error .badGeometry
  else if dataShards + parityShards > order then
    .error .badGeometry
  else
    let total := dataShards + parityShards
    match Matrix.buildRSMatrix dataShards total with
    | none => .error .singularMatrix
    | some m =>
      .ok {
        dataShards := dataShards
        parityShards := parityShards
        matrix := m
      }

/-- Product codec construction (uses Constants geometry; no silent zero-matrix fallback). -/
def carbonadoRSExcept : Except FecError ReedSolomon :=
  ReedSolomon.new fecK (fecM - fecK)

/-- Product RS(4,4) constructs successfully (native). -/
theorem carbonadoRS_constructs :
    (match carbonadoRSExcept with | .ok _ => true | .error _ => false) = true := by
  native_decide

/--
  Carbonado product codec: RS(`fecK`, `fecM - fecK`) → 8 total shards.

  Error branch is eliminated by `carbonadoRS_constructs` — never substitutes a
  zero generator matrix (review issue #1).
-/
def carbonadoRS : ReedSolomon :=
  match h : carbonadoRSExcept with
  | .ok rs => rs
  | .error _ =>
    False.elim <| by
      have ht : (match carbonadoRSExcept with | .ok _ => true | .error _ => false) = true :=
        carbonadoRS_constructs
      simp only [h] at ht
      exact Bool.noConfusion ht

/-- Codec geometry matches `Constants.fecK` / `fecM`. -/
theorem carbonadoRS_geometry :
    carbonadoRS.dataShards = fecK ∧ carbonadoRS.parityShards = fecM - fecK := by
  native_decide

/-- Zero-filled ByteArray of length `n`. -/
private def zerosBA (n : Nat) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    for _ in [:n] do
      out := out.push 0
    pure out

/-- Encode parity into the last `parityShards` of `shards` (data in first k). -/
def ReedSolomon.encode (rs : ReedSolomon) (shards : Array ByteArray) :
    Except FecError (Array ByteArray) :=
  -- `ReedSolomon.new` requires dataShards ≥ 1 and parityShards ≥ 1 ⇒ totalShards ≥ 2.
  if shards.size != rs.totalShards then
    .error .badGeometry
  else
    let shardLen := (shards[0]!).size
    if shardLen == 0 then
      .error .emptyShard
    else
      Id.run do
        let mut ok := true
        for i in [:shards.size] do
          if (shards[i]!).size != shardLen then
            ok := false
        if !ok then
          pure (.error .incorrectShardSize)
        else
          let mut out := shards
          for p in [:rs.parityShards] do
            let row := rs.dataShards + p
            let mut parity := zerosBA shardLen
            for iData in [:rs.dataShards] do
              let coeff := rs.matrix.get row iData
              let data := out[iData]!
              if iData == 0 then
                parity := mulSliceBA coeff data
              else
                parity := mulSliceAddBA coeff data parity
            out := out.set! (rs.dataShards + p) parity
          pure (.ok out)

/-- Collect present-shard length; enforce non-empty + uniform. -/
private def presentShardLen (shards : Array (Option ByteArray)) :
    Except FecError Nat :=
  Id.run do
    let mut found : Option Nat := none
    for i in [:shards.size] do
      match shards[i]! with
      | none => pure ()
      | some s =>
        if s.size == 0 then
          return .error .emptyShard
        match found with
        | none => found := some s.size
        | some n =>
          if s.size != n then
            return .error .incorrectShardSize
    match found with
    | none => pure (.error .tooFewShards)
    | some n => pure (.ok n)

/-- Reconstruct all shards (data + parity) from any `dataShards` present. -/
def ReedSolomon.reconstruct (rs : ReedSolomon) (shards : Array (Option ByteArray)) :
    Except FecError (Array ByteArray) :=
  if shards.size != rs.totalShards then
    .error .badGeometry
  else
    match presentShardLen shards with
    | .error e => .error e
    | .ok shardLen =>
      Id.run do
        let mut numberPresent := 0
        for i in [:shards.size] do
          if (shards[i]!).isSome then
            numberPresent := numberPresent + 1
        if numberPresent < rs.dataShards then
          pure (.error .tooFewShards)
        else if numberPresent == rs.totalShards then
          let mut out : Array ByteArray := Array.mkEmpty rs.totalShards
          for i in [:shards.size] do
            out := out.push (shards[i]!).get!
          pure (.ok out)
        else
          let mut validIndices : Array Nat := Array.mkEmpty rs.dataShards
          let mut invalidIndices : Array Nat := Array.mkEmpty rs.dataShards
          let mut subShards : Array ByteArray := Array.mkEmpty rs.dataShards
          for matrixRow in [:rs.totalShards] do
            match shards[matrixRow]! with
            | some s =>
              if validIndices.size < rs.dataShards then
                validIndices := validIndices.push matrixRow
                subShards := subShards.push s
            | none =>
              invalidIndices := invalidIndices.push matrixRow
          let mut sub := Matrix.zeros rs.dataShards rs.dataShards
          for subRow in [:rs.dataShards] do
            let validIndex := validIndices[subRow]!
            for c in [:rs.dataShards] do
              sub := sub.set subRow c (rs.matrix.get validIndex c)
          match invertOrSingular sub with
          | .error e => pure (.error e)
          | .ok dataDecode =>
            let mut out : Array ByteArray := Array.mkEmpty rs.totalShards
            for i in [:rs.totalShards] do
              match shards[i]! with
              | some s => out := out.push s
              | none => out := out.push (zerosBA shardLen)
            for invIdx in [:invalidIndices.size] do
              let iSlice := invalidIndices[invIdx]!
              if iSlice < rs.dataShards then
                let row := dataDecode.getRow iSlice
                let mut decoded := zerosBA shardLen
                for iData in [:rs.dataShards] do
                  let coeff := row[iData]!
                  let src := subShards[iData]!
                  if iData == 0 then
                    decoded := mulSliceBA coeff src
                  else
                    decoded := mulSliceAddBA coeff src decoded
                out := out.set! iSlice decoded
            let mut dataOnly : Array ByteArray := Array.mkEmpty rs.dataShards
            for i in [:rs.dataShards] do
              dataOnly := dataOnly.push (out[i]!)
            for invIdx in [:invalidIndices.size] do
              let iSlice := invalidIndices[invIdx]!
              if iSlice ≥ rs.dataShards then
                let p := iSlice - rs.dataShards
                let mut parity := zerosBA shardLen
                for iData in [:rs.dataShards] do
                  let coeff := rs.matrix.get (rs.dataShards + p) iData
                  let src := dataOnly[iData]!
                  if iData == 0 then
                    parity := mulSliceBA coeff src
                  else
                    parity := mulSliceAddBA coeff src parity
                out := out.set! iSlice parity
            pure (.ok out)

/-- Reconstruct data shards only. -/
def ReedSolomon.reconstructData (rs : ReedSolomon) (shards : Array (Option ByteArray)) :
    Except FecError (Array ByteArray) :=
  match rs.reconstruct shards with
  | .error e => .error e
  | .ok full =>
    Id.run do
      let mut data : Array ByteArray := Array.mkEmpty rs.dataShards
      for i in [:rs.dataShards] do
        data := data.push (full[i]!)
      pure (.ok data)

/-- Verify parity matches data under this codec. -/
def ReedSolomon.verify (rs : ReedSolomon) (shards : Array ByteArray) : Except FecError Bool :=
  if shards.size != rs.totalShards then
    .error .badGeometry
  else
    match rs.encode shards with
    | .error e => .error e
    | .ok encoded =>
      Id.run do
        let mut ok := true
        for p in [:rs.parityShards] do
          let i := rs.dataShards + p
          let a := encoded[i]!
          let b := shards[i]!
          if a.size != b.size then
            ok := false
          else
            for j in [:a.size] do
              if a.get! j != b.get! j then
                ok := false
        pure (.ok ok)

/-- Singular 2×2 zero matrix maps to `singularMatrix` (taxonomy surface for invert). -/
theorem invertOrSingular_zeros :
    (match invertOrSingular (Matrix.zeros 2 2) with
     | .error .singularMatrix => true
     | _ => false) = true := by
  native_decide

/-- Identity inverts cleanly. -/
theorem invertOrSingular_identity :
    (match invertOrSingular (Matrix.identity 2) with
     | .ok m => m.get 0 0 == 1 && m.get 1 1 == 1
     | .error _ => false) = true := by
  native_decide

end Carbonado.Fec.RS
