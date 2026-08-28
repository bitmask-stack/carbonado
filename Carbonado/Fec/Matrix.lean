/-
  Dense matrices over GF(2^8) for Reed–Solomon encoding matrices.

  Matches `reed-solomon-erasure` `matrix.rs`: Vandermonde, Gaussian elimination
  invert, multiply, augment, sub_matrix.
-/
import Carbonado.Fec.Galois

namespace Carbonado.Fec.Matrix

open Carbonado.Fec.Galois

/-- Row-major matrix of GF elements. -/
structure Matrix where
  rows : Nat
  cols : Nat
  /-- Flattened `rows * cols` elements, row-major. -/
  data : Array UInt8
  deriving Repr

def Matrix.get (m : Matrix) (r c : Nat) : UInt8 :=
  m.data[r * m.cols + c]!

def Matrix.set (m : Matrix) (r c : Nat) (v : UInt8) : Matrix :=
  { m with data := m.data.set! (r * m.cols + c) v }

def Matrix.zeros (rows cols : Nat) : Matrix :=
  { rows := rows, cols := cols, data := Array.replicate (rows * cols) 0 }

def Matrix.identity (size : Nat) : Matrix :=
  Id.run do
    let mut m := zeros size size
    for i in [:size] do
      m := m.set i i 1
    pure m

def Matrix.getRow (m : Matrix) (row : Nat) : Array UInt8 :=
  Id.run do
    let mut out : Array UInt8 := Array.mkEmpty m.cols
    for c in [:m.cols] do
      out := out.push (m.get row c)
    pure out

def Matrix.swapRows (m : Matrix) (r1 r2 : Nat) : Matrix :=
  if r1 == r2 then m
  else
    Id.run do
      let mut result := m
      for c in [:m.cols] do
        let a := result.get r1 c
        let b := result.get r2 c
        result := result.set r1 c b
        result := result.set r2 c a
      pure result

def Matrix.multiply (lhs rhs : Matrix) : Matrix :=
  Id.run do
    let mut result := zeros lhs.rows rhs.cols
    for r in [:lhs.rows] do
      for c in [:rhs.cols] do
        let mut val : UInt8 := 0
        for i in [:lhs.cols] do
          val := add val (mul (lhs.get r i) (rhs.get i c))
        result := result.set r c val
    pure result

def Matrix.augment (lhs rhs : Matrix) : Matrix :=
  Id.run do
    let mut result := zeros lhs.rows (lhs.cols + rhs.cols)
    for r in [:lhs.rows] do
      for c in [:lhs.cols] do
        result := result.set r c (lhs.get r c)
      for c in [:rhs.cols] do
        result := result.set r (lhs.cols + c) (rhs.get r c)
    pure result

def Matrix.subMatrix (m : Matrix) (rmin cmin rmax cmax : Nat) : Matrix :=
  Id.run do
    let mut result := zeros (rmax - rmin) (cmax - cmin)
    for r in [rmin:rmax] do
      for c in [cmin:cmax] do
        result := result.set (r - rmin) (c - cmin) (m.get r c)
    pure result

/-- Gaussian elimination to RREF (in-place style). Returns `none` if singular. -/
def Matrix.gaussianElim (m : Matrix) : Option Matrix :=
  Id.run do
    let mut work := m
    for r in [:work.rows] do
      if work.get r r == 0 then
        let mut found := false
        for rBelow in [r+1:work.rows] do
          if !found && work.get rBelow r != 0 then
            work := work.swapRows r rBelow
            found := true
      if work.get r r == 0 then
        return none
      if work.get r r != 1 then
        let scale := div 1 (work.get r r)
        for c in [:work.cols] do
          work := work.set r c (mul scale (work.get r c))
      for rBelow in [r+1:work.rows] do
        if work.get rBelow r != 0 then
          let scale := work.get rBelow r
          for c in [:work.cols] do
            let v := add (work.get rBelow c) (mul scale (work.get r c))
            work := work.set rBelow c v
    -- Clear above diagonal
    for d in [:work.rows] do
      for rAbove in [:d] do
        if work.get rAbove d != 0 then
          let scale := work.get rAbove d
          for c in [:work.cols] do
            let v := add (work.get rAbove c) (mul scale (work.get d c))
            work := work.set rAbove c v
    pure (some work)

/-- Invert a square matrix; `none` if singular. -/
def Matrix.invert (m : Matrix) : Option Matrix :=
  if m.rows != m.cols then
    none
  else
    let n := m.rows
    let work := m.augment (identity n)
    match work.gaussianElim with
    | none => none
    | some reduced => some (reduced.subMatrix 0 n n (n * 2))

/-- Vandermonde: `M[r,c] = nth(r)^c`. -/
def Matrix.vandermonde (rows cols : Nat) : Matrix :=
  Id.run do
    let mut result := zeros rows cols
    for r in [:rows] do
      let rA := nth r
      for c in [:cols] do
        result := result.set r c (exp rA c)
    pure result

/-- Systematic RS generator: `V * inv(top)`. -/
def Matrix.buildRSMatrix (dataShards totalShards : Nat) : Option Matrix :=
  let vandermonde := Matrix.vandermonde totalShards dataShards
  let top := vandermonde.subMatrix 0 0 dataShards dataShards
  match top.invert with
  | none => none
  | some invTop => some (vandermonde.multiply invTop)

end Carbonado.Fec.Matrix
