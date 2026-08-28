/-
  GF(2^8) arithmetic matching `reed-solomon-erasure` 5.0.3 (`galois_8`).

  Generating polynomial = 29 (0x1d), same as the crate's `build.rs`.
  Log/exp tables are built with the same algorithm so mul/div/exp bit-match.
-/

namespace Carbonado.Fec.Galois

/-- Field order. -/
def order : Nat := 256

/-- Generating polynomial used by reed-solomon-erasure (AES poly 0x1d). -/
def generatingPolynomial : Nat := 29

/-- Build LOG_TABLE[b] = discrete log of `b` (log of 0 is left 0). -/
def genLogTable : Array UInt8 :=
  Id.run do
    let mut result : Array UInt8 := Array.replicate 256 (0 : UInt8)
    let mut b : Nat := 1
    for log in [:255] do
      result := result.set! b (UInt8.ofNat log)
      b := b <<< 1
      if b ≥ 256 then
        b := (b - 256).xor generatingPolynomial
    pure result

/-- Build EXP_TABLE of length 510: dual copy so mul can index `log_a + log_b` without mod. -/
def genExpTable (logTable : Array UInt8) : Array UInt8 :=
  Id.run do
    let mut result : Array UInt8 := Array.replicate 510 (0 : UInt8)
    for i in [1:256] do
      let log := (logTable[i]!).toNat
      let v := UInt8.ofNat i
      result := result.set! log v
      result := result.set! (log + 255) v
    pure result

/-- Discrete-log table (index 0 unused / zero). -/
def logTable : Array UInt8 := genLogTable

/-- Antilog table (size 510). -/
def expTable : Array UInt8 := genExpTable logTable

/-- Addition = XOR. -/
@[inline] def add (a b : UInt8) : UInt8 := a ^^^ b

/-- Subtraction = XOR (characteristic 2). -/
@[inline] def sub (a b : UInt8) : UInt8 := a ^^^ b

/-- Multiplication via log/exp tables. -/
def mul (a b : UInt8) : UInt8 :=
  if a == 0 || b == 0 then
    0
  else
    let la := (logTable[a.toNat]!).toNat
    let lb := (logTable[b.toNat]!).toNat
    expTable[la + lb]!

/-- Division via log/exp. Divisor must be non-zero (caller invariant). -/
def div (a b : UInt8) : UInt8 :=
  if a == 0 then
    0
  else
    let la := (logTable[a.toNat]!).toNat
    let lb := (logTable[b.toNat]!).toNat
    let logResult : Int := (Int.ofNat la) - (Int.ofNat lb)
    let logResult := if logResult < 0 then logResult + 255 else logResult
    expTable[logResult.toNat]!

/-- `a^n` in GF(2^8). -/
def exp (a : UInt8) (n : Nat) : UInt8 :=
  if n == 0 then
    1
  else if a == 0 then
    0
  else
    let logA := (logTable[a.toNat]!).toNat
    let logResult := (logA * n) % 255
    expTable[logResult]!

/-- Field element index `n` (nth_internal = identity for GF(2^8) in the crate). -/
@[inline] def nth (n : Nat) : UInt8 := UInt8.ofNat (n % 256)

/-- Multiply every element of `input` by `c` into a fresh array. -/
def mulSlice (c : UInt8) (input : Array UInt8) : Array UInt8 :=
  Id.run do
    let mut out : Array UInt8 := Array.mkEmpty input.size
    for i in [:input.size] do
      out := out.push (mul c (input[i]!))
    pure out

/-- `out[i] ^= mul(c, input[i])` (lengths must match). -/
def mulSliceAdd (c : UInt8) (input : Array UInt8) (out : Array UInt8) : Array UInt8 :=
  Id.run do
    let mut result := out
    for i in [:input.size] do
      let v := add (result[i]!) (mul c (input[i]!))
      result := result.set! i v
    pure result

/-- Multiply every byte of a `ByteArray` by `c`. -/
def mulSliceBA (c : UInt8) (input : ByteArray) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    for i in [:input.size] do
      out := out.push (mul c (input.get! i))
    pure out

/-- XOR-accumulate `mul(c, input)` into `out` (ByteArray form). -/
def mulSliceAddBA (c : UInt8) (input out : ByteArray) : ByteArray :=
  Id.run do
    let mut result := out
    for i in [:input.size] do
      let v := add (result.get! i) (mul c (input.get! i))
      result := result.set! i v
    pure result

/-! ## Parity samples vs reed-solomon-erasure galois_8 -/

theorem mul_1_1 : mul 1 1 = 1 := by native_decide
theorem mul_2_3 : mul 2 3 = 6 := by native_decide
theorem mul_0x53_0xca : mul 0x53 0xca = 0x8f := by native_decide
theorem mul_0xff_1 : mul 0xff 1 = 0xff := by native_decide
theorem mul_7_11 : mul 7 11 = 0x31 := by native_decide

theorem div_2_3 : div 2 3 = 0xf5 := by native_decide
theorem exp_2_3 : exp 2 3 = 8 := by native_decide
theorem exp_0x53_3 : exp 0x53 3 = 0xd0 := by native_decide

theorem mul_comm_7_11 : mul 7 11 = mul 11 7 := by native_decide

end Carbonado.Fec.Galois
