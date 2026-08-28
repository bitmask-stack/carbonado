/-
  Byte utilities for Carbonado crypto (SHA-512, AES, EtM).

  Product code uses `ByteArray` for wire material. No secret zeroization is
  claimed here (see docs/LIMITS.md). Equality helpers are logical, not CT proofs.
-/

namespace Carbonado.Crypto.Util

/-- Equality for authentication tags (length-checked; logical, not a CT proof). -/
def ctEq (a b : ByteArray) : Bool :=
  if a.size != b.size then
    false
  else
    Id.run do
      let mut acc : UInt8 := 0
      for i in [:a.size] do
        acc := acc ||| (a.get! i ^^^ b.get! i)
      pure (acc == 0)

/-- Append `b` to `a`. -/
def appendBA (a b : ByteArray) : ByteArray :=
  a.append b

/-- XOR two byte arrays; result length is `min a.size b.size`. -/
def xorBytes (a b : ByteArray) : ByteArray :=
  let n := min a.size b.size
  Id.run do
    let mut out := ByteArray.empty
    for i in [:n] do
      out := out.push (a.get! i ^^^ b.get! i)
    pure out

/-- Repeat a byte `n` times. -/
def replicate (n : Nat) (b : UInt8) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    for _ in [:n] do
      out := out.push b
    pure out

/-- Pad or truncate to exactly `n` bytes (zero-pad on the right). -/
def resize (bs : ByteArray) (n : Nat) : ByteArray :=
  if bs.size >= n then
    bs.extract 0 n
  else
    appendBA bs (replicate (n - bs.size) 0)

/-- Big-endian increment of a 16-byte counter (Ctr128BE step). -/
def incCtr128BE (ctr : ByteArray) : ByteArray :=
  Id.run do
    let mut out := ctr
    let mut i : Int := 15
    let mut carry := true
    while carry && i ≥ 0 do
      let idx := i.toNat
      let v := out.get! idx
      if v == 0xff then
        out := out.set! idx 0
        i := i - 1
      else
        out := out.set! idx (v + 1)
        carry := false
    pure out

/-- Read big-endian `UInt64` from `bs` starting at `off`. -/
def getUInt64BE (bs : ByteArray) (off : Nat) : UInt64 :=
  let b0 := (bs.get! off).toUInt64
  let b1 := (bs.get! (off + 1)).toUInt64
  let b2 := (bs.get! (off + 2)).toUInt64
  let b3 := (bs.get! (off + 3)).toUInt64
  let b4 := (bs.get! (off + 4)).toUInt64
  let b5 := (bs.get! (off + 5)).toUInt64
  let b6 := (bs.get! (off + 6)).toUInt64
  let b7 := (bs.get! (off + 7)).toUInt64
  (b0 <<< 56) ||| (b1 <<< 48) ||| (b2 <<< 40) ||| (b3 <<< 32) |||
    (b4 <<< 24) ||| (b5 <<< 16) ||| (b6 <<< 8) ||| b7

/-- Write big-endian `UInt64` into a fresh 8-byte array. -/
def putUInt64BE (x : UInt64) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 56) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 48) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 40) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 32) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 24) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 16) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 8) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat x % 256))
    pure out

/-- Read little-endian `UInt32` from `bs` starting at `off`. -/
def getUInt32LE (bs : ByteArray) (off : Nat) : UInt32 :=
  let b0 := (bs.get! off).toUInt32
  let b1 := (bs.get! (off + 1)).toUInt32
  let b2 := (bs.get! (off + 2)).toUInt32
  let b3 := (bs.get! (off + 3)).toUInt32
  b0 ||| (b1 <<< 8) ||| (b2 <<< 16) ||| (b3 <<< 24)

/-- Write little-endian `UInt32` into a fresh 4-byte array. -/
def putUInt32LE (x : UInt32) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    out := out.push (UInt8.ofNat (UInt32.toNat x % 256))
    out := out.push (UInt8.ofNat (UInt32.toNat (x >>> 8) % 256))
    out := out.push (UInt8.ofNat (UInt32.toNat (x >>> 16) % 256))
    out := out.push (UInt8.ofNat (UInt32.toNat (x >>> 24) % 256))
    pure out

/-- Read little-endian `UInt64` from `bs` starting at `off`. -/
def getUInt64LE (bs : ByteArray) (off : Nat) : UInt64 :=
  let b0 := (bs.get! off).toUInt64
  let b1 := (bs.get! (off + 1)).toUInt64
  let b2 := (bs.get! (off + 2)).toUInt64
  let b3 := (bs.get! (off + 3)).toUInt64
  let b4 := (bs.get! (off + 4)).toUInt64
  let b5 := (bs.get! (off + 5)).toUInt64
  let b6 := (bs.get! (off + 6)).toUInt64
  let b7 := (bs.get! (off + 7)).toUInt64
  b0 ||| (b1 <<< 8) ||| (b2 <<< 16) ||| (b3 <<< 24) |||
    (b4 <<< 32) ||| (b5 <<< 40) ||| (b6 <<< 48) ||| (b7 <<< 56)

/-- Write little-endian `UInt64` into a fresh 8-byte array. -/
def putUInt64LE (x : UInt64) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    out := out.push (UInt8.ofNat (UInt64.toNat x % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 8) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 16) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 24) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 32) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 40) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 48) % 256))
    out := out.push (UInt8.ofNat (UInt64.toNat (x >>> 56) % 256))
    pure out

private def hexDigit (n : Nat) : Char :=
  if n < 10 then Char.ofNat ('0'.toNat + n)
  else Char.ofNat ('a'.toNat + (n - 10))

/-- Lowercase hex encoding (for demos / golden diagnostics). -/
def toHex (bs : ByteArray) : String :=
  Id.run do
    let mut s : String := ""
    for i in [:bs.size] do
      let b := (bs.get! i).toNat
      s := s.push (hexDigit (b / 16)) |>.push (hexDigit (b % 16))
    pure s

private def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c && c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

/-- Parse hex string to bytes (even length). Returns `none` on error. -/
def fromHex? (s : String) : Option ByteArray :=
  let chars := s.toList
  if chars.length % 2 != 0 then
    none
  else
    Id.run do
      let mut out := ByteArray.empty
      let mut rest := chars
      let mut ok := true
      while rest.length ≥ 2 && ok do
        match rest with
        | c0 :: c1 :: tail =>
          match hexVal c0, hexVal c1 with
          | some hi, some lo =>
            out := out.push (UInt8.ofNat (hi * 16 + lo))
            rest := tail
          | _, _ => ok := false
        | _ => ok := false
      if ok then some out else none

/-- UTF-8 encode a String. -/
def utf8 (s : String) : ByteArray := s.toUTF8

/-- Build ByteArray from a list of bytes. -/
def ofList (bs : List UInt8) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    for b in bs do
      out := out.push b
    pure out

end Carbonado.Crypto.Util
