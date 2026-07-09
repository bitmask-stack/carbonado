/-
  AES-256 block encrypt + AES-256-CTR (Ctr128BE) matching RustCrypto
  `aes` 0.8.4 + `ctr` 0.9.2 (`Ctr128BE<Aes256>`).

  Counter: 16-byte big-endian 128-bit integer; keystream block i is
  AES-256_K(BE128(nonce) + i).

  ## Unchecked primitives (caller contract)

  `expandKey256` and `ctrXor` are **low-level unchecked** helpers:
  * `expandKey256` requires a key of at least `keySize` (32) bytes
  * `ctrXor` requires a nonce of at least `blockSize` (16) bytes and a 32-byte key

  Short inputs panic via `ByteArray.get!` rather than returning a typed error.
  Product EtM APIs (`Carbonado.Crypto.EtM`) validate key/nonce lengths first and
  never call these with undersized buffers. Direct callers must supply full sizes.
-/
import Carbonado.Crypto.Util

namespace Carbonado.Crypto.AESCTR

open Carbonado.Crypto.Util

/-- AES block size. -/
def blockSize : Nat := 16

/-- AES-256 key size. -/
def keySize : Nat := 32

/-- Forward S-box. -/
private def sbox : Array UInt8 := #[
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

private def rcon : Array UInt8 := #[
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

private def xtime (a : UInt8) : UInt8 :=
  let s := a <<< 1
  if (a &&& 0x80) != 0 then s ^^^ 0x1b else s

private def mul2 (a : UInt8) : UInt8 := xtime a
private def mul3 (a : UInt8) : UInt8 := xtime a ^^^ a

/-- AES-256 expanded key: 15 round keys × 16 bytes = 240 bytes. -/
def expandKey256 (key : ByteArray) : ByteArray :=
  Id.run do
    let mut w := ByteArray.empty
    for i in [:32] do
      w := w.push (key.get! i)
    let mut i : Nat := 8
    while i < 60 do
      let mut temp0 := w.get! ((i - 1) * 4)
      let mut temp1 := w.get! ((i - 1) * 4 + 1)
      let mut temp2 := w.get! ((i - 1) * 4 + 2)
      let mut temp3 := w.get! ((i - 1) * 4 + 3)
      if i % 8 == 0 then
        let t0 := temp0
        temp0 := sbox[temp1.toNat]! ^^^ rcon[i / 8]!
        temp1 := sbox[temp2.toNat]!
        temp2 := sbox[temp3.toNat]!
        temp3 := sbox[t0.toNat]!
      else if i % 8 == 4 then
        temp0 := sbox[temp0.toNat]!
        temp1 := sbox[temp1.toNat]!
        temp2 := sbox[temp2.toNat]!
        temp3 := sbox[temp3.toNat]!
      w := w.push (w.get! ((i - 8) * 4) ^^^ temp0)
      w := w.push (w.get! ((i - 8) * 4 + 1) ^^^ temp1)
      w := w.push (w.get! ((i - 8) * 4 + 2) ^^^ temp2)
      w := w.push (w.get! ((i - 8) * 4 + 3) ^^^ temp3)
      i := i + 1
    pure w

private def addRoundKey (state rk : ByteArray) (round : Nat) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    let base := round * 16
    for i in [:16] do
      out := out.push (state.get! i ^^^ rk.get! (base + i))
    pure out

private def subBytes (state : ByteArray) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    for i in [:16] do
      out := out.push sbox[(state.get! i).toNat]!
    pure out

/-- ShiftRows on column-major AES state (index = row + 4*col). -/
private def shiftRows (state : ByteArray) : ByteArray :=
  let get (r c : Nat) := state.get! (r + 4 * c)
  Id.run do
    let mut arr : Array UInt8 := Array.replicate 16 0
    for c in [:4] do
      arr := arr.set! (0 + 4 * c) (get 0 c)
      arr := arr.set! (1 + 4 * c) (get 1 ((c + 1) % 4))
      arr := arr.set! (2 + 4 * c) (get 2 ((c + 2) % 4))
      arr := arr.set! (3 + 4 * c) (get 3 ((c + 3) % 4))
    let mut out := ByteArray.empty
    for i in [:16] do
      out := out.push arr[i]!
    pure out

private def mixColumns (state : ByteArray) : ByteArray :=
  Id.run do
    let mut arr : Array UInt8 := Array.replicate 16 0
    for c in [:4] do
      let s0 := state.get! (0 + 4 * c)
      let s1 := state.get! (1 + 4 * c)
      let s2 := state.get! (2 + 4 * c)
      let s3 := state.get! (3 + 4 * c)
      arr := arr.set! (0 + 4 * c) (mul2 s0 ^^^ mul3 s1 ^^^ s2 ^^^ s3)
      arr := arr.set! (1 + 4 * c) (s0 ^^^ mul2 s1 ^^^ mul3 s2 ^^^ s3)
      arr := arr.set! (2 + 4 * c) (s0 ^^^ s1 ^^^ mul2 s2 ^^^ mul3 s3)
      arr := arr.set! (3 + 4 * c) (mul3 s0 ^^^ s1 ^^^ s2 ^^^ mul2 s3)
    let mut out := ByteArray.empty
    for i in [:16] do
      out := out.push arr[i]!
    pure out

/-- Encrypt one 16-byte block with AES-256 (expanded key 240 bytes). -/
def encryptBlock (roundKeys block : ByteArray) : ByteArray :=
  Id.run do
    let mut state := addRoundKey block roundKeys 0
    for round in [1:14] do
      state := subBytes state
      state := shiftRows state
      state := mixColumns state
      state := addRoundKey state roundKeys round
    state := subBytes state
    state := shiftRows state
    state := addRoundKey state roundKeys 14
    pure state

/-- AES-256-CTR keystream XOR (encrypt ≡ decrypt). Nonce is 16-byte Ctr128BE IV. -/
def ctrXor (key nonce data : ByteArray) : ByteArray :=
  let rk := expandKey256 key
  Id.run do
    let mut counter := nonce.extract 0 16
    let mut out := ByteArray.empty
    let mut off : Nat := 0
    while off < data.size do
      let ks := encryptBlock rk counter
      let n := min 16 (data.size - off)
      for i in [:n] do
        out := out.push (data.get! (off + i) ^^^ ks.get! i)
      counter := incCtr128BE counter
      off := off + n
    pure out

end Carbonado.Crypto.AESCTR
