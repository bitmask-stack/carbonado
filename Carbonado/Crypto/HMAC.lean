/-
  HMAC-SHA512 (RFC 2104 / FIPS 198-1) — full 64-byte tags, never truncated.

  Parity target: RustCrypto `hmac` 0.12.1 (`ref/rustcrypto-macs`).
-/
import Carbonado.Crypto.SHA512
import Carbonado.Crypto.Util

namespace Carbonado.Crypto.HMAC

open Carbonado.Crypto.Util
open Carbonado.Crypto.SHA512

/-- HMAC-SHA512 with arbitrary-length key and message. Output is 64 bytes. -/
def hmacSHA512 (key msg : ByteArray) : ByteArray :=
  let block := blockSize -- 128 for SHA-512
  let keyBlock : ByteArray :=
    if key.size > block then
      resize (SHA512.hash key) block
    else
      resize key block
  let ipad := Id.run do
    let mut out := ByteArray.empty
    for i in [:block] do
      out := out.push (keyBlock.get! i ^^^ 0x36)
    pure out
  let opad := Id.run do
    let mut out := ByteArray.empty
    for i in [:block] do
      out := out.push (keyBlock.get! i ^^^ 0x5c)
    pure out
  let inner := SHA512.hash (appendBA ipad msg)
  SHA512.hash (appendBA opad inner)

end Carbonado.Crypto.HMAC
