import Carbonado.Constants
import Carbonado.Crypto
import Carbonado.Fec
import Carbonado.Bao
import Carbonado.Header
import Carbonado.Compress
import Carbonado.Slh
import Carbonado.Pipeline
import Carbonado.Stream
import Carbonado.Scrub
import Carbonado.Shard
import Carbonado.Adamantine
import Carbonado.Filepack
import Carbonado.Outboard
import Carbonado.Directory
import Carbonado.Cli

-- Large patterned Bao vectors + partial tree recursion need a deeper elaborator budget.
set_option maxRecDepth 2048

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Crypto.SHA512
open Carbonado.Crypto.HMAC
open Carbonado.Crypto.AESCTR
open Carbonado.Crypto.EtM
open Carbonado.Fec.Galois
open Carbonado.Fec.Matrix
open Carbonado.Fec.RS
open Carbonado.Fec.Inboard
open Carbonado.Bao.Blake3
open Carbonado.Bao.Product
open Carbonado.Header
open Carbonado.Compress
open Carbonado.Slh
open Carbonado.Pipeline
open Carbonado.Stream
open Carbonado.Scrub
open Carbonado.Shard
open Carbonado.Adamantine
open Carbonado.Filepack
open Carbonado.Outboard
open Carbonado.Directory
open Carbonado.Cli
-- Note: do not open Carbonado.Bao.Tree — name clash with Fec.Inboard.encodeInboard/decodeInboard.

/-- Expected magic bytes: ASCII `CARBONADO20\n`. -/
private def expectedMagic : List UInt8 :=
  [0x43, 0x41, 0x52, 0x42, 0x4f, 0x4e, 0x41, 0x44, 0x4f, 0x32, 0x30, 0x0a]

private def master42 : ByteArray := replicate 32 0x42
private def nonce11 : ByteArray := replicate 16 0x11

private def fail (msg : String) : IO Unit := do
  IO.eprintln s!"FAIL: {msg}"
  IO.Process.exit 1

private def expectHex (label : String) (got : ByteArray) (wantHex : String) : IO Unit := do
  let g := toHex got
  if g != wantHex then
    fail s!"{label}: got {g} want {wantHex}"

private def expectTrue (label : String) (b : Bool) : IO Unit := do
  if !b then fail label

/-- Patterned bytes `i % 251` for Bao parity vectors (name avoids shadowing FEC locals). -/
private def baoPattern (n : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  for i in [:n] do
    out := out.push (UInt8.ofNat (i % 251))
  pure out

/-- Scaffold + Program B–G demo (EtM + FEC + Bao + pipeline + zstd/SLH + Adamantine/CLI). -/
def runDemo : IO Unit := do
  IO.println "carbonado (Lean 4 AOT — Program G Adamantine + CLI)"
  IO.println s!"magic length = {magicBytes.length} (expect 12)"
  IO.println s!"headerLen = {headerLen}"
  IO.println s!"sliceLen = {sliceLen}"
  IO.println s!"baoChunkLog = {baoChunkLog}"
  IO.println s!"leafBytes = {Carbonado.Bao.Tree.leafBytes}"
  IO.println s!"verificationContext = {verificationContext}"
  IO.println s!"fecK = {fecK} fecM = {fecM} stripeUnit = {stripeUnit}"
  IO.println s!"hmacTagLen = {hmacTagLen} (full HMAC-SHA512)"
  IO.println s!"slh1SidecarLen = {slh1SidecarLen}"
  IO.println s!"sample public c14 format byte = {formatC14.toUInt8}"
  IO.println s!"sample encrypted c15 format byte = {formatC15.toUInt8}"
  if magicBytes != expectedMagic then
    fail "magic bytes (expect CARBONADO20\\n)"
  if magicBytes.length != 12 then fail "magic length"
  if headerLen != 177 then fail "headerLen"
  if sliceLen != 4096 then fail "sliceLen"
  if baoChunkLog != 2 then fail "baoChunkLog"
  if nonceLen != 16 then fail "nonceLen"
  if hashLen != 32 then fail "hashLen"
  if slh1SignatureLen != 7856 then fail "slh1SignatureLen"
  if stripeUnit != 16384 then fail "stripeUnit"
  if fecK != 4 || fecM != 8 then fail "FEC geometry"
  if hmacTagLen != 64 then fail "hmacTagLen"
  if slh1SidecarLen != 7860 then fail "slh1SidecarLen"
  if formatC14.toUInt8 != 14 then fail "formatC14"
  if formatC15.toUInt8 != 15 then fail "formatC15"
  IO.println "scaffold constants ok"

  -- SHA-512 goldens (FIPS / common)
  expectHex "sha512(empty)" (Carbonado.Crypto.SHA512.hash ByteArray.empty)
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
  expectHex "sha512(abc)" (hashString "abc")
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
  expectHex "sha512(fox)" (hashString "The quick brown fox jumps over the lazy dog")
    "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
  IO.println "sha512 goldens ok"

  -- HMAC-SHA512 RFC 4231 test case 1
  let hmacKey := replicate 20 0x0b
  expectHex "hmac-rfc4231-1" (hmacSHA512 hmacKey (utf8 "Hi There"))
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
  IO.println "hmac goldens ok"

  -- AES-256-CTR NIST SP 800-38A F.5.5
  let nistKey := ofList [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4]
  let nistCtr := ofList [
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]
  let nistPt := ofList [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10]
  expectHex "aes-ctr-nist" (ctrXor nistKey nistCtr nistPt)
    "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"
  IO.println "aes-ctr nist golden ok"

  -- Subkeys (master = 0x42×32)
  match deriveSubkey master42 "aes-ctr" with
  | .error e => fail s!"derive aes-ctr: {repr e}"
  | .ok skAes =>
    expectHex "subkey aes-ctr" skAes
      "6f15fb9936ca3e4d2ecc5bd80bcc06c12d67361b72dcf5e8edc8312092f42a28494d106e3340595717f67ab0ec91b0b8d0ea653853ca129a4515ea6df74a5ca7"
  match deriveSubkey master42 "etm-hmac" with
  | .error e => fail s!"derive etm-hmac: {repr e}"
  | .ok skEtm =>
    expectHex "subkey etm-hmac" skEtm
      "d9795accc69d8966b12f051575d3efc53725697a14d8117ffcef149eea20bb859e025d2e76f5b47bb1bc73af3c34aceb317ba0d5d00e5b3f36e7f21accae3609"
  match deriveSubkey master42 "header-auth" with
  | .error e => fail s!"derive header-auth: {repr e}"
  | .ok skHdr =>
    expectHex "subkey header-auth" skHdr
      "af1f7d5c23422538fab14c8343eaef42918230ba04fef171176b3c01a89e9bab0ae60b90586d9863f4a4231d91eb984516f0be04c20d4c7e784f0fe459de2b19"
  IO.println "subkey goldens ok"

  -- EtM header-path goldens + roundtrips
  let cases : List (String × ByteArray × String) := [
    ("empty", ByteArray.empty,
      "74e137726bc9f0a9e55add833d1ac0c187bb366f22f0a2be1189536828d77dfc2d021e8aad99fab802c664db3b8ec1e0c46198f44dd3f3e9321bded8263a6aa2"),
    ("hello", utf8 "hello",
      "1d05aa600755696228225aeada6672b65266554ef6a2e2b5f4a083870ad00f534747fbd18d98f4c6e449a4b64e954b77f65bd63eba1a9a0e080cca3c296760b08f0a0e143c"),
    ("multi", utf8 "The quick brown fox jumps over the lazy dog",
      "38cddad202dc0f7daacd53b35573b43a3c79bbcfa44aee039d661c92d5be8f16701b996b7474d66610627fb714376524cfcbb4aa30d8e7062ca9b61cf32eccd9b307075822eda7e16b52f04354c83f70cd6b5a9ab6817560693ae25a0cdd1883752eeccaff8bb0228d84c6")
  ]
  for (name, pt, want) in cases do
    match encryptWithNonce master42 nonce11 pt with
    | .error e => fail s!"encrypt {name}: {repr e}"
    | .ok blob =>
      expectHex s!"etm {name}" blob want
      match decryptWithNonce master42 nonce11 blob with
      | .ok pt' =>
        expectTrue s!"roundtrip {name}" (toHex pt' == toHex pt)
      | .error e => fail s!"decrypt {name}: {repr e}"
  IO.println "etm header-path goldens + roundtrip ok"

  -- Low-level embedded nonce layout
  match encryptEmbeddedNonce master42 nonce11 (utf8 "hello") with
  | .error e => fail s!"encryptEmbedded: {repr e}"
  | .ok low =>
    expectHex "low_level_hello" low
      "111111111111111111111111111111111d05aa600755696228225aeada6672b65266554ef6a2e2b5f4a083870ad00f534747fbd18d98f4c6e449a4b64e954b77f65bd63eba1a9a0e080cca3c296760b08f0a0e143c"
    match decryptEmbeddedNonce master42 low with
    | .ok pt => expectTrue "low roundtrip" (toHex pt == toHex (utf8 "hello"))
    | .error e => fail s!"decryptEmbedded: {repr e}"
  IO.println "etm low-level layout ok"

  -- Tampered tag → authenticationFailed (strict match)
  match encryptWithNonce master42 nonce11 (utf8 "hello") with
  | .error e => fail s!"encrypt for tamper: {repr e}"
  | .ok blob =>
    let mut bad := blob
    -- flip first tag byte
    bad := bad.set! 0 (bad.get! 0 ^^^ 0x01)
    match decryptWithNonce master42 nonce11 bad with
    | .error .authenticationFailed => pure ()
    | .error e => fail s!"tamper: expected authenticationFailed, got {repr e}"
    | .ok _ => fail "tamper: decrypt succeeded on bad tag"
  IO.println "tampered tag → authenticationFailed ok"

  -- Ciphertext-body tamper (byte past the 64-byte tag) → authenticationFailed
  match encryptWithNonce master42 nonce11 (utf8 "hello") with
  | .error e => fail s!"encrypt for ct tamper: {repr e}"
  | .ok blob =>
    if blob.size ≤ hmacTagLen then
      fail "ct tamper: blob has no ciphertext body"
    else
      let mut bad := blob
      bad := bad.set! hmacTagLen (bad.get! hmacTagLen ^^^ 0x01)
      match decryptWithNonce master42 nonce11 bad with
      | .error .authenticationFailed => pure ()
      | .error e => fail s!"ct body tamper: expected authenticationFailed, got {repr e}"
      | .ok _ => fail "ct body tamper: decrypt succeeded"
  IO.println "ct body tamper → authenticationFailed ok"

  -- Wrong master → authenticationFailed
  let wrongMaster := replicate 32 0x43
  match encryptWithNonce master42 nonce11 (utf8 "hello") with
  | .error e => fail s!"encrypt for wrong key: {repr e}"
  | .ok blob =>
    match decryptWithNonce wrongMaster nonce11 blob with
    | .error .authenticationFailed => pure ()
    | .error e => fail s!"wrong key: expected authenticationFailed, got {repr e}"
    | .ok _ => fail "wrong key: decrypt succeeded"
  IO.println "wrong key → authenticationFailed ok"

  -- Short ciphertext → invalidCiphertextLength
  match decryptWithNonce master42 nonce11 (replicate 10 0) with
  | .error .invalidCiphertextLength => pure ()
  | .error e => fail s!"short ct: expected invalidCiphertextLength, got {repr e}"
  | .ok _ => fail "short ct: ok"
  IO.println "short ciphertext → invalidCiphertextLength ok"

  -- Dual-invalid (short master + short CT): Rust/Lean both report CT length first
  match decryptWithNonce (replicate 16 0x42) nonce11 (replicate 10 0) with
  | .error .invalidCiphertextLength => pure ()
  | .error e => fail s!"dual short: expected invalidCiphertextLength, got {repr e}"
  | .ok _ => fail "dual short: ok"
  IO.println "dual short master+ct → invalidCiphertextLength ok"

  -- Short master (long enough CT) → invalidKeyLength
  match decryptWithNonce (replicate 16 0x42) nonce11 (replicate 64 0) with
  | .error .invalidKeyLength => pure ()
  | .error e => fail s!"short master: expected invalidKeyLength, got {repr e}"
  | .ok _ => fail "short master: ok"
  IO.println "short master → invalidKeyLength ok"

  -- Bad nonce length → invalidNonceLength (encrypt + decrypt)
  match encryptWithNonce master42 (replicate 8 0x11) (utf8 "hi") with
  | .error .invalidNonceLength => pure ()
  | .error e => fail s!"encrypt bad nonce: expected invalidNonceLength, got {repr e}"
  | .ok _ => fail "encrypt bad nonce: ok"
  match decryptWithNonce master42 (replicate 8 0x11) (replicate 64 0) with
  | .error .invalidNonceLength => pure ()
  | .error e => fail s!"decrypt bad nonce: expected invalidNonceLength, got {repr e}"
  | .ok _ => fail "decrypt bad nonce: ok"
  IO.println "bad nonce → invalidNonceLength ok"

  -- Embedded short input → invalidCiphertextLength
  match decryptEmbeddedNonce master42 (replicate 20 0) with
  | .error .invalidCiphertextLength => pure ()
  | .error e => fail s!"embedded short: expected invalidCiphertextLength, got {repr e}"
  | .ok _ => fail "embedded short: ok"
  IO.println "embedded short → invalidCiphertextLength ok"

  -- Header MAC goldens
  match computeHeaderMac master42 (utf8 "CARBONADO20\n") with
  | .error e => fail s!"header mac magic: {repr e}"
  | .ok tag =>
    expectHex "header_mac(MAGIC)" tag
      "c02b40016162e5abf37a007183f2117a46fb74175529188dc98786c9cab370691c7903dcf552765f7764ec2c392af0863b618ea295ed026e8a47b304f0127937"
  -- sample full auth_data (113 bytes)
  let mut auth := ByteArray.empty
  for b in magicBytes do auth := auth.push b
  for _ in [:16] do auth := auth.push 0x11
  for _ in [:32] do auth := auth.push 0xcd
  for _ in [:32] do auth := auth.push 0x00
  auth := auth.push 0x05
  for _ in [:4] do auth := auth.push 0x00 -- chunk 0 LE
  auth := auth.push 100; auth := auth.push 0; auth := auth.push 0; auth := auth.push 0 -- encoded_len 100 LE
  for _ in [:4] do auth := auth.push 0x00 -- padding
  for _ in [:8] do auth := auth.push 0x00 -- metadata
  expectTrue "auth_data len" (auth.size == 113)
  match computeHeaderMac master42 auth with
  | .error e => fail s!"header mac sample: {repr e}"
  | .ok tag =>
    expectHex "header_mac(sample_auth)" tag
      "72b887d72cf53ae234f4802ac1984405a14dfdc9a0494ceb2067d24af0f4063f2dc94e7cd754289722d17a318845398dcc929190c3c39aae0b415af8867c0699"
    match verifyHeaderMac master42 auth tag with
    | .ok true => pure ()
    | .ok false => fail "verifyHeaderMac: expected true on good tag"
    | .error e => fail s!"verifyHeaderMac good: {repr e}"
    let badTag := tag.set! 0 (tag.get! 0 ^^^ 1)
    match verifyHeaderMac master42 auth badTag with
    | .ok false => pure ()
    | .ok true => fail "verifyHeaderMac: expected false on bad tag"
    | .error e => fail s!"verifyHeaderMac bad: {repr e}"
  IO.println "header mac goldens ok"
  IO.println "header mac verify false path ok"

  IO.println "etm stack ok"

  -- Program C: GF + RS 4/8 + inboard geometry
  expectTrue "gf mul 0x53*0xca" (mul 0x53 0xca == 0x8f)
  expectTrue "gf div 2/3" (div 2 3 == 0xf5)
  expectTrue "gf exp 2^3" (exp 2 3 == 8)
  IO.println "gf goldens ok"

  let p0 := calcPaddingLen 0
  let p1 := calcPaddingLen 1
  let p4k := calcPaddingLen 4096
  let pStripe := calcPaddingLen 16384
  let pPlus := calcPaddingLen 16385
  expectTrue "pad0" (p0.paddingLen == 0 && p0.chunkLen == 0)
  expectTrue "pad1" (p1.paddingLen == 16383 && p1.chunkLen == 4096)
  expectTrue "pad4096" (p4k.paddingLen == 12288 && p4k.chunkLen == 4096)
  expectTrue "pad16384" (pStripe.paddingLen == 0 && pStripe.chunkLen == 4096)
  expectTrue "pad16385" (pPlus.paddingLen == 16383 && pPlus.chunkLen == 8192)
  expectTrue "rs geometry" (carbonadoRS.dataShards == fecK && carbonadoRS.parityShards == fecM - fecK)
  IO.println "padding geometry ok"

  -- 1-byte shard encode golden
  let s1 : Array ByteArray := #[
    ofList [1], ofList [2], ofList [3], ofList [4],
    ofList [0], ofList [0], ofList [0], ofList [0]]
  match carbonadoRS.encode s1 with
  | .error e => fail s!"encode len1: {repr e}"
  | .ok enc =>
    expectTrue "parity0" ((enc[4]!).get! 0 == 0x45)
    expectTrue "parity1" ((enc[5]!).get! 0 == 0x5e)
    expectTrue "parity2" ((enc[6]!).get! 0 == 0x67)
    expectTrue "parity3" ((enc[7]!).get! 0 == 0x78)
    -- reconstruct parity-only
    let opts : Array (Option ByteArray) := #[
      none, none, none, none,
      some (enc[4]!), some (enc[5]!), some (enc[6]!), some (enc[7]!)]
    match carbonadoRS.reconstruct opts with
    | .error e => fail s!"reconstruct parity-only: {repr e}"
    | .ok full =>
      expectTrue "recon0" ((full[0]!).get! 0 == 1)
      expectTrue "recon1" ((full[1]!).get! 0 == 2)
      expectTrue "recon2" ((full[2]!).get! 0 == 3)
      expectTrue "recon3" ((full[3]!).get! 0 == 4)
  IO.println "rs encode/reconstruct goldens ok"

  -- Inboard hello roundtrip (16 KiB stripe; O(stripe) memory)
  match encodeInboard (utf8 "hello") with
  | .error e => fail s!"encodeInboard hello: {repr e}"
  | .ok (body, pad, chunk) =>
    expectTrue "hello pad" (pad == 16379)
    expectTrue "hello chunk" (chunk == 4096)
    expectTrue "hello body len" (body.size == 32768)
    expectTrue "hello head ascii" (body.get! 0 == 'h'.toNat.toUInt8 && body.get! 4 == 'o'.toNat.toUInt8)
    match decodeInboard body pad with
    | .error e => fail s!"decodeInboard hello: {repr e}"
    | .ok pt =>
      expectTrue "hello roundtrip" (toHex pt == toHex (utf8 "hello"))
    -- Knock out all data shards; reconstruct from parity only
    match inboardToShards body with
    | .error e => fail s!"split hello: {repr e}"
    | .ok shards =>
      match reconstructAfterKnockout shards [0, 1, 2, 3] pad with
      | .error e => fail s!"knockout data: {repr e}"
      | .ok pt =>
        expectTrue "hello knockout data" (toHex pt == toHex (utf8 "hello"))
      match reconstructAfterKnockout shards [4, 5, 6, 7] pad with
      | .error e => fail s!"knockout parity: {repr e}"
      | .ok pt =>
        expectTrue "hello knockout parity" (toHex pt == toHex (utf8 "hello"))
      match reconstructAfterKnockout shards [0, 2, 5, 7] pad with
      | .error e => fail s!"knockout mixed: {repr e}"
      | .ok pt =>
        expectTrue "hello knockout mixed" (toHex pt == toHex (utf8 "hello"))
  IO.println "inboard hello roundtrip + knockout ok"

  -- Pattern i%251 length 100
  let mut pat := ByteArray.empty
  for i in [:100] do
    pat := pat.push (UInt8.ofNat (i % 251))
  match encodeInboard pat with
  | .error e => fail s!"encode pat100: {repr e}"
  | .ok (body, pad, _) =>
    expectTrue "pat100 pad" (pad == 16284)
    match decodeInboard body pad with
    | .error e => fail s!"decode pat100: {repr e}"
    | .ok pt =>
      expectTrue "pat100 roundtrip" (toHex pt == toHex pat)
    match inboardToShards body with
    | .error e => fail s!"split pat100: {repr e}"
    | .ok shards =>
      expectHex "pat100 parity0 head" ((shards[4]!).extract 0 8)
        "001b362d6c775a41"
  IO.println "inboard pattern roundtrip ok"

  -- Strict error paths
  match decodeInboard (ofList [1, 2, 3]) 0 with
  | .error .unevenShards => pure ()
  | .error e => fail s!"uneven: expected unevenShards, got {repr e}"
  | .ok _ => fail "uneven: ok"
  IO.println "unevenShards ok"

  match carbonadoRS.reconstruct #[
      some (ofList [1]), some (ofList [2]), some (ofList [3]),
      none, none, none, none, none] with
  | .error .tooFewShards => pure ()
  | .error e => fail s!"tooFew: expected tooFewShards, got {repr e}"
  | .ok _ => fail "tooFew: ok"
  IO.println "tooFewShards ok"

  match carbonadoRS.reconstruct #[
      some ByteArray.empty, some (ofList [1]), some (ofList [2]), some (ofList [3]),
      none, none, none, none] with
  | .error .emptyShard => pure ()
  | .error e => fail s!"emptyShard: expected emptyShard, got {repr e}"
  | .ok _ => fail "emptyShard: ok"
  IO.println "emptyShard ok"

  match carbonadoRS.reconstruct #[
      some (ofList [1]), some (ofList [1, 2]), some (ofList [3]), some (ofList [4]),
      none, none, none, none] with
  | .error .incorrectShardSize => pure ()
  | .error e => fail s!"incorrectSize: expected incorrectShardSize, got {repr e}"
  | .ok _ => fail "incorrectSize: ok"
  IO.println "incorrectShardSize ok"

  match carbonadoRS.reconstruct #[some (ofList [1]), some (ofList [2])] with
  | .error .badGeometry => pure ()
  | .error e => fail s!"badGeometry: expected badGeometry, got {repr e}"
  | .ok _ => fail "badGeometry: ok"
  IO.println "badGeometry ok"

  match stripPadding #[ofList [1], ofList [2], ofList [3], ofList [4]] 5 with
  | .error .paddingTooLarge => pure ()
  | .error e => fail s!"paddingTooLarge: expected paddingTooLarge, got {repr e}"
  | .ok _ => fail "paddingTooLarge: ok"
  IO.println "paddingTooLarge ok"

  match invertOrSingular (Matrix.zeros 2 2) with
  | .error .singularMatrix => pure ()
  | .error e => fail s!"singular: expected singularMatrix, got {repr e}"
  | .ok _ => fail "singular: ok"
  IO.println "singularMatrix ok"

  match ReedSolomon.new 0 4 with
  | .error .badGeometry => pure ()
  | .error e => fail s!"new0data: expected badGeometry, got {repr e}"
  | .ok _ => fail "new0data: ok"
  match carbonadoRS.encode #[ofList [1], ofList [2]] with
  | .error .badGeometry => pure ()
  | .error e => fail s!"encode bad geo: expected badGeometry, got {repr e}"
  | .ok _ => fail "encode bad geo: ok"
  match carbonadoRS.encode #[
      ByteArray.empty, ofList [1], ofList [2], ofList [3],
      ofList [0], ofList [0], ofList [0], ofList [0]] with
  | .error .emptyShard => pure ()
  | .error e => fail s!"encode empty: expected emptyShard, got {repr e}"
  | .ok _ => fail "encode empty: ok"
  IO.println "encode/new guards ok"

  match carbonadoRS.encode #[
      ofList [1], ofList [2], ofList [3], ofList [4],
      ofList [0], ofList [0], ofList [0], ofList [0]] with
  | .error e => fail s!"verify setup: {repr e}"
  | .ok enc =>
    match carbonadoRS.verify enc with
    | .ok true => pure ()
    | .ok false => fail "verify good: expected true"
    | .error e => fail s!"verify good: {repr e}"
    let mut bad := enc
    bad := bad.set! 4 (ofList [(enc[4]!).get! 0 ^^^ 0x01])
    match carbonadoRS.verify bad with
    | .ok false => pure ()
    | .ok true => fail "verify bad: expected false"
    | .error e => fail s!"verify bad: {repr e}"
  IO.println "verify good/bad ok"

  match reconstructAfterKnockout
      #[ofList [1], ofList [2], ofList [3], ofList [4],
        ofList [0], ofList [0], ofList [0], ofList [0]] [0, 99] 0 with
  | .error .badGeometry => pure ()
  | .error e => fail s!"knockout oob: expected badGeometry, got {repr e}"
  | .ok _ => fail "knockout oob: ok"
  IO.println "knockout oob badGeometry ok"

  IO.println "fec stack ok"

  -- Program D: BLAKE3 + keyed Bao (4 KiB leaves, format-byte key)
  expectHex "blake3(empty)" (Carbonado.Bao.Blake3.hash ByteArray.empty)
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
  expectHex "blake3(abc)" (Carbonado.Bao.Blake3.hash (utf8 "abc"))
    "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
  IO.println "blake3 goldens ok"

  expectHex "vkey c4" (carbonadoVerificationKey 4)
    "6f1b6d31098f44f98e31231fe4244d532d1263556a45fe370d74cae1a447ffbf"
  expectHex "vkey c6" (carbonadoVerificationKey 6)
    "3923848b90f499febc394b34cbac1f3c2d9a98a89b93beb4bb6361d1db5d4615"
  expectHex "vkey c14" (carbonadoVerificationKey 14)
    "4f1be70ef9d46fe13ad7c55230a7703d90ee6601d0e24b041c5db041a8a26d44"
  expectTrue "vkey domain" (toHex (carbonadoVerificationKey 4) != toHex (carbonadoVerificationKey 6))
  IO.println "verification key goldens ok"

  expectHex "keyed root hello c4" (rootForFormat 4 (utf8 "hello"))
    "f8a7892045a78f933cca82f9ef17046c453ad166e5463e5e93c88cf614443d86"
  expectHex "keyed root pat100 c4" (rootForFormat 4 (baoPattern 100))
    "27e8845ee8cfeed082734d4409991f9db4e9e4d0476de3ed196d89f4a2f37077"
  expectHex "keyed root pat100 c6" (rootForFormat 6 (baoPattern 100))
    "1e478e01260caf8df6ad29f09c754a5e8423ee5ceceee4209db543828416147f"
  expectTrue "root commits to format"
    (toHex (rootForFormat 4 (baoPattern 100)) != toHex (rootForFormat 6 (baoPattern 100)))
  IO.println "keyed root goldens ok"

  -- Inboard empty / hello / pat100
  let (r0, a0) := encodeInboardForFormat 4 ByteArray.empty
  expectHex "inboard empty" a0 "0000000000000000"
  expectHex "inboard empty root" r0
    "51ceb9e65f98d4ae586f2345d792b4d5af14f4222bfaa95dac58313034498294"
  match decodeInboardForFormat 4 r0 a0 with
  | .ok d => expectTrue "empty roundtrip" (d.size == 0)
  | .error e => fail s!"empty decode: {repr e}"

  let (rHello, aHello) := encodeInboardForFormat 4 (utf8 "hello")
  expectHex "inboard hello" aHello "050000000000000068656c6c6f"
  match decodeInboardForFormat 4 rHello aHello with
  | .ok d => expectTrue "hello roundtrip" (toHex d == toHex (utf8 "hello"))
  | .error e => fail s!"hello decode: {repr e}"

  let bao100 := baoPattern 100
  let (r100, a100) := encodeInboardForFormat 4 bao100
  expectTrue "inboard pat100 len" (a100.size == 108)
  match decodeInboardForFormat 4 r100 a100 with
  | .ok d => expectTrue "pat100 roundtrip" (toHex d == toHex bao100)
  | .error e => fail s!"pat100 decode: {repr e}"
  IO.println "inboard encode/decode ok"

  -- Multi-leaf (5000 B) inboard + outboard
  let bao5k := baoPattern 5000
  let (r5k, a5k) := encodeInboardForFormat 4 bao5k
  expectHex "root pat5000" r5k
    "d1168cb56536e2e0ae67934258019b239b875a07d812505df43155db53ae53ad"
  expectTrue "inboard 5000 total" (a5k.size == 5072)
  match decodeInboardForFormat 4 r5k a5k with
  | .ok d => expectTrue "pat5000 roundtrip" (toHex d == toHex bao5k)
  | .error e => fail s!"pat5000 decode: {repr e}"
  let (rOb, ob) := encodeOutboardForFormat 4 bao5k
  expectTrue "outboard root match" (toHex rOb == toHex r5k)
  expectTrue "outboard len" (ob.size == 64)
  expectHex "outboard 5000" ob
    "d5b0f4c38a9c1ddc9d00230cb53225677b7b41f8fa15f7de4750aa32a7882cfdd0b117458bfb503d3f195a969fdc9d8f2b94984022a2a940b81b238f505e3b80"
  match verifyOutboardForFormat 4 rOb bao5k ob with
  | .ok _ => pure ()
  | .error e => fail s!"outboard verify: {repr e}"
  IO.println "outboard encode/verify ok"

  -- Slice first group of 5000: stream decode (no plaintext oracle)
  let (rSlice, sliceEnc) := encodeSliceForFormat 4 bao5k 0 1
  expectTrue "slice root" (toHex rSlice == toHex r5k)
  expectTrue "slice enc len" (sliceEnc.size == 4160)
  match decodeSliceForFormat 4 rSlice 5000 0 1 sliceEnc with
  | .ok s =>
    expectTrue "slice size" (s.size == 4096)
    expectTrue "slice bytes" (toHex s == toHex (bao5k.extract 0 4096))
  | .error e => fail s!"slice decode: {repr e}"
  match verifySliceInboardForFormat 4 r5k a5k 0 1 with
  | .ok s => expectTrue "slice inboard size" (s.size == 4096)
  | .error e => fail s!"slice inboard: {repr e}"
  -- count=0 after full inboard auth → empty ok
  match verifySliceInboardForFormat 4 r5k a5k 0 0 with
  | .ok s => expectTrue "count0 after auth" (s.size == 0)
  | .error e => fail s!"count0 inboard: {repr e}"
  -- corrupt inboard + count=0 must fail (auth-first)
  let mut bad5k := a5k
  bad5k := bad5k.set! 20 (bad5k.get! 20 ^^^ 0x01)
  match verifySliceInboardForFormat 4 r5k bad5k 0 0 with
  | Except.error .authenticationFailed => pure ()
  | Except.error e => fail s!"count0 corrupt: expected authenticationFailed, got {repr e}"
  | Except.ok _ => fail "count0 corrupt: ok"
  IO.println "slice encode/stream-decode ok"

  -- Three-leaf tree (12288 B): deeper nesting
  let bao12k := baoPattern 12288
  let (r12, a12) := encodeInboardForFormat 4 bao12k
  expectHex "root pat12288" r12
    "7390719e0ff132dd988f246240f60bd70e8b6cb52836f9978340676a5b442c9d"
  expectTrue "inboard 12288 total" (a12.size == 12424)
  match decodeInboardForFormat 4 r12 a12 with
  | .ok d => expectTrue "pat12288 roundtrip" (toHex d == toHex bao12k)
  | .error e => fail s!"pat12288 decode: {repr e}"
  let (rOb12, ob12) := encodeOutboardForFormat 4 bao12k
  expectTrue "outboard 12288 root" (toHex rOb12 == toHex r12)
  expectTrue "outboard 12288 len" (ob12.size == 128)
  -- middle slice (leaf index 1) stream decode
  let (_rs, midSlice) := encodeSliceForFormat 4 bao12k 1 1
  expectTrue "mid slice enc len" (midSlice.size == 4224)
  match decodeSliceForFormat 4 r12 12288 1 1 midSlice with
  | .ok s =>
    expectTrue "mid slice size" (s.size == 4096)
    expectTrue "mid slice bytes" (toHex s == toHex (bao12k.extract 4096 8192))
  | .error e => fail s!"mid slice decode: {repr e}"
  IO.println "three-leaf tree ok"

  -- Wrong format key → authenticationFailed
  match decodeInboardForFormat 6 r100 a100 with
  | Except.error .authenticationFailed => pure ()
  | Except.error e => fail s!"wrong format: expected authenticationFailed, got {repr e}"
  | Except.ok _ => fail "wrong format: ok"
  IO.println "wrong format key → authenticationFailed ok"

  -- Slice wrong key → authenticationFailed (stream path)
  match decodeSliceForFormat 6 rSlice 5000 0 1 sliceEnc with
  | Except.error .authenticationFailed => pure ()
  | Except.error e => fail s!"slice wrong key: expected authenticationFailed, got {repr e}"
  | Except.ok _ => fail "slice wrong key: ok"
  IO.println "slice wrong key → authenticationFailed ok"

  -- Truncated response → truncatedResponse
  match decodeInboardForFormat 4 r5k (a5k.extract 0 20) with
  | Except.error .truncatedResponse => pure ()
  | Except.error e => fail s!"trunc: expected truncatedResponse, got {repr e}"
  | Except.ok _ => fail "trunc: ok"
  IO.println "truncated response → truncatedResponse ok"

  -- Truncated slice response → truncatedResponse
  match decodeSliceForFormat 4 rSlice 5000 0 1 (sliceEnc.extract 0 20) with
  | Except.error .truncatedResponse => pure ()
  | Except.error e => fail s!"slice trunc: expected truncatedResponse, got {repr e}"
  | Except.ok _ => fail "slice trunc: ok"
  IO.println "truncated slice → truncatedResponse ok"

  -- Trailing garbage after valid inboard response → trailingData
  let mut trail := a100
  trail := trail.push 0xaa
  match decodeInboardForFormat 4 r100 trail with
  | Except.error .trailingData => pure ()
  | Except.error e => fail s!"trail: expected trailingData, got {repr e}"
  | Except.ok _ => fail "trail: ok"
  IO.println "trailing data → trailingData ok"

  -- Trailing garbage on slice response → trailingData
  let mut sliceTrail := sliceEnc
  sliceTrail := sliceTrail.push 0xbb
  match decodeSliceForFormat 4 rSlice 5000 0 1 sliceTrail with
  | Except.error .trailingData => pure ()
  | Except.error e => fail s!"slice trail: expected trailingData, got {repr e}"
  | Except.ok _ => fail "slice trail: ok"
  IO.println "slice trailing data → trailingData ok"

  -- Invalid prefix → invalidPrefix
  match Carbonado.Bao.Tree.contentLenPrefix (ofList [1, 2, 3]) with
  | Except.error .invalidPrefix => pure ()
  | Except.error e => fail s!"prefix: expected invalidPrefix, got {repr e}"
  | Except.ok _ => fail "prefix: ok"
  IO.println "short prefix → invalidPrefix ok"

  -- Invalid root length → invalidRootLength
  match decodeInboardForFormat 4 (ofList [0]) a100 with
  | Except.error .invalidRootLength => pure ()
  | Except.error e => fail s!"rootlen: expected invalidRootLength, got {repr e}"
  | Except.ok _ => fail "rootlen: ok"
  IO.println "bad root length → invalidRootLength ok"

  -- Invalid slice index → invalidSliceIndex
  match verifySliceInboardForFormat 4 r100 a100 5 1 with
  | Except.error .invalidSliceIndex => pure ()
  | Except.error e => fail s!"slice idx: expected invalidSliceIndex, got {repr e}"
  | Except.ok _ => fail "slice idx: ok"
  IO.println "bad slice index → invalidSliceIndex ok"

  -- count=0 on stream decode → invalidSliceCount
  match decodeSliceForFormat 4 rSlice 5000 0 0 sliceEnc with
  | Except.error .invalidSliceCount => pure ()
  | Except.error e => fail s!"slice count0: expected invalidSliceCount, got {repr e}"
  | Except.ok _ => fail "slice count0: ok"
  IO.println "slice count 0 → invalidSliceCount ok"

  -- Tampered inboard body → authenticationFailed
  let mut badArt := a100
  if badArt.size > 10 then
    badArt := badArt.set! 10 (badArt.get! 10 ^^^ 0x01)
  match decodeInboardForFormat 4 r100 badArt with
  | Except.error .authenticationFailed => pure ()
  | Except.error e => fail s!"tamper body: expected authenticationFailed, got {repr e}"
  | Except.ok _ => fail "tamper body: ok"
  IO.println "tampered body → authenticationFailed ok"

  -- Tampered slice response → authenticationFailed
  let mut badSlice := sliceEnc
  badSlice := badSlice.set! 70 (badSlice.get! 70 ^^^ 0x01)
  match decodeSliceForFormat 4 rSlice 5000 0 1 badSlice with
  | Except.error .authenticationFailed => pure ()
  | Except.error e => fail s!"slice tamper: expected authenticationFailed, got {repr e}"
  | Except.ok _ => fail "slice tamper: ok"
  IO.println "tampered slice → authenticationFailed ok"

  IO.println "bao stack ok"

  -- Program E: Header + pipeline c0–c15 + stream bounds + scrub + shard
  match Header.new master42 nonce11 (replicate 32 0xcd) (replicate 32 0) 5 0 100 0
      (replicate 8 0) with
  | .error e => fail s!"Header.new: {repr e}"
  | .ok h =>
    match h.toBytes with
    | .error e => fail s!"Header.toBytes: {repr e}"
    | .ok wire =>
      expectTrue "header wire 177" (wire.size == 177)
      match parseAndVerify master42 wire with
      | .ok h2 =>
        expectTrue "header roundtrip format" (h2.format == 5)
        expectTrue "header roundtrip nonce" (toHex h2.payloadNonce == toHex nonce11)
      | .error e => fail s!"parseAndVerify: {repr e}"
      -- Tamper header_mac → headerAuthenticationFailed
      let mut badWire := wire
      badWire := badWire.set! 28 (badWire.get! 28 ^^^ 0x01)
      match parseAndVerify master42 badWire with
      | .error .headerAuthenticationFailed => pure ()
      | .error e => fail s!"tamper hdr: expected headerAuthenticationFailed, got {repr e}"
      | .ok _ => fail "tamper hdr: ok"
  IO.println "header wire + verify ok"

  -- badMagic (HeaderError, mapped to PipelineError on decodeHeadered)
  match parseAndVerify master42 (replicate 177 0) with
  | .error .badMagic => pure ()
  | .error e => fail s!"badMagic: expected HeaderError.badMagic, got {repr e}"
  | .ok _ => fail "badMagic: ok"
  -- Full archive with bad magic after length pad → pipeline badMagic
  match decodeHeadered master42 (replicate 200 0) with
  | .error .badMagic => pure ()
  | .error e => fail s!"pipe badMagic: expected badMagic, got {repr e}"
  | .ok _ => fail "pipe badMagic: ok"
  IO.println "badMagic → HeaderError/PipelineError.badMagic ok"

  -- invalidHeaderLength
  match decodeHeadered master42 (ofList [1, 2, 3]) with
  | .error .invalidHeaderLength => pure ()
  | .error e => fail s!"short hdr: expected invalidHeaderLength, got {repr e}"
  | .ok _ => fail "short hdr: ok"
  IO.println "short header → invalidHeaderLength ok"

  -- invalidFieldLength
  match Header.new master42 nonce11 (ofList [1]) (replicate 32 0) 0 0 0 0 (replicate 8 0) with
  | .error .invalidFieldLength => pure ()
  | .error e => fail s!"bad field: expected invalidFieldLength, got {repr e}"
  | .ok _ => fail "bad field: ok"
  IO.println "invalidFieldLength ok"

  -- Format matrix body roundtrips (all 16 formats; AOT uses real zstd-20 when Compression bit set)
  match formatMatrixRoundtrip master42 nonce11 (utf8 "hi") with
  | .ok true => pure ()
  | .ok false => fail "format matrix: mismatch"
  | .error e => fail s!"format matrix: {repr e}"
  IO.println "format matrix c0–c15 roundtrip ok"

  -- Headered encrypted path (c5) + public bao (c4)
  match roundtripHeadered master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 5) with
  | .ok true => pure ()
  | .ok false => fail "headered c5 mismatch"
  | .error e => fail s!"headered c5: {repr e}"
  match roundtripHeadered master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 4) with
  | .ok true => pure ()
  | .ok false => fail "headered c4 mismatch"
  | .error e => fail s!"headered c4: {repr e}"
  -- c12 and c15 (FEC + Bao)
  match roundtripBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 12) with
  | .ok true => pure ()
  | .ok false => fail "c12 mismatch"
  | .error e => fail s!"c12: {repr e}"
  match roundtripBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 15) with
  | .ok true => pure ()
  | .ok false => fail "c15 mismatch"
  | .error e => fail s!"c15: {repr e}"
  IO.println "headered + c12/c15 roundtrip ok"

  -- encoded_len bound: short body → truncatedBody; trailer ignored (c0 + c5)
  match encodeHeadered master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 0) 0
      zeroSlhPk zeroMeta with
  | .error e => fail s!"enc c0 for len: {repr e}"
  | .ok (_h, arch) =>
    -- trailer after body still recovers
    let withTrailer := appendBA arch (ofList [0xaa, 0xbb, 0xcc])
    match decodeHeadered master42 withTrailer with
    | .ok pt => expectTrue "c0 trailer ignore" (toHex pt == toHex (utf8 "hello"))
    | .error e => fail s!"c0 trailer: {repr e}"
    -- short body
    if arch.size > headerLen + 1 then
      let short := arch.extract 0 (headerLen + 1)
      match decodeHeadered master42 short with
      | .error .truncatedBody => pure ()
      | .error e => fail s!"short body: expected truncatedBody, got {repr e}"
      | .ok _ => fail "short body: ok"
  match encodeHeadered master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 5) 0
      zeroSlhPk zeroMeta with
  | .error e => fail s!"enc c5 for trailer: {repr e}"
  | .ok (_h, arch) =>
    let withTrailer := appendBA arch (ofList [0xde, 0xad])
    match decodeHeadered master42 withTrailer with
    | .ok pt => expectTrue "c5 trailer ignore" (toHex pt == toHex (utf8 "hello"))
    | .error e => fail s!"c5 trailer: {repr e}"
  IO.println "encoded_len truncatedBody + trailer ignore ok"

  -- Payload auth failure via pipeline decrypt (embedded, tampered after encode)
  match encodeBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 1) false with
  | .error e => fail s!"enc c1: {repr e}"
  | .ok enc =>
    let mut bad := enc.body
    if bad.size > 20 then
      bad := bad.set! 20 (bad.get! 20 ^^^ 0x01)
    match decodeBody master42 nonce11 enc.baoHash bad enc.info.paddingLen
        (FormatBits.ofUInt8 1) false with
    | .error .payloadAuthenticationFailed => pure ()
    | .error e => fail s!"payload tamper: expected payloadAuthenticationFailed, got {repr e}"
    | .ok _ => fail "payload tamper: ok"
  IO.println "payload tamper → payloadAuthenticationFailed ok"

  -- Composition: short ciphertext → invalidCiphertextLength (c1, no Bao)
  match decodeBody master42 nonce11 zeroHash (replicate 10 0) 0
      (FormatBits.ofUInt8 1) false with
  | .error .invalidCiphertextLength => pure ()
  | .error e => fail s!"short ct pipe: expected invalidCiphertextLength, got {repr e}"
  | .ok _ => fail "short ct pipe: ok"
  -- Composition: FEC padding too large on empty body with pad>0
  match decodeBody master42 nonce11 zeroHash ByteArray.empty 5
      (FormatBits.ofUInt8 8) false with
  | .error .paddingTooLarge => pure ()
  | .error e => fail s!"pad large: expected paddingTooLarge, got {repr e}"
  | .ok _ => fail "pad large: ok"
  -- Composition: truncated Bao response via pipeline c4 (short prefix → invalidPrefix)
  match encodeBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 4) false with
  | .error e => fail s!"enc c4 trunc: {repr e}"
  | .ok enc =>
    match decodeBody master42 nonce11 enc.baoHash (enc.body.extract 0 4)
        enc.info.paddingLen (FormatBits.ofUInt8 4) false with
    | .error .invalidPrefix => pure ()
    | .error e => fail s!"trunc bao: expected invalidPrefix, got {repr e}"
    | .ok _ => fail "trunc bao: ok"
  -- Composition: trailing garbage after valid Bao inboard → trailingData
  match encodeBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 4) false with
  | .error e => fail s!"enc c4 trail: {repr e}"
  | .ok enc =>
    let trailed := appendBA enc.body (ofList [0xaa])
    match decodeBody master42 nonce11 enc.baoHash trailed
        enc.info.paddingLen (FormatBits.ofUInt8 4) false with
    | .error .trailingData => pure ()
    | .error e => fail s!"trail bao: expected trailingData, got {repr e}"
    | .ok _ => fail "trail bao: ok"
  -- Composition: invalid root length
  match encodeBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 4) false with
  | .error e => fail s!"enc c4 root: {repr e}"
  | .ok enc =>
    match decodeBody master42 nonce11 (ofList [0]) enc.body
        enc.info.paddingLen (FormatBits.ofUInt8 4) false with
    | .error .invalidRootLength => pure ()
    | .error e => fail s!"root len: expected invalidRootLength, got {repr e}"
    | .ok _ => fail "root len: ok"
  IO.println "composition invalidCiphertextLength + paddingTooLarge + bao trunc ok"

  -- invalidNonceLength / invalidKeyLength via pipeline
  match encodeBody master42 (replicate 8 0) (utf8 "hi") (FormatBits.ofUInt8 1) false with
  | .error .invalidNonceLength => pure ()
  | .error e => fail s!"bad nonce pipe: expected invalidNonceLength, got {repr e}"
  | .ok _ => fail "bad nonce pipe: ok"
  match encodeBody (replicate 16 0) nonce11 (utf8 "hi") (FormatBits.ofUInt8 1) false with
  | .error .invalidKeyLength => pure ()
  | .error e => fail s!"short master pipe: expected invalidKeyLength, got {repr e}"
  | .ok _ => fail "short master pipe: ok"
  IO.println "pipeline invalidNonceLength + invalidKeyLength ok"

  -- Bao auth fail via pipeline (wrong root on c4)
  match encodeBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 4) false with
  | .error e => fail s!"enc c4: {repr e}"
  | .ok enc =>
    let badRoot := replicate 32 0xaa
    match decodeBody master42 nonce11 badRoot enc.body enc.info.paddingLen
        (FormatBits.ofUInt8 4) false with
    | .error .baoAuthenticationFailed => pure ()
    | .error e => fail s!"bao wrong root: expected baoAuthenticationFailed, got {repr e}"
    | .ok _ => fail "bao wrong root: ok"
  IO.println "wrong bao root → baoAuthenticationFailed ok"

  -- FEC uneven via pipeline fec decode
  match fecDecodeStep (ofList [1, 2, 3]) 0 true with
  | .error .unevenShards => pure ()
  | .error e => fail s!"uneven pipe: expected unevenShards, got {repr e}"
  | .ok _ => fail "uneven pipe: ok"
  IO.println "fecDecodeStep uneven → unevenShards ok"

  -- ofFecError / ofBaoError / ofCryptoError exact maps (remaining taxonomy)
  expectTrue "map tooFew" (ofFecError .tooFewShards == .tooFewShards)
  expectTrue "map emptyShard" (ofFecError .emptyShard == .emptyShard)
  expectTrue "map incorrectSize" (ofFecError .incorrectShardSize == .incorrectShardSize)
  expectTrue "map badGeometry" (ofFecError .badGeometry == .badGeometry)
  expectTrue "map paddingTooLarge" (ofFecError .paddingTooLarge == .paddingTooLarge)
  expectTrue "map singular" (ofFecError .singularMatrix == .singularMatrix)
  expectTrue "map trunc" (ofBaoError .truncatedResponse == .truncatedResponse)
  expectTrue "map trail" (ofBaoError .trailingData == .trailingData)
  expectTrue "map prefix" (ofBaoError .invalidPrefix == .invalidPrefix)
  expectTrue "map rootLen" (ofBaoError .invalidRootLength == .invalidRootLength)
  expectTrue "map sliceIdx" (ofBaoError .invalidSliceIndex == .invalidSliceIndex)
  expectTrue "map sliceCnt" (ofBaoError .invalidSliceCount == .invalidSliceCount)
  expectTrue "map ctLen" (ofCryptoError .invalidCiphertextLength == .invalidCiphertextLength)
  -- Map-only residual (not reachable as distinct product pipeline paths without
  -- fabricating lower-layer inputs): tooFewShards, emptyShard, incorrectShardSize,
  -- singularMatrix, invalidSliceIndex, invalidSliceCount — see SPEC-MATRIX / PROOFS.
  IO.println "PipelineError taxonomy maps ok"

  -- Stream bounds
  expectTrue "stripe retain" (maxFecStripeRetain stripeUnit == 32768)
  expectTrue "empty retain" (maxFecStripeRetain 0 == 0)
  expectTrue "one-byte retain" (maxFecStripeRetain 1 == 32768)
  expectTrue "chunk eq slice" (chunkBytes == sliceLen)
  IO.println "stream stripe bounds ok"

  -- Scrub: requires verification
  match scrubInboardArchive (utf8 "x") (replicate 32 0) (FormatBits.ofUInt8 0) with
  | .error .scrubRequiresVerification => pure ()
  | .error e => fail s!"scrub noV: expected scrubRequiresVerification, got {repr e}"
  | .ok _ => fail "scrub noV: ok"
  IO.println "scrubRequiresVerification ok"

  -- Scrub: pristine → unnecessaryScrub
  match encodeBody master42 nonce11 (utf8 "hello") (FormatBits.ofUInt8 4) false with
  | .error e => fail s!"enc for scrub: {repr e}"
  | .ok enc =>
    match scrubInboardArchive enc.body enc.baoHash (FormatBits.ofUInt8 4) with
    | .error .unnecessaryScrub => pure ()
    | .error e => fail s!"pristine scrub: expected unnecessaryScrub, got {repr e}"
    | .ok _ => fail "pristine scrub: ok"
  IO.println "unnecessaryScrub ok"

  -- Scrub: knockout data shards, recover via RS + Bao root
  match Carbonado.Fec.Inboard.encodeInboard (utf8 "hello") with
  | .error e => fail s!"fec for scrub: {repr e}"
  | .ok (fecBody, pad, _) =>
    let (root, art) := encodeInboardForFormat 12 fecBody
    match scrubWithMissing fecBody root pad 12 [0, 1, 2, 3] with
    | .ok rec =>
      expectTrue "scrub recover len" (rec.size == art.size)
      expectTrue "scrub recover bytes" (toHex rec == toHex art)
    | .error e => fail s!"scrub knockout: {repr e}"
    -- Too many missing (5) → invalidScrubbedHash
    match scrubWithMissing fecBody root pad 12 [0, 1, 2, 3, 4] with
    | .error .invalidScrubbedHash => pure ()
    | .error e => fail s!"scrub too many: expected invalidScrubbedHash, got {repr e}"
    | .ok _ => fail "scrub too many: ok"
  -- Empty FEC body → badGeometry (no panic)
  match scrubWithMissing ByteArray.empty (replicate 32 0) 0 12 [0] with
  | .error .badGeometry => pure ()
  | .error e => fail s!"scrub empty: expected badGeometry, got {repr e}"
  | .ok _ => fail "scrub empty: ok"
  match scrubAfterKnockout ByteArray.empty (replicate 32 0) 0 12 [0] with
  | .error .badGeometry => pure ()
  | .error e => fail s!"scrubAfter empty: expected badGeometry, got {repr e}"
  | .ok _ => fail "scrubAfter empty: ok"
  IO.println "scrub knockout recovery + invalidScrubbedHash ok"

  -- Sharding
  let n0 := replicate 16 0x11
  let n1 := replicate 16 0x22
  let n2 := replicate 16 0x33
  match roundtripShards master42 (utf8 "abcdefghij") (FormatBits.ofUInt8 0) 4 #[n0, n1, n2] with
  | .ok true => pure ()
  | .ok false => fail "shards mismatch"
  | .error e => fail s!"shards: {repr e}"
  match encodeShards master42 (utf8 "ab") (FormatBits.ofUInt8 0) 0 #[n0] zeroSlhPk zeroMeta with
  | .error .emptySegment => pure ()
  | .error e => fail s!"budget0: expected emptySegment, got {repr e}"
  | .ok _ => fail "budget0: ok"
  -- insufficientNonces (distinct from invalidNonceLength)
  match encodeShards master42 (utf8 "abcdefghij") (FormatBits.ofUInt8 0) 4
      #[n0] zeroSlhPk zeroMeta with
  | .error .insufficientNonces => pure ()
  | .error e => fail s!"few nonces: expected insufficientNonces, got {repr e}"
  | .ok _ => fail "few nonces: ok"
  match validateChunkSequence #[0, 2] with
  | .error .invalidChunkSequence => pure ()
  | .error e => fail s!"gap seq: expected invalidChunkSequence, got {repr e}"
  | .ok _ => fail "gap seq: ok"
  match validateChunkSequence #[0, 0] with
  | .error .invalidChunkSequence => pure ()
  | .error e => fail s!"dup seq: expected invalidChunkSequence, got {repr e}"
  | .ok _ => fail "dup seq: ok"
  -- Structure label disagrees with verified header chunk_index
  match encodeShards master42 (utf8 "abcdefgh") (FormatBits.ofUInt8 0) 4
      #[n0, n1] zeroSlhPk zeroMeta with
  | .error e => fail s!"enc shards for label: {repr e}"
  | .ok shards =>
    if shards.size ≥ 1 then
      let s0 := shards[0]!
      let lied := { s0 with chunkIndex := 99 }
      match decodeShards master42 #[lied] with
      | .error .invalidChunkSequence => pure ()
      | .error e => fail s!"label lie: expected invalidChunkSequence, got {repr e}"
      | .ok _ => fail "label lie: ok"
  IO.println "shard roundtrip + sequence errors ok"

  -- Encrypted formats odd
  expectTrue "c15 odd" (formatC15.toUInt8 % 2 == 1)
  expectTrue "c14 even" (formatC14.toUInt8 % 2 == 0)
  IO.println "encrypted formats odd ok"

  IO.println "pipeline stack ok"

  ------------------------------------------------------------------
  -- Program F: zstd compress + SLH1 wire / bind-to-root
  ------------------------------------------------------------------
  expectTrue "zstd level 20" (zstdLevel == 20)
  expectTrue "zstd magic len" (zstdMagic.length == 4)
  -- Status mapping (pure)
  expectTrue "status empty" (match decodeStatusPayload ByteArray.empty with
    | .error .invalidInput => true | _ => false)
  expectTrue "status 1" (match decodeStatusPayload (ofList [1]) with
    | .error .compressionFailed => true | _ => false)
  expectTrue "status 2" (match decodeStatusPayload (ofList [2]) with
    | .error .decompressionFailed => true | _ => false)
  expectTrue "status 3" (match decodeStatusPayload (ofList [3]) with
    | .error .outputTooLarge => true | _ => false)
  expectTrue "status 4" (match decodeStatusPayload (ofList [4]) with
    | .error .invalidInput => true | _ => false)
  IO.println "zstd status mapping ok"

  -- Pipeline ofZstdError maps (distinct)
  expectTrue "map compressionFailed"
    (ofZstdError ZstdError.compressionFailed == PipelineError.compressionFailed)
  expectTrue "map decompressionFailed"
    (ofZstdError ZstdError.decompressionFailed == PipelineError.decompressionFailed)
  expectTrue "map outputTooLarge"
    (ofZstdError ZstdError.outputTooLarge == PipelineError.decompressOutputTooLarge)
  expectTrue "map invalidInput"
    (ofZstdError ZstdError.invalidInput == PipelineError.zstdInvalidInput)
  IO.println "PipelineError zstd maps ok"

  -- AOT real zstd: hello golden from ZSTD_compress API (level 20)
  let hello := utf8 "hello"
  match compressLevel20 hello with
  | .error e => fail s!"zstd compress hello: {repr e}"
  | .ok ct =>
    expectTrue "zstd hello magic" (hasZstdMagic ct)
    expectHex "zstd hello level20" ct "28b52ffd200529000068656c6c6f"
    match decompress ct with
    | .error e => fail s!"zstd decompress hello: {repr e}"
    | .ok pt => expectTrue "zstd hello roundtrip" (ctEq pt hello)
  -- Empty compress golden
  match compressLevel20 ByteArray.empty with
  | .error e => fail s!"zstd empty compress: {repr e}"
  | .ok ct =>
    expectHex "zstd empty level20" ct "28b52ffd2000010000"
    match decompress ct with
    | .error e => fail s!"zstd empty decompress: {repr e}"
    | .ok pt => expectTrue "zstd empty roundtrip" (ctEq pt ByteArray.empty)
  -- Corrupt frame → decompressionFailed (not lumped)
  match decompress (ofList [0x00, 0x01, 0x02, 0x03]) with
  | .error .decompressionFailed => pure ()
  | .error e => fail s!"corrupt zstd: expected decompressionFailed, got {repr e}"
  | .ok _ => fail "corrupt zstd: ok"
  -- Tiny maxOut on non-empty frame → outputTooLarge when content known
  match compressLevel20 hello with
  | .error e => fail s!"zstd for max: {repr e}"
  | .ok ct =>
    match decompressWithMax ct 1 with
    | .error .outputTooLarge => pure ()
    | .error e => fail s!"maxOut: expected outputTooLarge, got {repr e}"
    | .ok _ => fail "maxOut: ok"
  -- Highly compressible: many zeros → smaller than input under real zstd
  let zeros := replicate 4096 0
  match compressLevel20 zeros with
  | .error e => fail s!"zstd zeros: {repr e}"
  | .ok ct =>
    expectTrue "zstd zeros shrinks" (ct.size < zeros.size)
    match decompress ct with
    | .error e => fail s!"zstd zeros dec: {repr e}"
    | .ok pt => expectTrue "zstd zeros roundtrip" (ctEq pt zeros)
  IO.println "zstd goldens + roundtrip + error paths ok"

  -- Pipeline c2 (compression only) roundtrip under AOT zstd
  match roundtripBody master42 nonce11 hello (FormatBits.ofUInt8 2) with
  | .ok true => pure ()
  | .ok false => fail "c2 zstd pipeline mismatch"
  | .error e => fail s!"c2 zstd pipeline: {repr e}"
  -- c6 = compression + verification
  match roundtripBody master42 nonce11 hello (FormatBits.ofUInt8 6) with
  | .ok true => pure ()
  | .ok false => fail "c6 zstd+bao mismatch"
  | .error e => fail s!"c6 zstd+bao: {repr e}"
  -- Headered + compression: c3 (encrypted|compression) and c7 (E|C|V)
  match roundtripHeadered master42 nonce11 hello (FormatBits.ofUInt8 3) with
  | .ok true => pure ()
  | .ok false => fail "headered c3 zstd mismatch"
  | .error e => fail s!"headered c3 zstd: {repr e}"
  match roundtripHeadered master42 nonce11 hello (FormatBits.ofUInt8 7) with
  | .ok true => pure ()
  | .ok false => fail "headered c7 zstd mismatch"
  | .error e => fail s!"headered c7 zstd: {repr e}"
  IO.println "pipeline compression formats c2/c6 + headered c3/c7 ok"

  -- SLH1 wire
  expectTrue "slh magic" (ctEq slh1MagicBA (ofList [0x53, 0x4c, 0x48, 0x31]))
  expectTrue "slh sidecar len" (slh1SidecarLen == 7860)
  match buildSidecar (replicate slh1SignatureLen 0) with
  | .error e => fail s!"build sidecar: {repr e}"
  | .ok sc =>
    expectTrue "sidecar wire len" (sc.size == 7860)
    match parseSidecar sc with
    | .ok sig => expectTrue "parse sig zeros" (ctEq sig (replicate slh1SignatureLen 0))
    | .error e => fail s!"parse sidecar: {repr e}"
  match parseSidecar (ofList [1, 2, 3]) with
  | .error .invalidSidecarLength => pure ()
  | .error e => fail s!"short sidecar: expected invalidSidecarLength, got {repr e}"
  | .ok _ => fail "short sidecar: ok"
  match parseSidecar (replicate slh1SidecarLen 0) with
  | .error .badSlhMagic => pure ()
  | .error e => fail s!"bad magic: expected badSlhMagic, got {repr e}"
  | .ok _ => fail "bad magic: ok"
  match buildSidecar (ofList [1]) with
  | .error .invalidSignatureLength => pure ()
  | .error e => fail s!"short sig: expected invalidSignatureLength, got {repr e}"
  | .ok _ => fail "short sig: ok"
  IO.println "SLH1 wire framing ok"

  -- Bind-to-root (mock oracle) + full-length wire roundtrip (AOT only)
  let rootA := replicate hashLen 0xaa
  let rootB := replicate hashLen 0xbb
  let pk := replicate slhPublicKeyLen 0x11
  let goodSig := replicate slh1SignatureLen 0xcd
  let badSig := replicate slh1SignatureLen 0x00
  match buildSidecar goodSig with
  | .error e => fail s!"build full sidecar: {repr e}"
  | .ok sc =>
    expectTrue "full sidecar len" (sc.size == 7860)
    match parseSidecar sc with
    | .ok sig => expectTrue "full parse sig" (ctEq sig goodSig)
    | .error e => fail s!"parse full sidecar: {repr e}"
    -- wrong magic at exact length
    let badMag := appendBA (ofList [0, 0, 0, 0]) goodSig
    match parseSidecar badMag with
    | .error .badSlhMagic => pure ()
    | .error e => fail s!"bad magic full: expected badSlhMagic, got {repr e}"
    | .ok _ => fail "bad magic full: ok"
  match verifyBoundToExpected (mockOracleFor rootA goodSig) pk rootA rootB goodSig with
  | .error .verificationFailed => pure ()
  | .error e => fail s!"wrong root: expected verificationFailed, got {repr e}"
  | .ok _ => fail "wrong root: ok"
  match verifyBoundToExpected (mockOracleFor rootA goodSig) pk rootA rootA goodSig with
  | .ok () => pure ()
  | .error e => fail s!"correct root: {repr e}"
  match verifyBoundToExpected (mockOracleFor rootA goodSig) pk rootA rootA badSig with
  | .error .verificationFailed => pure ()
  | .error e => fail s!"bad sig: expected verificationFailed, got {repr e}"
  | .ok _ => fail "bad sig: ok"
  match signRoot (replicate 128 0x42) rootA with
  | .error .signatureUnavailable => pure ()
  | .error e => fail s!"sign: expected signatureUnavailable, got {repr e}"
  | .ok _ => fail "sign: ok"
  match signRoot (replicate 128 0x42) (ofList [1]) with
  | .error .invalidRootLength => pure ()
  | .error e => fail s!"sign root len: expected invalidRootLength, got {repr e}"
  | .ok _ => fail "sign root len: ok"
  match mkBinding (ofList [1]) rootA goodSig with
  | .error .invalidPublicKeyLength => pure ()
  | .error e => fail s!"pk len: expected invalidPublicKeyLength, got {repr e}"
  | .ok _ => fail "pk len: ok"
  IO.println "SLH bind-to-root + unavailable sign ok"

  IO.println "program F stack ok"

  -- ── Program G: Adamantine + Filepack + Directory ──
  expectTrue "adamantine magic len" (adamantineMagic.length == 13)
  expectTrue "adamantine header len" (adamantineHeaderLen == 19)
  let adamPayload := utf8 "catalog-body"
  let adamWire := encodeAdamantine adamPayload adamantineFmtPublic 0
  match decodeAdamantine adamWire with
  | .error e => fail s!"adamantine decode: {repr e}"
  | .ok (p, h) =>
    expectTrue "adamantine payload" (ctEq p adamPayload)
    expectTrue "adamantine fmt" (h.carbonadoFmt == adamantineFmtPublic)
    expectTrue "adamantine flags" (h.flags == 0)
  match decodeAdamantine (encodeAdamantine ByteArray.empty adamantineFmtPublic 2) with
  | .error (.invalidFlags 2) => pure ()
  | .error e => fail s!"adam flags: expected invalidFlags 2, got {repr e}"
  | .ok _ => fail "adam flags: ok"
  match decodeAdamantine (encodeAdamantine ByteArray.empty 0 0) with
  | .error (.invalidCarbonadoFormat 0) => pure ()
  | .error e => fail s!"adam fmt: expected invalidCarbonadoFormat, got {repr e}"
  | .ok _ => fail "adam fmt: ok"
  match decodeAdamantine (appendBA adamantineMagicDevV2 (replicate 7 0)) with
  | .error (.unsupportedVersion 2 0) => pure ()
  | .error e => fail s!"adam dev2: expected unsupportedVersion 2 0, got {repr e}"
  | .ok _ => fail "adam dev2: ok"
  match decodeAdamantine (ofList [1, 2, 3]) with
  | .error .invalidHeader => pure ()
  | .error e => fail s!"adam short: expected invalidHeader, got {repr e}"
  | .ok _ => fail "adam short: ok"
  match buildPayload (utf8 "man") (utf8 "bun") with
  | .error e => fail s!"buildPayload: {repr e}"
  | .ok pl =>
    match splitPayload pl with
    | .error e => fail s!"splitPayload: {repr e}"
    | .ok (m, b) =>
      expectTrue "payload man" (ctEq m (utf8 "man"))
      expectTrue "payload bun" (ctEq b (utf8 "bun"))
  IO.println "adamantine wire ok"

  -- Path validation
  match validateRelPath "" with
  | .error .emptyRelPath => pure ()
  | _ => fail "rel empty"
  match validateRelPath "a/../b" with
  | .error .relPathTraversal => pure ()
  | _ => fail "rel traversal"
  match validateRelPath "/abs" with
  | .error .relPathAbsolute => pure ()
  | _ => fail "rel absolute"
  match validateRelPath "a\\b" with
  | .error .relPathBackslash => pure ()
  | _ => fail "rel backslash"
  match validateRelPath "a//b" with
  | .error .relPathEmptyComponent => pure ()
  | _ => fail "rel empty component"
  match validateRelPath "ok/file.txt" with
  | .ok () => pure ()
  | _ => fail "rel ok"
  IO.println "filepack path rules ok"

  -- Outboard c12/c14 roundtrip
  let pubMaster := replicate 32 0
  match roundtripOutboard pubMaster nonce11 (utf8 "hello-outboard") (FormatBits.ofUInt8 12) with
  | .error e => fail s!"outboard c12: {repr e}"
  | .ok false => fail "outboard c12 mismatch"
  | .ok true => pure ()
  match roundtripOutboard pubMaster nonce11 (utf8 "hello-c14") (FormatBits.ofUInt8 14) with
  | .error e => fail s!"outboard c14: {repr e}"
  | .ok false => fail "outboard c14 mismatch"
  | .ok true => pure ()
  match roundtripOutboard master42 nonce11 (utf8 "secret-seg") (FormatBits.ofUInt8 13) with
  | .error e => fail s!"outboard c13: {repr e}"
  | .ok false => fail "outboard c13 mismatch"
  | .ok true => pure ()
  IO.println "outboard segment roundtrip ok"

  -- Directory pure roundtrip (public)
  let dirFiles : Array DirFile := #[
    { relPath := "a.txt", content := utf8 "alpha" },
    { relPath := "sub/b.txt", content := utf8 "beta" }
  ]
  let dirOpts : DirectoryEncodeOptions := {
    catalogEncrypted := false
    segmentPolicy := .forceCompressed
  }
  match roundtripDirectory pubMaster dirFiles dirOpts #[] with
  | .error e => fail s!"directory public roundtrip: {repr e}"
  | .ok false => fail "directory public content mismatch"
  | .ok true => pure ()
  -- Encrypted directory
  let encOpts : DirectoryEncodeOptions := {
    catalogEncrypted := true
    segmentPolicy := .forceCompressed
  }
  -- 2 files + 1 catalog nonce
  let n0 := replicate 16 0x10
  let n1 := replicate 16 0x20
  let n2 := replicate 16 0x30
  match roundtripDirectory master42 dirFiles encOpts #[n0, n1, n2] with
  | .error e => fail s!"directory encrypted roundtrip: {repr e}"
  | .ok false => fail "directory encrypted content mismatch"
  | .ok true => pure ()
  -- Path traversal rejected at encode
  let badFiles : Array DirFile := #[{ relPath := "../evil", content := utf8 "x" }]
  match encodeDirectory pubMaster badFiles dirOpts #[] with
  | .error .pathTraversal => pure ()
  | .error e => fail s!"traversal: expected pathTraversal, got {repr e}"
  | .ok _ => fail "traversal: ok"
  match encodeDirectory pubMaster #[{ relPath := "/abs", content := utf8 "x" }] dirOpts #[] with
  | .error .pathAbsolute => pure ()
  | .error e => fail s!"absolute: expected pathAbsolute, got {repr e}"
  | .ok _ => fail "absolute: ok"
  -- Zero master on encrypted rejected
  match encodeDirectory pubMaster dirFiles encOpts #[n0, n1, n2] with
  | .error .zeroMasterKeyNotAllowed => pure ()
  | .error e => fail s!"zero master enc: expected zeroMasterKeyNotAllowed, got {repr e}"
  | .ok _ => fail "zero master enc: ok"
  -- Non-zero master on public rejected
  match encodeDirectory master42 dirFiles dirOpts #[] with
  | .error .encryptedDirectoryNotRequested => pure ()
  | .error e => fail s!"public non-zero: expected encryptedDirectoryNotRequested, got {repr e}"
  | .ok _ => fail "public non-zero: ok"
  -- Catalog name parse
  match parseCatalogName "aa.adam.c14" with
  | .error .invalidCatalogPath => pure ()
  | _ => fail "short catalog name"
  -- requireOts rejected at encode (not minting undecodeable archives)
  match encodeDirectory pubMaster dirFiles { catalogEncrypted := false, segmentPolicy := .forceRaw, requireOts := true } #[] with
  | .error .otsFeatureRequired => pure ()
  | .error e => fail s!"requireOts encode: expected otsFeatureRequired, got {repr e}"
  | .ok _ => fail "requireOts encode: ok"
  IO.println "directory pure encode/decode ok"

  -- Exact-variant decode failures (AOT; after a good encode)
  match encodeDirectory pubMaster
      #[{ relPath := "only.txt", content := utf8 "payload" }]
      { catalogEncrypted := false, segmentPolicy := .forceRaw } #[] with
  | .error e => fail s!"encode for tamper tests: {repr e}"
  | .ok arch =>
    -- catalogBaoRootMismatch: wrong root in structure vs filename
    let badRootArch := { arch with catalogBaoRoot := replicate 32 0xab }
    match decodeDirectory pubMaster badRootArch with
    | .error .catalogBaoRootMismatch => pure ()
    | .error e => fail s!"catalog root: expected catalogBaoRootMismatch, got {repr e}"
    | .ok _ => fail "catalog root: ok"
    -- missingSegment: drop all segment artifacts
    let noSegs := { arch with segments := #[] }
    match decodeDirectory pubMaster noSegs with
    | .error .missingSegment => pure ()
    | .error e => fail s!"missing segment: expected missingSegment, got {repr e}"
    | .ok _ => fail "missing segment: ok"
    -- segmentMainLenMismatch: truncate main bytes
    if arch.segments.size > 0 then
      let s0 := arch.segments[0]!
      let shortMain :=
        if s0.main.size > 0 then s0.main.extract 0 (s0.main.size - 1) else s0.main
      let badLenSegs := #[ { s0 with main := shortMain } ]
      match decodeDirectory pubMaster { arch with segments := badLenSegs } with
      | .error .segmentMainLenMismatch => pure ()
      | .error e => fail s!"main len: expected segmentMainLenMismatch, got {repr e}"
      | .ok _ => fail "main len: ok"
  -- contentBlake3Mismatch exact helper (integrated into decodeDirectory)
  match checkContentBlake3 (utf8 "hello") (replicate 32 0) with
  | .error .contentBlake3Mismatch => pure ()
  | .error e => fail s!"blake3 helper: expected contentBlake3Mismatch, got {repr e}"
  | .ok _ => fail "blake3 helper: ok"
  match checkContentBlake3 ByteArray.empty (Carbonado.Bao.Blake3.hash ByteArray.empty) with
  | .ok () => pure ()
  | .error e => fail s!"blake3 helper ok path: {repr e}"
  IO.println "directory exact failure modes ok"

  -- DirectoryError maps (1:1)
  expectTrue "map traversal" (ofFilepackError .relPathTraversal == DirectoryError.pathTraversal)
  expectTrue "map absolute" (ofFilepackError .relPathAbsolute == DirectoryError.pathAbsolute)
  expectTrue "map backslash" (ofFilepackError .relPathBackslash == DirectoryError.pathBackslash)
  expectTrue "map null" (ofFilepackError .relPathNullByte == DirectoryError.pathNullByte)
  expectTrue "map empty component" (ofFilepackError .relPathEmptyComponent == DirectoryError.pathEmptyComponent)
  expectTrue "map tooManySegments" (ofFilepackError .tooManySegments == DirectoryError.tooManySegments)
  expectTrue "map otsProofTooLarge" (ofFilepackError .otsProofTooLarge == DirectoryError.otsProofTooLarge)
  expectTrue "map adam flags" (ofAdamantineError (.invalidFlags 3) == .invalidAdamantineFlags 3)
  expectTrue "map adam magic" (ofAdamantineError .invalidMagic == .invalidAdamantineMagic)
  -- Bundle semantics exact
  match validateSegmentBundleSemantics 0x0C {
      segmentBaoRoot := replicate 32 0, chunkIndex := 0, mainLen := 1,
      verificationOutboardOffset := 0, verificationOutboardLen := 0,
      fecParityOffset := 0, fecParityLen := 0 } with
  | .error .missingFecParity => pure ()
  | .error e => fail s!"bundle missing fec: {repr e}"
  | .ok _ => fail "bundle missing fec: ok"
  match validateSegmentBundleSemantics 0x0C {
      segmentBaoRoot := replicate 32 0, chunkIndex := 0, mainLen := 1,
      verificationOutboardOffset := 0, verificationOutboardLen := 0,
      fecParityOffset := 0, fecParityLen := 1 } with
  | .error .fecParityLenMismatch => pure ()
  | .error e => fail s!"bundle fec len: {repr e}"
  | .ok _ => fail "bundle fec len: ok"
  IO.println "directory error taxonomy ok"

  IO.println "program G stack ok"
  IO.println s!"version = {Carbonado.Cli.versionString}"

/-- Entry: CLI subcommands or default demo (flake `checks.demo`). -/
def main (args : List String) : IO UInt32 := do
  match args with
  | [] | ["demo"] =>
    runDemo
    pure 0
  | cmd :: rest =>
    Carbonado.Cli.runCommand cmd rest
