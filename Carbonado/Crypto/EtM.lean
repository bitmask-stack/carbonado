/-
  Carbonado v2 symmetric Encrypt-then-MAC stack.

  Normative (AGENTS.md §2.1):
  * Subkeys: `HMAC-SHA512(master, "carbonado-v2/" || label)` → 64 bytes
  * AES-256-CTR (`Ctr128BE`) with 16-byte nonce
  * Payload EtM: `tag = HMAC-SHA512(etm-hmac, "carbonado-v2-etm" || nonce || ct)`
  * Header-path layout: `[tag(64) | ct]`
  * Low-level layout: `[nonce(16) | tag(64) | ct]`
  * Header MAC: `HMAC-SHA512(header-auth, auth_data)` (MAGIC is domain in auth_data)
  * **MAC-before-decrypt**: tag verified before any keystream is applied

  Error check order on decrypt (parity with Rust `symmetric_decrypt_with_nonce`):
  1. ciphertext length (`invalidCiphertextLength`)
  2. master key length (`invalidKeyLength`)
  3. nonce length (`invalidNonceLength`)
  4. MAC verify (`authenticationFailed`) then keystream
-/
import Carbonado.Constants
import Carbonado.Crypto.AESCTR
import Carbonado.Crypto.HMAC
import Carbonado.Crypto.Util

namespace Carbonado.Crypto.EtM

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Crypto.HMAC
open Carbonado.Crypto.AESCTR

/-- Crypto error taxonomy (strict matches in tests; distinct failure modes). -/
inductive CryptoError where
  | invalidKeyLength
  | invalidCiphertextLength
  | invalidNonceLength
  | authenticationFailed
  deriving DecidableEq, Repr

/-- Decrypt result: plaintext is only present on success. -/
inductive DecryptResult where
  | ok (plaintext : ByteArray)
  | error (e : CryptoError)
  -- No `Repr` (ByteArray has no Repr instance in core Lean 4.30).

/-- True iff the result carries plaintext. -/
def DecryptResult.isOk : DecryptResult → Bool
  | .ok _ => true
  | .error _ => false

/-- Extract plaintext if present. -/
def DecryptResult.plaintext? : DecryptResult → Option ByteArray
  | .ok pt => some pt
  | .error _ => none

/-- Minimum master key length (high-entropy 32 bytes; 64 also accepted). -/
def minMasterLen : Nat := 32

/-- Derive a 64-byte subkey: `HMAC-SHA512(master, "carbonado-v2/" || label)`. -/
def deriveSubkey (master : ByteArray) (label : String) : Except CryptoError ByteArray :=
  if master.size == 0 then
    .error .invalidKeyLength
  else
    let msg := appendBA (utf8 subkeyDomainPrefix) (utf8 label)
    .ok (hmacSHA512 master msg)

/-- Derive using the registered `SubkeyLabel` enum. -/
def deriveSubkeyLabel (master : ByteArray) (label : SubkeyLabel) : Except CryptoError ByteArray :=
  deriveSubkey master label.toString

/-- First 32 bytes of `aes-ctr` subkey → AES-256 key. -/
def aesKeyOfMaster (master : ByteArray) : Except CryptoError ByteArray :=
  match deriveSubkey master "aes-ctr" with
  | .error e => .error e
  | .ok material =>
    if material.size < 32 then .error .invalidKeyLength
    else .ok (material.extract 0 32)

/-- Full 64-byte `etm-hmac` subkey. -/
def etmKeyOfMaster (master : ByteArray) : Except CryptoError ByteArray :=
  deriveSubkey master "etm-hmac"

/-- Full 64-byte `header-auth` subkey. -/
def headerAuthKeyOfMaster (master : ByteArray) : Except CryptoError ByteArray :=
  deriveSubkey master "header-auth"

/-- Payload EtM MAC input: `"carbonado-v2-etm" || nonce || ciphertext`. -/
def etmMacInput (nonce ct : ByteArray) : ByteArray :=
  appendBA (appendBA (utf8 etmDomain) nonce) ct

/-- Compute the 64-byte payload EtM tag. -/
def computePayloadTag (macKey nonce ct : ByteArray) : ByteArray :=
  hmacSHA512 macKey (etmMacInput nonce ct)

/-- Header-path encrypt: output `[tag(64) | ct]`. Nonce stored out-of-band (Header). -/
def encryptWithNonce (master nonce plaintext : ByteArray) : Except CryptoError ByteArray :=
  if master.size < minMasterLen then
    .error .invalidKeyLength
  else if nonce.size != nonceLen then
    .error .invalidNonceLength
  else
    match aesKeyOfMaster master, etmKeyOfMaster master with
    | .error e, _ => .error e
    | _, .error e => .error e
    | .ok aesKey, .ok macKey =>
      let ct := ctrXor aesKey nonce plaintext
      let tag := computePayloadTag macKey nonce ct
      .ok (appendBA tag ct)

/--
  Core MAC-then-decrypt step (keys already derived).

  Keystream (`ctrXor`) is applied **only** in the success branch after `ctEq`.
  The tag check is the condition of the `if` — plaintext is not built on failure.
-/
def decryptAfterMacCheck (aesKey macKey nonce tag ct : ByteArray) : DecryptResult :=
  if ctEq tag (computePayloadTag macKey nonce ct) then
    .ok (ctrXor aesKey nonce ct)
  else
    .error .authenticationFailed

/--
  Header-path decrypt: input `[tag(64) | ct]`.

  **MAC-before-decrypt:** `decryptAfterMacCheck` verifies the full 64-byte tag
  before constructing any `.ok` plaintext.

  Guard order matches Rust `symmetric_decrypt_with_nonce`:
  ciphertext length → master length → nonce length → MAC.
-/
def decryptWithNonce (master nonce input : ByteArray) : DecryptResult :=
  if input.size < hmacTagLen then
    .error .invalidCiphertextLength
  else if master.size < minMasterLen then
    .error .invalidKeyLength
  else if nonce.size != nonceLen then
    .error .invalidNonceLength
  else
    let tag := input.extract 0 hmacTagLen
    let ct := input.extract hmacTagLen input.size
    match aesKeyOfMaster master, etmKeyOfMaster master with
    | .error e, _ => .error e
    | _, .error e => .error e
    | .ok aesKey, .ok macKey =>
      decryptAfterMacCheck aesKey macKey nonce tag ct

/-- Low-level encrypt: `[nonce(16) | tag(64) | ct]` (caller supplies nonce). -/
def encryptEmbeddedNonce (master nonce plaintext : ByteArray) : Except CryptoError ByteArray :=
  match encryptWithNonce master nonce plaintext with
  | .error e => .error e
  | .ok inner =>
    -- `encryptWithNonce` already requires `nonce.size = nonceLen`.
    .ok (appendBA nonce inner)

/--
  Low-level decrypt for `[nonce(16) | tag(64) | ct]`.
  Same MAC-before-decrypt discipline as `decryptWithNonce`.
-/
def decryptEmbeddedNonce (master input : ByteArray) : DecryptResult :=
  if input.size < nonceLen + hmacTagLen then
    .error .invalidCiphertextLength
  else
    let nonce := input.extract 0 nonceLen
    let rest := input.extract nonceLen input.size
    decryptWithNonce master nonce rest

/-- Header MAC: `HMAC-SHA512(header-auth subkey, auth_data)` — no extra domain string. -/
def computeHeaderMac (master authData : ByteArray) : Except CryptoError ByteArray :=
  if master.size < minMasterLen then
    .error .invalidKeyLength
  else
    match headerAuthKeyOfMaster master with
    | .error e => .error e
    | .ok key => .ok (hmacSHA512 key authData)

/-- Verify a header MAC; true only on exact 64-byte match. -/
def verifyHeaderMac (master authData tag : ByteArray) : Except CryptoError Bool :=
  match computeHeaderMac master authData with
  | .error e => .error e
  | .ok expected => .ok (ctEq tag expected)

/-!
  ## MAC-before-decrypt theorems

  Control-flow contract: `.ok plaintext` is only constructed after `ctEq` succeeds.
  No constant-time claim (see docs/LIMITS.md).
-/

/-- Tag mismatch ⇒ authentication failure (no plaintext). -/
theorem decryptAfterMacCheck_tag_fail
    (aesKey macKey nonce tag ct : ByteArray)
    (h : ctEq tag (computePayloadTag macKey nonce ct) = false) :
    decryptAfterMacCheck aesKey macKey nonce tag ct = .error .authenticationFailed := by
  unfold decryptAfterMacCheck
  rw [if_neg (by simp [h])]

/-- Successful core decrypt ⇒ tag matched (MAC verified before keystream use). -/
theorem decryptAfterMacCheck_ok_implies_mac
    (aesKey macKey nonce tag ct pt : ByteArray)
    (h : decryptAfterMacCheck aesKey macKey nonce tag ct = .ok pt) :
    ctEq tag (computePayloadTag macKey nonce ct) = true := by
  unfold decryptAfterMacCheck at h
  by_cases hct : ctEq tag (computePayloadTag macKey nonce ct) = true
  · exact hct
  · have hctf : ctEq tag (computePayloadTag macKey nonce ct) = false := by
      cases hc : ctEq tag (computePayloadTag macKey nonce ct) <;> simp_all
    simp [hctf] at h

/-- Authentication failure carries no plaintext. -/
theorem decryptAfterMacCheck_auth_fail_no_plaintext
    (aesKey macKey nonce tag ct : ByteArray)
    (h : ctEq tag (computePayloadTag macKey nonce ct) = false) :
    (decryptAfterMacCheck aesKey macKey nonce tag ct).plaintext? = none := by
  rw [decryptAfterMacCheck_tag_fail aesKey macKey nonce tag ct h]
  rfl

/-- `.ok` is the only constructor that embeds plaintext bytes. -/
theorem decryptResult_ok_iff_plaintext
    (r : DecryptResult) (pt : ByteArray) :
    r = .ok pt ↔ r.plaintext? = some pt := by
  cases r with
  | ok p =>
    constructor
    · intro h; cases h; rfl
    · intro h
      simp only [DecryptResult.plaintext?] at h
      injection h with h'
      subst h'
      rfl
  | error e =>
    constructor
    · intro h; cases h
    · intro h; cases h

/-- Short ciphertext is rejected first (Rust parity: length before master). -/
theorem decryptWithNonce_short_input
    (master nonce input : ByteArray)
    (hs : (input.size < hmacTagLen) = true) :
    decryptWithNonce master nonce input = .error .invalidCiphertextLength := by
  unfold decryptWithNonce
  simp [hs]

/--
  Short master key is rejected when the ciphertext is long enough to pass the
  length gate (Rust order: CT length first, then master).
-/
theorem decryptWithNonce_short_master
    (master nonce input : ByteArray)
    (hs : (input.size < hmacTagLen) = false)
    (hm : (master.size < minMasterLen) = true) :
    decryptWithNonce master nonce input = .error .invalidKeyLength := by
  unfold decryptWithNonce
  simp [hs, hm]

/-- Bad nonce length is a distinct error (not `invalidCiphertextLength`). -/
theorem decryptWithNonce_bad_nonce
    (master nonce input : ByteArray)
    (hs : (input.size < hmacTagLen) = false)
    (hm : (master.size < minMasterLen) = false)
    (hn : (nonce.size != nonceLen) = true) :
    decryptWithNonce master nonce input = .error .invalidNonceLength := by
  unfold decryptWithNonce
  simp [hs, hm, hn]

end Carbonado.Crypto.EtM
