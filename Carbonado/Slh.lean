/-
  SLH-DSA-SHA2-128s sidecar wire format + Bao-root binding (Program F / R9 G10).

  Normative (AGENTS §2.3):
  * Sidecar: `SLH1` (4) + raw signature (7856) = 7860 bytes
  * Public key (32 B) lives in Header.slh_public_key, not the sidecar
  * Signature is over the 32-byte Bao root of the target container

  **G10 (R9):** real SLH-DSA via `@[extern]` into libbitcoinpqc objects linked
  in `libcarbonado_native.a` (`nix/native/carbonado_slh.c`). Lean elaborator
  bodies are fail-closed fallbacks (do **not** `native_decide` over live crypto).
  AOT `Main` / C ABI / dual-suite composition exercise the real oracle.

  Dual-suite product SLH may still use Rust `bitcoinpqc` composition; pure Lean
  is for `libcarbonado` purity. Composition remains SSOT for dual-suite wire.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util

namespace Carbonado.Slh

open Carbonado.Constants
open Carbonado.Crypto.Util

/-- Strict SLH/sidecar error taxonomy (exact-match in tests). -/
inductive SlhError where
  /-- Sidecar byte length ≠ 7860. -/
  | invalidSidecarLength
  /-- First 4 bytes ≠ `SLH1`. -/
  | badSlhMagic
  /-- Signature material length ≠ 7856. -/
  | invalidSignatureLength
  /-- Public key length ≠ 32. -/
  | invalidPublicKeyLength
  /-- Claimed Bao root length ≠ 32. -/
  | invalidRootLength
  /-- Signature verification failed (oracle returned false). -/
  | verificationFailed
  /-- Keygen/sign refused (bad params, crypto failure). -/
  | signatureUnavailable
  /-- Entropy shorter than 128 bytes for keygen. -/
  | invalidEntropyLength
  deriving DecidableEq, Repr

/-- Detached SLH1 sidecar contents (signature only; pk is out-of-band). -/
structure SlhSidecar where
  signature : ByteArray
  deriving DecidableEq

/-- Binding of public key + Bao root + signature (product verification view). -/
structure SlhBinding where
  publicKey : ByteArray
  baoRoot : ByteArray
  signature : ByteArray
  deriving DecidableEq

/-- Expected SLH1 magic as ByteArray. -/
def slh1MagicBA : ByteArray :=
  ofList slh1Magic

/-- True iff `wire` begins with the 4-byte `SLH1` magic (no length check). -/
def slh1MagicPrefix (wire : ByteArray) : Bool :=
  wire.size ≥ 4 && ctEq (wire.extract 0 4) slh1MagicBA

/--
  Magic check for an **exact-length** sidecar body (after size gate).
  Distinct from `invalidSidecarLength` — used so `badSlhMagic` is theorem-tested
  without allocating 7860 bytes under `native_decide`.
-/
def parseMagicAtExactLen (bytes : ByteArray) : Except SlhError ByteArray :=
  if !slh1MagicPrefix bytes then
    .error .badSlhMagic
  else
    .ok (bytes.extract 4 bytes.size)

/-- Build on-disk sidecar bytes from a raw 7856-byte signature. -/
def buildSidecar (signature : ByteArray) : Except SlhError ByteArray :=
  if signature.size != slh1SignatureLen then
    .error .invalidSignatureLength
  else
    .ok (appendBA slh1MagicBA signature)

/--
  Parse and validate SLH1 sidecar wire.
  Returns the raw 7856-byte signature (matches Rust `read_slh_sidecar`).
  Order: length → magic → extract (short good-magic prefix → length error first).
-/
def parseSidecar (bytes : ByteArray) : Except SlhError ByteArray :=
  if bytes.size != slh1SidecarLen then
    .error .invalidSidecarLength
  else
    parseMagicAtExactLen bytes

/-- Validate field sizes and construct a binding (no crypto). -/
def mkBinding (publicKey baoRoot signature : ByteArray) : Except SlhError SlhBinding :=
  if publicKey.size != slhPublicKeyLen then
    .error .invalidPublicKeyLength
  else if baoRoot.size != hashLen then
    .error .invalidRootLength
  else if signature.size != slh1SignatureLen then
    .error .invalidSignatureLength
  else
    .ok { publicKey := publicKey, baoRoot := baoRoot, signature := signature }

/--
  Build binding from Header pk + root + sidecar file bytes.
  Fail-closed on wire errors before any verify oracle is consulted.
-/
def bindingFromSidecar (publicKey baoRoot sidecarBytes : ByteArray) :
    Except SlhError SlhBinding :=
  match parseSidecar sidecarBytes with
  | .error e => .error e
  | .ok sig => mkBinding publicKey baoRoot sig

/--
  Verify that a signature is bound to a **specific** Bao root.

  `verifyOracle pk message sig` is the SLH-DSA verify predicate (true = accept).
-/
def verifyBound (verifyOracle : ByteArray → ByteArray → ByteArray → Bool)
    (publicKey claimedRoot signature : ByteArray) : Except SlhError Unit :=
  match mkBinding publicKey claimedRoot signature with
  | .error e => .error e
  | .ok b =>
    if verifyOracle b.publicKey b.baoRoot b.signature then
      .ok ()
    else
      .error .verificationFailed

/--
  Bind-to-root check: signature must verify over `expectedRoot`, and the
  claimed message root must equal `expectedRoot` (ctEq). Wrong root →
  `verificationFailed` even if a confused oracle would accept another message.
-/
def verifyBoundToExpected (verifyOracle : ByteArray → ByteArray → ByteArray → Bool)
    (publicKey expectedRoot claimedRoot signature : ByteArray) :
    Except SlhError Unit :=
  if expectedRoot.size != hashLen then
    .error .invalidRootLength
  else if claimedRoot.size != hashLen then
    .error .invalidRootLength
  else if !ctEq expectedRoot claimedRoot then
    .error .verificationFailed
  else
    verifyBound verifyOracle publicKey claimedRoot signature

/--
  Mock oracle for pure tests: accepts iff `sig` equals `acceptedSig` and
  `message` equals `acceptedRoot`. Used only for binding model tests.
-/
def mockOracleFor (acceptedRoot acceptedSig : ByteArray)
    (_pk message sig : ByteArray) : Bool :=
  ctEq message acceptedRoot && ctEq sig acceptedSig

/-! ## Live SLH-DSA via libbitcoinpqc (G10)

  Status-prefixed blobs match `carbonado_slh.c` / zstd pattern.
  Elaborator bodies are fail-closed (status **3** / verify 0) — not for `native_decide`.
  Status 1 is reserved for short entropy only (see `decodeSlhStatusPayload`).
-/

/-- Status-prefix helper for elaborator `@[extern]` bodies (keygen/sign).

  Uses status **3** (crypto / unavailable), not 1 (short entropy), so elaborator
  fallbacks map to `signatureUnavailable` rather than `invalidEntropyLength`.
-/
def slhStatusFail : ByteArray :=
  ByteArray.mk #[3]

/--
  Raw keygen: entropy (≥128) → `[status][pk 32 | sk 64]`.
  AOT: real `slh_dsa_sha2_128s_keygen`. Elaborator: status 3 fail.
-/
@[extern "carbonado_slh_keygen_raw"]
def keygenRaw (entropy : @& ByteArray) : ByteArray :=
  slhStatusFail

/--
  Raw sign: sk (64) + message → `[status][sig 7856]`.
  AOT: real deterministic `slh_dsa_sha2_128s_sign`. Elaborator: status 3 fail.
-/
@[extern "carbonado_slh_sign_raw"]
def signRaw (sk : @& ByteArray) (message : @& ByteArray) : ByteArray :=
  slhStatusFail

/--
  Raw verify: pk + message + sig → `1` accept / `0` reject.
  AOT: real `slh_dsa_sha2_128s_verify`. Elaborator: always reject (fail-closed).
-/
@[extern "carbonado_slh_verify_raw"]
def verifyRaw (pk : @& ByteArray) (message : @& ByteArray) (signature : @& ByteArray) : UInt8 :=
  0

/-- Decode status-prefixed keygen/sign blob (SLH-specific; not Compress zstd).

  Status codes from `carbonado_slh.c`:
  * 0 → ok payload
  * 1 → short entropy (`invalidEntropyLength`)
  * 2 → other bad argument (`signatureUnavailable`)
  * 3+ → crypto failure (`signatureUnavailable`)
-/
def decodeSlhStatusPayload (raw : ByteArray) : Except SlhError ByteArray :=
  if raw.size == 0 then
    .error .signatureUnavailable
  else
    let code := raw.get! 0
    if code == 0 then
      .ok (raw.extract 1 raw.size)
    else if code == 1 then
      .error .invalidEntropyLength
    else
      .error .signatureUnavailable

/-- Keygen from ≥128 bytes entropy → `(publicKey, secretKey)`. -/
def keygen (entropy : ByteArray) : Except SlhError (ByteArray × ByteArray) :=
  if entropy.size < 128 then
    .error .invalidEntropyLength
  else
    match decodeSlhStatusPayload (keygenRaw entropy) with
    | .error e => .error e
    | .ok payload =>
      if payload.size != slhPublicKeyLen + 64 then
        .error .signatureUnavailable
      else
        .ok (payload.extract 0 slhPublicKeyLen, payload.extract slhPublicKeyLen payload.size)

/-- Live SLH-DSA verify predicate for `verifyBound` / CLI. -/
def liveVerifyOracle (pk message sig : ByteArray) : Bool :=
  verifyRaw pk message sig == 1

/-- Sign a 32-byte Bao root with a 64-byte secret key. -/
def signWithSk (secretKey root : ByteArray) : Except SlhError ByteArray :=
  if root.size != hashLen then
    .error .invalidRootLength
  else if secretKey.size != 64 then
    .error .signatureUnavailable
  else
    match decodeSlhStatusPayload (signRaw secretKey root) with
    | .error e => .error e
    | .ok sig =>
      if sig.size != slh1SignatureLen then
        .error .invalidSignatureLength
      else
        .ok sig

/--
  Product sign path: ≥128-byte entropy → keygen → sign 32-byte Bao root.
  Returns the 7856-byte raw signature (not SLH1 sidecar framing).
-/
def signRoot (secretKeyEntropy root : ByteArray) : Except SlhError ByteArray :=
  if root.size != hashLen then
    .error .invalidRootLength
  else if secretKeyEntropy.size < 128 then
    .error .invalidEntropyLength
  else
    match keygen secretKeyEntropy with
    | .error e => .error e
    | .ok (_pk, sk) => signWithSk sk root

/-- Keygen + sign, returning `(pk, sk, sig)` for roundtrip tests. -/
def keygenAndSignRoot (entropy root : ByteArray) :
    Except SlhError (ByteArray × ByteArray × ByteArray) :=
  if root.size != hashLen then
    .error .invalidRootLength
  else
    match keygen entropy with
    | .error e => .error e
    | .ok (pk, sk) =>
      match signWithSk sk root with
      | .error e => .error e
      | .ok sig => .ok (pk, sk, sig)

/-- Verify raw signature over Bao root with live oracle. -/
def verifyRoot (publicKey root signature : ByteArray) : Except SlhError Unit :=
  verifyBound liveVerifyOracle publicKey root signature

/-! ## Theorems: wire framing + bind-to-root (small native_decide cases)

  Live crypto is **not** theorem-gated (`native_decide` cannot link externs).
  Length gates + mock-oracle binding remain pure.
-/

theorem slh1_sidecar_len : slh1SidecarLen = 7860 := slh1SidecarLen_eq

theorem slh1_sig_len : slh1SignatureLen = 7856 := by native_decide

/-- Short sidecar → invalidSidecarLength (not badSlhMagic). -/
theorem parse_short_length :
    (match parseSidecar (ofList [0x53, 0x4c, 0x48, 0x31]) with
     | .error .invalidSidecarLength => true
     | _ => false) = true := by
  native_decide

/-- Empty sidecar → invalidSidecarLength. -/
theorem parse_empty :
    (match parseSidecar ByteArray.empty with
     | .error .invalidSidecarLength => true
     | _ => false) = true := by
  native_decide

/-- Wrong 4-byte prefix is not SLH1 magic. -/
theorem zeros_not_slh1_magic :
    slh1MagicPrefix (ofList [0, 0, 0, 0]) = false := by
  native_decide

/-- Correct magic list is accepted by prefix check. -/
theorem slh1_magic_prefix_ok :
    slh1MagicPrefix slh1MagicBA = true := by
  native_decide

/-- Exact-length magic gate: zeros → badSlhMagic (not invalidSidecarLength). -/
theorem parse_magic_bad :
    (match parseMagicAtExactLen (ofList [0, 0, 0, 0]) with
     | .error .badSlhMagic => true
     | _ => false) = true := by
  native_decide

/-- Exact-length magic gate: good magic → extract of empty remaining payload. -/
theorem parse_magic_good_empty_payload :
    (match parseMagicAtExactLen slh1MagicBA with
     | .ok b => b.size == 0
     | .error _ => false) = true := by
  native_decide

/--
  When size is exact and magic fails, `parseSidecar` is `badSlhMagic`.
  (AOT Main also exercises full 7860-byte all-zero wire.)
-/
theorem parse_bad_magic_when_exact
    (bytes : ByteArray)
    (hlen : bytes.size = slh1SidecarLen)
    (hmag : slh1MagicPrefix bytes = false) :
    parseSidecar bytes = .error .badSlhMagic := by
  simp [parseSidecar, parseMagicAtExactLen, hlen, hmag]

/-- buildSidecar rejects wrong signature length. -/
theorem build_bad_sig_len :
    (match buildSidecar (ofList [1, 2, 3]) with
     | .error .invalidSignatureLength => true
     | _ => false) = true := by
  native_decide

/-- mkBinding rejects short public key (short sig also; pk checked first). -/
theorem bind_bad_pk :
    (match mkBinding (ofList [1]) (replicate hashLen 0) (ofList [1]) with
     | .error .invalidPublicKeyLength => true
     | _ => false) = true := by
  native_decide

/-- mkBinding rejects short root after pk ok. -/
theorem bind_bad_root :
    (match mkBinding (replicate slhPublicKeyLen 0) (ofList [1]) (ofList [1]) with
     | .error .invalidRootLength => true
     | _ => false) = true := by
  native_decide

/-- mkBinding rejects short signature after pk+root ok. -/
theorem bind_bad_sig :
    (match mkBinding (replicate slhPublicKeyLen 0) (replicate hashLen 0) (ofList [1]) with
     | .error .invalidSignatureLength => true
     | _ => false) = true := by
  native_decide

/--
  Wrong claimed root vs expected → verificationFailed **before** oracle/sig size.
  (Size gates are separate; this proves the ctEq root check is fail-closed.)
-/
theorem wrong_root_fails :
    (let rootA := replicate hashLen 0xaa
     let rootB := replicate hashLen 0xbb
     let pk := replicate slhPublicKeyLen 0x11
     -- Short sig: would be invalidSignatureLength if roots matched; roots differ first.
     let sig := ofList [0xcd]
     match verifyBoundToExpected (mockOracleFor rootA sig) pk rootA rootB sig with
     | .error .verificationFailed => true
     | _ => false) = true := by
  native_decide

/-- signRoot rejects bad root length before crypto. -/
theorem sign_bad_root :
    (match signRoot (replicate 128 0x42) (ofList [1]) with
     | .error .invalidRootLength => true
     | _ => false) = true := by
  native_decide

/-- signRoot rejects short entropy before crypto. -/
theorem sign_bad_entropy :
    (match signRoot (replicate 16 0x42) (replicate hashLen 0) with
     | .error .invalidEntropyLength => true
     | _ => false) = true := by
  native_decide

/-- Magic list matches ASCII SLH1. -/
theorem slh1_magic_bytes :
    slh1Magic = [0x53, 0x4c, 0x48, 0x31] := slh1Magic_eq_literal

end Carbonado.Slh
