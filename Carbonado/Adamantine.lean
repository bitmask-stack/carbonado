/-
  Adamantine 1.0 directory catalog wire envelope (Program G).

  Normative layout (AGENTS §7.1 / Rust `src/adamantine.rs`):
  ```
  Offset  Size  Field
  0       13    magic            ADAMANTINE10\n
  13      1     carbonado_fmt    0x0E | 0x0F
  14      1     flags            u8 (bit0 REQUIRE_OTS; bits 1–7 must be 0)
  15      4     payload_len      u32 LE
  19      N     payload          manifest + Bao bundle (see Filepack / payload)
  ```

  Payload framing (Rust `adamantine_payload`):
  ```
  [u32 LE manifest_len][manifest bytes][u32 LE bundle_len][bundle bytes]
  ```

  Dev magics `ADAMANTINE1\n` / `ADAMANTINE2\n` are rejected with distinct errors.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util

namespace Carbonado.Adamantine

open Carbonado.Constants
open Carbonado.Crypto.Util

/-- Adamantine 1.0 magic: `ADAMANTINE10\n` (13 bytes). -/
def adamantineMagic : List UInt8 :=
  [0x41, 0x44, 0x41, 0x4d, 0x41, 0x4e, 0x54, 0x49, 0x4e, 0x45, 0x31, 0x30, 0x0a]

theorem adamantineMagic_length : adamantineMagic.length = 13 := by native_decide

theorem adamantineMagic_eq_literal :
    adamantineMagic =
      [0x41, 0x44, 0x41, 0x4d, 0x41, 0x4e, 0x54, 0x49, 0x4e, 0x45, 0x31, 0x30, 0x0a] := by
  rfl

/-- Total Adamantine header length. -/
def adamantineHeaderLen : Nat := 19

theorem adamantineHeaderLen_eq : adamantineHeaderLen = 19 := by native_decide

/-- Catalog carbonado_fmt public (c14). -/
def adamantineFmtPublic : UInt8 := 0x0E

/-- Catalog carbonado_fmt encrypted (c15). -/
def adamantineFmtEncrypted : UInt8 := 0x0F

/-- Flag bit 0: REQUIRE_OTS (per-entry proofs required at decode). -/
def adamantineFlagRequireOts : UInt8 := 1

/-- Allowed flags mask (only bit 0). -/
def adamantineFlagsMask : UInt8 := adamantineFlagRequireOts

/-- Max rkyv / Lean-native manifest payload (16 MiB). -/
def maxManifestPayloadLen : Nat := 16 * 1024 * 1024

/-- Max Bao bundle (256 MiB). -/
def maxBaoBundleLen : Nat := 256 * 1024 * 1024

/-- Max total Adamantine payload. -/
def maxAdamantinePayloadLen : Nat :=
  maxManifestPayloadLen + 4 + maxBaoBundleLen

/-- Strict Adamantine error taxonomy (exact-match in tests). -/
inductive AdamantineError where
  /-- Input shorter than 19-byte header, or length fields inconsistent. -/
  | invalidHeader
  /-- Magic is not a recognized Adamantine form. -/
  | invalidMagic
  /-- Legacy/dev magic `ADAMANTINE1\n` or unsupported major.minor. -/
  | unsupportedVersion (major minor : UInt8)
  /-- carbonado_fmt not c14/c15. -/
  | invalidCarbonadoFormat (fmt : UInt8)
  /-- Reserved flag bits set. -/
  | invalidFlags (flags : UInt8)
  /-- Declared payload larger than DoS cap. -/
  | payloadTooLarge (declared max : Nat)
  /-- Declared payload length exceeds available bytes. -/
  | payloadLengthMismatch (expected available : Nat)
  deriving DecidableEq, Repr

/-- Parsed Adamantine 1.0 header (excluding payload). -/
structure AdamantineHeader where
  carbonadoFmt : UInt8
  flags : UInt8
  deriving DecidableEq, Repr, Inhabited

/-- Magic as ByteArray. -/
def adamantineMagicBA : ByteArray := ofList adamantineMagic

/-- Legacy v1 magic `ADAMANTINE1\n` (12 bytes). -/
def adamantineMagicV1 : ByteArray :=
  ofList [0x41, 0x44, 0x41, 0x4d, 0x41, 0x4e, 0x54, 0x49, 0x4e, 0x45, 0x31, 0x0a]

/-- Dev v2 magic `ADAMANTINE2\n` (12 bytes). -/
def adamantineMagicDevV2 : ByteArray :=
  ofList [0x41, 0x44, 0x41, 0x4d, 0x41, 0x4e, 0x54, 0x49, 0x4e, 0x45, 0x32, 0x0a]

/-- Validate catalog carbonado_fmt is c14 or c15. -/
def validateCarbonadoFmt (fmt : UInt8) : Except AdamantineError Unit :=
  if fmt == adamantineFmtPublic || fmt == adamantineFmtEncrypted then
    .ok ()
  else
    .error (.invalidCarbonadoFormat fmt)

/-- Validate flags: only bit 0 allowed. -/
def validateFlags (flags : UInt8) : Except AdamantineError Unit :=
  if flags &&& (~~~adamantineFlagsMask) != 0 then
    .error (.invalidFlags flags)
  else
    .ok ()

/--
  Parse unsupported `ADAMANTINE{d}{d?}\n` version digits.
  Returns `none` when the prefix is not Adamantine-shaped.
-/
def parseUnsupportedMagicVersion (magic : ByteArray) : Option (UInt8 × UInt8) :=
  if magic.size < 12 then
    none
  else if !ctEq (magic.extract 0 10)
      (ofList [0x41, 0x44, 0x41, 0x4d, 0x41, 0x4e, 0x54, 0x49, 0x4e, 0x45]) then
    none
  else
    let b10 := magic.get! 10
    let b11 := if magic.size > 11 then magic.get! 11 else 0x0a
    let isDigit (b : UInt8) : Bool := b ≥ 0x30 && b ≤ 0x39
    if b11 == 0x0a then
      if isDigit b10 then some (b10 - 0x30, 0) else none
    else if isDigit b11 && magic.size > 12 && magic.get! 12 == 0x0a && isDigit b10 then
      some (b10 - 0x30, b11 - 0x30)
    else
      none

/-- Prepend Adamantine 1.0 header to a payload (no size cap check — use `buildPayload` first). -/
def encodeAdamantine (payload : ByteArray) (carbonadoFmt flags : UInt8) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    out := appendBA out adamantineMagicBA
    out := out.push carbonadoFmt
    out := out.push flags
    out := appendBA out (putUInt32LE (UInt32.ofNat payload.size))
    out := appendBA out payload
    pure out

/-- Strip and validate Adamantine 1.0 header; exact payload length required (no trailer). -/
def decodeAdamantine (bytes : ByteArray) :
    Except AdamantineError (ByteArray × AdamantineHeader) :=
  if bytes.size < adamantineHeaderLen then
    .error .invalidHeader
  else
    let magic13 := bytes.extract 0 13
    if ctEq magic13 adamantineMagicBA then
      let carbonadoFmt := bytes.get! 13
      let flags := bytes.get! 14
      match validateCarbonadoFmt carbonadoFmt, validateFlags flags with
      | .error e, _ => .error e
      | _, .error e => .error e
      | .ok (), .ok () =>
        let payloadLen := UInt32.toNat (getUInt32LE bytes 15)
        if payloadLen > maxAdamantinePayloadLen then
          .error (.payloadTooLarge payloadLen maxAdamantinePayloadLen)
        else
          let payloadEnd := adamantineHeaderLen + payloadLen
          if bytes.size < payloadEnd then
            .error (.payloadLengthMismatch payloadLen (bytes.size - adamantineHeaderLen))
          else if bytes.size != payloadEnd then
            .error .invalidHeader
          else
            .ok (bytes.extract adamantineHeaderLen payloadEnd,
              { carbonadoFmt := carbonadoFmt, flags := flags })
    else if bytes.size ≥ 12 && ctEq (bytes.extract 0 12) adamantineMagicV1 then
      .error (.unsupportedVersion 1 0)
    else if bytes.size ≥ 12 && ctEq (bytes.extract 0 12) adamantineMagicDevV2 then
      .error (.unsupportedVersion 2 0)
    else
      match parseUnsupportedMagicVersion magic13 with
      | some (maj, min) => .error (.unsupportedVersion maj min)
      | none => .error .invalidMagic

/-- Build payload: `[u32 LE man_len][man][u32 LE bun_len][bun]`. -/
def buildPayload (manifest bundle : ByteArray) : Except AdamantineError ByteArray :=
  if manifest.size > maxManifestPayloadLen then
    .error (.payloadTooLarge manifest.size maxManifestPayloadLen)
  else if bundle.size > maxBaoBundleLen then
    .error (.payloadTooLarge bundle.size maxBaoBundleLen)
  else
    let total := 4 + manifest.size + 4 + bundle.size
    if total > maxAdamantinePayloadLen then
      .error (.payloadTooLarge total maxAdamantinePayloadLen)
    else
      Id.run do
        let mut out := ByteArray.empty
        out := appendBA out (putUInt32LE (UInt32.ofNat manifest.size))
        out := appendBA out manifest
        out := appendBA out (putUInt32LE (UInt32.ofNat bundle.size))
        out := appendBA out bundle
        pure (.ok out)

/-- Split payload into (manifest, bundle); exact length required. -/
def splitPayload (payload : ByteArray) : Except AdamantineError (ByteArray × ByteArray) :=
  if payload.size > maxAdamantinePayloadLen then
    .error (.payloadTooLarge payload.size maxAdamantinePayloadLen)
  else if payload.size < 8 then
    .error (.payloadLengthMismatch 8 payload.size)
  else
    let manLen := UInt32.toNat (getUInt32LE payload 0)
    if manLen > maxManifestPayloadLen then
      .error (.payloadTooLarge manLen maxManifestPayloadLen)
    else
      let bundleLenOff := 4 + manLen
      if payload.size < bundleLenOff + 4 then
        .error (.payloadLengthMismatch (bundleLenOff + 4) payload.size)
      else
        let bunLen := UInt32.toNat (getUInt32LE payload bundleLenOff)
        if bunLen > maxBaoBundleLen then
          .error (.payloadTooLarge bunLen maxBaoBundleLen)
        else
          let bunStart := bundleLenOff + 4
          let bunEnd := bunStart + bunLen
          if bunEnd > payload.size then
            .error (.payloadLengthMismatch bunEnd payload.size)
          else if payload.size != bunEnd then
            .error (.payloadLengthMismatch bunEnd payload.size)
          else
            .ok (payload.extract 4 bundleLenOff, payload.extract bunStart bunEnd)

/-- Slice bundle at offset/len (fail-closed on OOB). -/
def bundleSlice (bundle : ByteArray) (offset len : Nat) : Except AdamantineError ByteArray :=
  if len == 0 then
    .ok ByteArray.empty
  else if offset + len > bundle.size then
    .error (.payloadLengthMismatch (offset + len) bundle.size)
  else
    .ok (bundle.extract offset (offset + len))

/-- Header encode/decode roundtrip identity (empty payload). -/
theorem encode_decode_empty_public :
    (match decodeAdamantine (encodeAdamantine ByteArray.empty adamantineFmtPublic 0) with
     | .ok (p, h) => p.size == 0 && h.carbonadoFmt == adamantineFmtPublic && h.flags == 0
     | .error _ => false) = true := by
  native_decide

/-- Invalid flags (reserved bits) rejected. -/
theorem invalid_flags_bit1 :
    (match decodeAdamantine (encodeAdamantine ByteArray.empty adamantineFmtPublic 2) with
     | .error (.invalidFlags 2) => true
     | _ => false) = true := by
  native_decide

/-- Bad carbonado_fmt rejected. -/
theorem invalid_fmt_c0 :
    (match decodeAdamantine (encodeAdamantine ByteArray.empty 0 0) with
     | .error (.invalidCarbonadoFormat 0) => true
     | _ => false) = true := by
  native_decide

/-- Short buffer → invalidHeader. -/
theorem short_header :
    (match decodeAdamantine (ofList [1, 2, 3]) with
     | .error .invalidHeader => true
     | _ => false) = true := by
  native_decide

/-- Dev v2 magic → unsupportedVersion 2 0. -/
theorem dev_v2_rejected :
    (match decodeAdamantine (appendBA adamantineMagicDevV2 (replicate 7 0)) with
     | .error (.unsupportedVersion 2 0) => true
     | _ => false) = true := by
  native_decide

end Carbonado.Adamantine
