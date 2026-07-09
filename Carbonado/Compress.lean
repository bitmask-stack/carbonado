/-
  Zstd compression for the Carbonado pipeline (Program F).

  Product AOT statically embeds libzstd (level 20) from the pinned `ref/zstd`
  tree into `libcarbonado_native.a` via `nix/native` (`staticLibDeps`; **no**
  shared `-lzstd`).

  **Evaluation model (LIMITS):**
  * `@[extern]` symbols are used by the **compiled** AOT binary.
  * Lean bodies are identity fallbacks for the elaborator when C is not linked.
  * Do **not** `native_decide` over `compressRaw` / `decompressRaw` (extern needs
    the native symbol at decide-time). Pure tests cover status decoding + bit-clear
    pipeline paths; AOT `Main` / `demo` gate real zstd goldens and c2/c6 roundtrips.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util

namespace Carbonado.Compress

open Carbonado.Constants
open Carbonado.Crypto.Util

/-- Strict zstd error taxonomy (exact-match in tests; no lumped diagnostics). -/
inductive ZstdError where
  | compressionFailed
  | decompressionFailed
  | outputTooLarge
  | invalidInput
  deriving DecidableEq, Repr

/-- Normative compression level (AGENTS: zstd-20). -/
def zstdLevel : UInt32 := 20

/-- DoS cap on decompressed output (Rust `MAX_SEGMENT_MAIN_LEN` = 256 MiB). -/
def maxDecompressedLen : UInt64 := 256 * 1024 * 1024

/-- Zstd frame magic (little-endian frame descriptor prefix). -/
def zstdMagic : List UInt8 := [0x28, 0xb5, 0x2f, 0xfd]

theorem zstdMagic_length : zstdMagic.length = 4 := by native_decide

/-- Pure status-prefix helper (identity payload). Used by extern Lean bodies. -/
def statusOkPayload (payload : ByteArray) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    out := out.push 0
    pure (appendBA out payload)

/--
  Raw compress: status-prefixed blob.
  Compiled AOT: real `ZSTD_compress` at `level`.
  Lean body: identity payload with status 0 (elaborator only; not for native_decide).
-/
@[extern "carbonado_zstd_compress"]
def compressRaw (input : @& ByteArray) (_level : UInt32) : ByteArray :=
  statusOkPayload input

/--
  Raw decompress: status-prefixed blob.
  `maxOut = 0` → C uses `maxDecompressedLen`.
  Lean body: identity with status 0.
-/
@[extern "carbonado_zstd_decompress"]
def decompressRaw (input : @& ByteArray) (_maxOut : UInt64) : ByteArray :=
  statusOkPayload input

/-- Map C status byte to `ZstdError` (distinct codes; no collapse). -/
def ofStatus (code : UInt8) : ZstdError :=
  match code with
  | 1 => .compressionFailed
  | 2 => .decompressionFailed
  | 3 => .outputTooLarge
  | _ => .invalidInput

/-- Decode status-prefixed blob into Except. Empty raw → invalidInput. -/
def decodeStatusPayload (raw : ByteArray) : Except ZstdError ByteArray :=
  if raw.size == 0 then
    .error .invalidInput
  else
    let code := raw.get! 0
    let payload := raw.extract 1 raw.size
    if code == 0 then
      .ok payload
    else
      .error (ofStatus code)

/-- Compress at normative level 20 (AOT: real zstd). -/
def compressLevel20 (input : ByteArray) : Except ZstdError ByteArray :=
  decodeStatusPayload (compressRaw input zstdLevel)

/-- Decompress with 256 MiB output cap. -/
def decompress (input : ByteArray) : Except ZstdError ByteArray :=
  decodeStatusPayload (decompressRaw input maxDecompressedLen)

/-- Decompress with an explicit max output size (for tests / tight caps). -/
def decompressWithMax (input : ByteArray) (maxOut : UInt64) : Except ZstdError ByteArray :=
  decodeStatusPayload (decompressRaw input maxOut)

/-- True if `bs` begins with zstd magic (product AOT frames always do). -/
def hasZstdMagic (bs : ByteArray) : Bool :=
  bs.size ≥ 4 &&
    bs.get! 0 == 0x28 &&
    bs.get! 1 == 0xb5 &&
    bs.get! 2 == 0x2f &&
    bs.get! 3 == 0xfd

/-- ofStatus maps 1 → compressionFailed. -/
theorem ofStatus_compress : ofStatus 1 = .compressionFailed := rfl

/-- ofStatus maps 2 → decompressionFailed. -/
theorem ofStatus_decompress : ofStatus 2 = .decompressionFailed := rfl

/-- ofStatus maps 3 → outputTooLarge. -/
theorem ofStatus_too_large : ofStatus 3 = .outputTooLarge := rfl

/-- ofStatus maps other non-zero → invalidInput (incl. 4 and unknown). -/
theorem ofStatus_invalid_4 : ofStatus 4 = .invalidInput := rfl

theorem ofStatus_invalid_99 : ofStatus 99 = .invalidInput := rfl

/-- Empty status blob → invalidInput (Bool form for Decidable). -/
theorem decode_empty_raw :
    (match decodeStatusPayload ByteArray.empty with
     | .error .invalidInput => true
     | _ => false) = true := by
  native_decide

/-- Status 1 with empty payload → compressionFailed. -/
theorem decode_status_1 :
    (match decodeStatusPayload (ofList [1]) with
     | .error .compressionFailed => true
     | _ => false) = true := by
  native_decide

/-- Status 2 → decompressionFailed. -/
theorem decode_status_2 :
    (match decodeStatusPayload (ofList [2]) with
     | .error .decompressionFailed => true
     | _ => false) = true := by
  native_decide

/-- Status 3 → outputTooLarge. -/
theorem decode_status_3 :
    (match decodeStatusPayload (ofList [3]) with
     | .error .outputTooLarge => true
     | _ => false) = true := by
  native_decide

/-- Status 4 → invalidInput. -/
theorem decode_status_4 :
    (match decodeStatusPayload (ofList [4]) with
     | .error .invalidInput => true
     | _ => false) = true := by
  native_decide

/-- Status 0 with payload returns the payload. -/
theorem decode_status_ok_hello :
    (match decodeStatusPayload (ofList [0, 0x68, 0x69]) with
     | .ok b => ctEq b (ofList [0x68, 0x69])
     | .error _ => false) = true := by
  native_decide

/-- Pure `statusOkPayload` is status 0 + payload (identity framing). -/
theorem statusOk_payload_identity :
    (match decodeStatusPayload (statusOkPayload (ofList [1, 2, 3])) with
     | .ok b => ctEq b (ofList [1, 2, 3])
     | .error _ => false) = true := by
  native_decide

end Carbonado.Compress
