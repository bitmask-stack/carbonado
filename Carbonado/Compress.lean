/-
  Zstd compression for the Carbonado pipeline (Program F).

  Product AOT statically embeds libzstd (level 20) from the pinned `ref/zstd`
  tree into the Lean AOT demo native archive via `nix/native` (`staticLibDeps`;
  **no** shared `-lzstd`). This is not a Rust `-sys` product.

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

/-- Zstd frame magic (little-endian `0xFD2FB528`; RFC 8878 / `ref/zstd/doc/zstd_compression_format.md`). -/
def zstdMagic : List UInt8 := [0x28, 0xb5, 0x2f, 0xfd]

theorem zstdMagic_length : zstdMagic.length = 4 := by native_decide

theorem zstdMagic_eq_literal :
    zstdMagic = [0x28, 0xb5, 0x2f, 0xfd] := rfl

/-- RFC `ZSTD_WINDOWLOG_ABSOLUTEMIN` (`ref/zstd/lib/common/zstd_internal.h`). -/
def zstdWindowLogMin : Nat := 10

/-- Product one-shot and streaming frames: `Content_Checksum_flag` is clear. -/
def zstdContentChecksum : Bool := false

/-- Product frames: `Dictionary_ID_flag` is 0 (no dictionary). -/
def zstdDictionaryIdFlag : UInt8 := 0

/-- Encoder-compliant unused bit (must be zero this spec version). -/
def zstdUnusedBit : Bool := false

/-- RFC reserved bit (decoder must reject if set). -/
def zstdReservedBit : Bool := false

/-- One-shot `ZSTD_compress` / `zstd::bulk` default: `contentSizeFlag = 1`. -/
def zstdBufferContentSizeFlag : Bool := true

/-- Streaming `copy_encode` with unknown size: `contentSizeFlag = 0`. -/
def zstdStreamContentSizeFlag : Bool := false

/-- Level-20 `windowLog` from `ref/zstd/lib/compress/clevels.h` `ZSTD_defaultCParameters[0][20]`
    (srcSize > 256 KiB, and streaming with unknown size). -/
def zstdLevel20WindowLogLarge : Nat := 25

/-- Level-20 `windowLog` for srcSize ≤ 256 KiB (`ZSTD_defaultCParameters[1][20]`). -/
def zstdLevel20WindowLog256KiB : Nat := 18

/-- Level-20 `windowLog` for srcSize ≤ 128 KiB (`ZSTD_defaultCParameters[2][20]`). -/
def zstdLevel20WindowLog128KiB : Nat := 17

/-- Level-20 `windowLog` for srcSize ≤ 16 KiB (`ZSTD_defaultCParameters[3][20]`). -/
def zstdLevel20WindowLog16KiB : Nat := 14

/-- Frame-header parse errors (RFC reserved-bit + framing; not C status codes). -/
inductive ZstdFrameError where
  | truncatedHeader
  | badMagic
  | reservedBitSet
  deriving DecidableEq, Repr

/-- RFC `Frame_Header_Descriptor` (1 byte). Bit 7 is the high bit. -/
structure FrameHeaderDescriptor where
  contentSizeFlag : UInt8
  singleSegment : Bool
  unusedBit : Bool
  reservedBit : Bool
  contentChecksum : Bool
  dictionaryIdFlag : UInt8
  deriving DecidableEq, Repr

/-- Parse the descriptor byte (total function). -/
def parseFrameHeaderDescriptor (b : UInt8) : FrameHeaderDescriptor :=
  {
    contentSizeFlag := (b >>> 6) &&& 3
    singleSegment := (b &&& 0x20) != 0
    unusedBit := (b &&& 0x10) != 0
    reservedBit := (b &&& 0x08) != 0
    contentChecksum := (b &&& 0x04) != 0
    dictionaryIdFlag := b &&& 3
  }

/-- RFC `DID_Field_Size` from `Dictionary_ID_flag`. -/
def didFieldSize (flag : UInt8) : Nat :=
  if flag == 0 then 0
  else if flag == 1 then 1
  else if flag == 2 then 2
  else if flag == 3 then 4
  else 0

/-- RFC `FCS_Field_Size` from `Frame_Content_Size_flag` + `Single_Segment_flag`. -/
def fcsFieldSize (fcsFlag : UInt8) (singleSegment : Bool) : Nat :=
  if fcsFlag == 1 then 2
  else if fcsFlag == 2 then 4
  else if fcsFlag == 3 then 8
  else if fcsFlag == 0 then
    if singleSegment then 1 else 0
  else 0

/-- `ref/zstd` `ZSTD_writeFrameHeader` FCS code when `contentSizeFlag` is set. -/
def fcsCodeForSize (pledged : Nat) : Nat :=
  (if pledged >= 256 then 1 else 0) +
    (if pledged >= 65536 + 256 then 1 else 0) +
    (if pledged >= 4294967295 then 1 else 0)

/-- Assemble the descriptor byte (`dictIDSizeCode + checksum<<2 + singleSegment<<5 + fcsCode<<6`). -/
def frameHeaderDescriptionByte
    (dictIdSizeCode checksumBit singleSegBit fcsCode : Nat) : UInt8 :=
  UInt8.ofNat (dictIdSizeCode + checksumBit * 4 + singleSegBit * 32 + fcsCode * 64)

/-- RFC windowLog = 10 + Exponent (bits 7–3 of `Window_Descriptor`). -/
def windowLogFromDescriptor (wd : UInt8) : Nat :=
  zstdWindowLogMin + (wd >>> 3).toNat

/-- RFC `Window_Size = windowBase + (windowBase / 8) * Mantissa`. -/
def windowSizeFromDescriptor (wd : UInt8) : Nat :=
  let exponent := (wd >>> 3).toNat
  let mantissa := (wd &&& 7).toNat
  let windowLog := zstdWindowLogMin + exponent
  let windowBase := 2 ^ windowLog
  windowBase + (windowBase / 8) * mantissa

/-- Power-of-two window descriptor (mantissa 0): `(windowLog - 10) << 3`. -/
def windowDescriptorByte (windowLog : Nat) : UInt8 :=
  UInt8.ofNat ((windowLog - zstdWindowLogMin) <<< 3)

/-- `ZSTD_writeFrameHeader`: Single_Segment iff content size is present and window ≥ pledged. -/
def singleSegment (contentSizeFlag : Bool) (windowSize pledgedSrcSize : Nat) : Bool :=
  contentSizeFlag && windowSize ≥ pledgedSrcSize

/-- Parsed RFC `Frame_Header` (magic already consumed). `headerLen` counts magic. -/
structure ParsedFrameHeader where
  descriptor : FrameHeaderDescriptor
  windowDescriptor : Option UInt8
  dictionaryId : Option UInt32
  contentSize : Option UInt64
  headerLen : Nat
  deriving DecidableEq, Repr

private def getUInt16LE (bs : ByteArray) (off : Nat) : UInt16 :=
  (bs.get! off).toUInt16 ||| ((bs.get! (off + 1)).toUInt16 <<< 8)

/-- Parse magic + `Frame_Header`. Rejects RFC reserved bit. Unused bit is recorded, not rejected. -/
def parseZstdFrameHeader (bs : ByteArray) : Except ZstdFrameError ParsedFrameHeader :=
  if bs.size < 5 then
    .error .truncatedHeader
  else if !(bs.get! 0 == 0x28 && bs.get! 1 == 0xb5 && bs.get! 2 == 0x2f && bs.get! 3 == 0xfd) then
    .error .badMagic
  else
    let d := parseFrameHeaderDescriptor (bs.get! 4)
    if d.reservedBit then
      .error .reservedBitSet
    else
      let needWin := if d.singleSegment then 0 else 1
      let didSz := didFieldSize d.dictionaryIdFlag
      let fcsSz := fcsFieldSize d.contentSizeFlag d.singleSegment
      let headerLen := 5 + needWin + didSz + fcsSz
      if bs.size < headerLen then
        .error .truncatedHeader
      else
        let winOff := 5
        let windowDescriptor :=
          if d.singleSegment then none else some (bs.get! winOff)
        let didOff := 5 + needWin
        let dictionaryId :=
          if didSz == 0 then none
          else if didSz == 1 then some (bs.get! didOff).toUInt32
          else if didSz == 2 then some (getUInt16LE bs didOff).toUInt32
          else if didSz == 4 then some (getUInt32LE bs didOff)
          else none
        let fcsOff := didOff + didSz
        let contentSize :=
          if fcsSz == 0 then none
          else if fcsSz == 1 then some (bs.get! fcsOff).toUInt64
          else if fcsSz == 2 then some ((getUInt16LE bs fcsOff).toUInt64 + 256)
          else if fcsSz == 4 then some (getUInt32LE bs fcsOff).toUInt64
          else if fcsSz == 8 then some (getUInt64LE bs fcsOff)
          else none
        .ok {
          descriptor := d
          windowDescriptor := windowDescriptor
          dictionaryId := dictionaryId
          contentSize := contentSize
          headerLen := headerLen
        }

/-- Shared product frame flags (both engines, both APIs). -/
def productFrameHeaderOk (h : ParsedFrameHeader) : Bool :=
  !h.descriptor.unusedBit &&
    !h.descriptor.reservedBit &&
    !h.descriptor.contentChecksum &&
    h.descriptor.dictionaryIdFlag == 0 &&
    h.dictionaryId.isNone

/-- One-shot / AOT frames for pledged size < 256 (1-byte FCS, Single_Segment, no window byte).
    Matches AOT goldens empty/hello and G9 lean `outboard_c14` (26-byte plaintext). -/
def productBufferSmallFrameOk (h : ParsedFrameHeader) (pledged : UInt64) : Bool :=
  productFrameHeaderOk h &&
    h.descriptor.singleSegment &&
    h.descriptor.contentSizeFlag == 0 &&
    h.windowDescriptor.isNone &&
    (match h.contentSize with
     | some n => n == pledged
     | none => false)

/-- Rust `copy_encode` at level 20 with unknown size: no FCS, windowLog 25, mantissa 0.
    Matches G9 rust `outboard_c14` (`28b52ffd0078…`). -/
def productStreamUnknownSizeFrameOk (h : ParsedFrameHeader) : Bool :=
  productFrameHeaderOk h &&
    !h.descriptor.singleSegment &&
    h.descriptor.contentSizeFlag == 0 &&
    h.contentSize.isNone &&
    (match h.windowDescriptor with
     | some wd =>
       windowLogFromDescriptor wd == zstdLevel20WindowLogLarge && (wd &&& 7) == 0
     | none => false)

/-- AOT `ZSTD_compress` level-20 golden for `hello` (`Carbonado.Main` / Program F). -/
def helloLevel20Golden : List UInt8 :=
  [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x05, 0x29, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f]

/-- AOT `ZSTD_compress` level-20 golden for empty input. -/
def emptyLevel20Golden : List UInt8 :=
  [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x00, 0x01, 0x00, 0x00]

/-- Committed G9 lean `outboard_c14` main prefix (descriptor `0x20` + 1-byte FCS 26). -/
def g9LeanC14Header : List UInt8 :=
  [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x1a]

/-- Committed G9 rust `outboard_c14` main prefix (descriptor `0x00` + window `0x78`). -/
def g9RustC14Header : List UInt8 :=
  [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x78]

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

theorem zstdLevel_eq_20 : zstdLevel = 20 := rfl

theorem zstdContentChecksum_off : zstdContentChecksum = false := rfl

theorem zstdUnusedBit_off : zstdUnusedBit = false := rfl

theorem zstdReservedBit_off : zstdReservedBit = false := rfl

theorem zstdDictionaryIdFlag_none : zstdDictionaryIdFlag = 0 := rfl

theorem zstdBufferContentSizeFlag_on : zstdBufferContentSizeFlag = true := rfl

theorem zstdStreamContentSizeFlag_off : zstdStreamContentSizeFlag = false := rfl

theorem zstdLevel20WindowLogLarge_eq : zstdLevel20WindowLogLarge = 25 := rfl

theorem zstdLevel20WindowLog256KiB_eq : zstdLevel20WindowLog256KiB = 18 := rfl

theorem zstdLevel20WindowLog128KiB_eq : zstdLevel20WindowLog128KiB = 17 := rfl

theorem zstdLevel20WindowLog16KiB_eq : zstdLevel20WindowLog16KiB = 14 := rfl

theorem zstdWindowLogMin_eq : zstdWindowLogMin = 10 := rfl

/-- One-shot small frames: no dict, no checksum, Single_Segment, FCS code 0 → descriptor `0x20`. -/
theorem aot_small_descriptor_byte :
    frameHeaderDescriptionByte 0 0 1 0 = 0x20 := by native_decide

/-- Streaming unknown size: no dict, no checksum, no Single_Segment, no FCS → descriptor `0x00`. -/
theorem stream_unknown_descriptor_byte :
    frameHeaderDescriptionByte 0 0 0 0 = 0x00 := by native_decide

theorem level20_large_window_descriptor_byte :
    windowDescriptorByte zstdLevel20WindowLogLarge = 0x78 := by native_decide

theorem window_0x78_log :
    windowLogFromDescriptor 0x78 = 25 := by native_decide

theorem window_0x78_size :
    windowSizeFromDescriptor 0x78 = 33554432 := by native_decide

theorem fcs_code_below_256 : fcsCodeForSize 26 = 0 := by native_decide

theorem fcs_field_small_single : fcsFieldSize 0 true = 1 := by native_decide

theorem fcs_field_stream_none : fcsFieldSize 0 false = 0 := by native_decide

theorem did_field_none : didFieldSize 0 = 0 := by native_decide

theorem small_pledged_is_single_segment :
    singleSegment true (2 ^ zstdLevel20WindowLogLarge) 26 = true := by native_decide

theorem unknown_size_is_not_single_segment :
    singleSegment false (2 ^ zstdLevel20WindowLogLarge) 26 = false := by native_decide

theorem parse_empty_truncated :
    (match parseZstdFrameHeader ByteArray.empty with
     | .error .truncatedHeader => true
     | _ => false) = true := by
  native_decide

theorem parse_four_bytes_truncated :
    (match parseZstdFrameHeader (ofList [0x28, 0xb5, 0x2f, 0xfd]) with
     | .error .truncatedHeader => true
     | _ => false) = true := by
  native_decide

theorem parse_bad_magic :
    (match parseZstdFrameHeader (ofList [0x00, 0x01, 0x02, 0x03, 0x20]) with
     | .error .badMagic => true
     | _ => false) = true := by
  native_decide

theorem parse_reserved_bit :
    (match parseZstdFrameHeader (ofList [0x28, 0xb5, 0x2f, 0xfd, 0x08]) with
     | .error .reservedBitSet => true
     | _ => false) = true := by
  native_decide

theorem parse_hello_golden_header :
    (match parseZstdFrameHeader (ofList helloLevel20Golden) with
     | .ok h => productBufferSmallFrameOk h 5
     | .error _ => false) = true := by
  native_decide

theorem parse_empty_golden_header :
    (match parseZstdFrameHeader (ofList emptyLevel20Golden) with
     | .ok h => productBufferSmallFrameOk h 0
     | .error _ => false) = true := by
  native_decide

theorem parse_g9_lean_c14_header :
    (match parseZstdFrameHeader (ofList g9LeanC14Header) with
     | .ok h => productBufferSmallFrameOk h 26
     | .error _ => false) = true := by
  native_decide

theorem parse_g9_rust_c14_header :
    (match parseZstdFrameHeader (ofList g9RustC14Header) with
     | .ok h => productStreamUnknownSizeFrameOk h
     | .error _ => false) = true := by
  native_decide

theorem hello_golden_has_magic :
    hasZstdMagic (ofList helloLevel20Golden) = true := by native_decide

theorem empty_golden_has_magic :
    hasZstdMagic (ofList emptyLevel20Golden) = true := by native_decide

theorem g9_headers_same_length :
    g9LeanC14Header.length = g9RustC14Header.length := by native_decide

theorem hello_golden_len :
    helloLevel20Golden.length = 14 := by native_decide

theorem empty_golden_len :
    emptyLevel20Golden.length = 9 := by native_decide

end Carbonado.Compress
