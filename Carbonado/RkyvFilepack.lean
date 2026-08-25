/-
  Pure Lean codec for rkyv `FilepackManifestWire` v2 (R9 decode + **W3a encode**).

  **Layout contract (rkyv 0.8.16 + `unaligned`, little-endian FixedUsize=u32):**
  matches Rust `src/filepack_manifest.rs` under the same crate features.

  Root (13 B) at **end** of buffer:
    version:u32 | format_level:u8 | entries:ArchivedVec (RelPtr i32 + len u32)

  FilepackEntry stride 58 B (inline path header):
    rel_path: ArchivedStringRepr (8 B)
    content_blake3: [u8; 32]
    segment_format: u8
    segments: ArchivedVec (8 B)
    ots_proof: ArchivedOption slot (9 B)

  SegmentRef: 60 B fixed.

  **Encode algorithm (matches rkyv HighSerializer two-phase):**
  1. For each entry in order: write nested pointed-to data in field order
     (ool path bytes, then SegmentRef array, then OTS proof bytes if Some).
  2. Write contiguous ArchivedFilepackEntry records.
  3. Write root at end.

  Production directory encode remains **Rust rkyv**. Pure Lean directory/CLI emits
  this rkyv body so Rust `decode_directory` can consume Lean-made catalogs.
  CFP2 remains available for pure-Lean demos only (`FilepackManifest.toWireBytes`);
  it is **not** byte-identical to rkyv.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Filepack

namespace Carbonado.RkyvFilepack

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Filepack

def maxRkyvPayloadLen : Nat := 16 * 1024 * 1024
def stringInlineCap : Nat := 8
def optionVecSlot : Nat := 9
def segmentRefSize : Nat := 60
def rootSize : Nat := 13
def entryMetaSize : Nat := stringInlineCap + 32 + 1 + 8 + optionVecSlot

def readU32LE (buf : ByteArray) (off : Nat) : Except FilepackError UInt32 :=
  if off + 4 > buf.size then .error .invalidWire
  else .ok (getUInt32LE buf off)

def readI32LE (buf : ByteArray) (off : Nat) : Except FilepackError Int :=
  if off + 4 > buf.size then .error .invalidWire
  else
    let n := UInt32.toNat (getUInt32LE buf off)
    if n ≥ 0x80000000 then
      .ok (Int.ofNat n - (Int.ofNat 0x100000000))
    else
      .ok (Int.ofNat n)

def readU64LE (buf : ByteArray) (off : Nat) : Except FilepackError UInt64 :=
  if off + 8 > buf.size then .error .invalidWire
  else .ok (getUInt64LE buf off)

/-- Little-endian signed i32 (two's complement). -/
def putI32LE (x : Int) : ByteArray :=
  let n : Nat :=
    if x ≥ 0 then
      x.toNat % 0x100000000
    else
      (0x100000000 - ((-x).toNat % 0x100000000)) % 0x100000000
  putUInt32LE (UInt32.ofNat n)

/-- Relative pointer: offset is from `fromPos` (start of RelPtr field) to `toPos`. -/
def putRelPtr (fromPos toPos : Nat) : ByteArray :=
  putI32LE (Int.ofNat toPos - Int.ofNat fromPos)

/--
  rkyv little-endian out-of-line string length packing:
  insert `10` as bits 7–6 of the low byte; high length bits start at bit 8
  (`(len & !0x3f) << 2` ≡ `(len / 64) << 8`).
-/
def packOolStringLen (len : Nat) : UInt32 :=
  let low := len &&& 0x3f
  let packed := low ||| 0x80 ||| ((len / 64) <<< 8)
  UInt32.ofNat (packed % 0x100000000)

/-- Inline ArchivedStringRepr (len ≤ 8): fill 0xff then overlay UTF-8. -/
def encodeInlineString (pathBytes : ByteArray) : ByteArray :=
  Id.run do
    let mut out := replicate stringInlineCap 0xff
    let n := min pathBytes.size stringInlineCap
    for i in [:n] do
      out := out.set! i (pathBytes.get! i)
    pure out

/--
  Out-of-line string header (8 B). Relative offset is from the **start of the
  8-byte header** (rkyv `ArchivedStringRepr::emplace_out_of_line`), not from
  the offset field at +4.
-/
def encodeOolStringHeader (headerPos dataPos len : Nat) : ByteArray :=
  appendBA (putUInt32LE (packOolStringLen len)) (putI32LE (Int.ofNat dataPos - Int.ofNat headerPos))

def resolveRelPtr (buf : ByteArray) (relPtrPos : Nat) : Except FilepackError Nat := do
  let off ← readI32LE buf relPtrPos
  let target := Int.ofNat relPtrPos + off
  if target < 0 then throw .invalidWire
  let t := target.toNat
  if t > buf.size then throw .invalidWire
  pure t

/-- Decode ArchivedStringRepr at `pos` (8-byte header). -/
def decodeArchivedString (buf : ByteArray) (pos : Nat) : Except FilepackError String := do
  if pos + stringInlineCap > buf.size then throw .invalidWire
  let b0 := buf.get! pos
  if b0 &&& 0xc0 == 0x80 then
    -- out-of-line (rkyv little-endian len packing)
    let rawLenNat := UInt32.toNat (← readU32LE buf pos)
    let low6 := rawLenNat % 64
    let high := rawLenNat / 256
    let len := low6 + high * 64
    let off ← readI32LE buf (pos + 4)
    let target := Int.ofNat pos + off
    if target < 0 then throw .invalidWire
    let t := target.toNat
    if t + len > buf.size then throw .invalidWire
    let bytes := buf.extract t (t + len)
    match String.fromUTF8? bytes with
    | some s => pure s
    | none => throw .invalidWire
  else
    let mut len := 0
    let mut done := false
    for i in [:stringInlineCap] do
      if !done then
        if buf.get! (pos + i) == 0xff then
          done := true
        else
          len := len + 1
    let bytes := buf.extract pos (pos + len)
    match String.fromUTF8? bytes with
    | some s => pure s
    | none => throw .invalidWire

def decodeSegmentRef (buf : ByteArray) (pos : Nat) : Except FilepackError SegmentRef := do
  if pos + segmentRefSize > buf.size then throw .invalidWire
  pure {
    segmentBaoRoot := buf.extract pos (pos + 32)
    chunkIndex := ← readU32LE buf (pos + 32)
    mainLen := ← readU64LE buf (pos + 36)
    verificationOutboardOffset := ← readU32LE buf (pos + 44)
    verificationOutboardLen := ← readU32LE buf (pos + 48)
    fecParityOffset := ← readU32LE buf (pos + 52)
    fecParityLen := ← readU32LE buf (pos + 56)
  }

def decodeSegmentVec (buf : ByteArray) (vecPos : Nat) :
    Except FilepackError (Array SegmentRef) := do
  if vecPos + 8 > buf.size then throw .invalidWire
  let target ← resolveRelPtr buf vecPos
  let lenNat := UInt32.toNat (← readU32LE buf (vecPos + 4))
  if lenNat > maxSegmentsPerEntry then throw .tooManySegments
  let mut segs : Array SegmentRef := #[]
  for i in [:lenNat] do
    segs := segs.push (← decodeSegmentRef buf (target + i * segmentRefSize))
  pure segs

def decodeOptionalBytes (buf : ByteArray) (pos : Nat) :
    Except FilepackError (Option ByteArray) := do
  if pos + optionVecSlot > buf.size then throw .invalidWire
  let tag := buf.get! pos
  if tag == 0 then
    pure none
  else if tag == 1 then
    let target ← resolveRelPtr buf (pos + 1)
    let lenNat := UInt32.toNat (← readU32LE buf (pos + 5))
    if lenNat > maxOtsProofLen then throw .otsProofTooLarge
    if target + lenNat > buf.size then throw .invalidWire
    pure (some (buf.extract target (target + lenNat)))
  else
    throw .invalidWire

def decodeEntry (buf : ByteArray) (entryPos : Nat) : Except FilepackError FilepackEntry := do
  if entryPos + entryMetaSize > buf.size then throw .invalidWire
  let relPath ← decodeArchivedString buf entryPos
  let blakePos := entryPos + stringInlineCap
  let contentBlake3 := buf.extract blakePos (blakePos + 32)
  let fmtPos := blakePos + 32
  let segmentFormat := buf.get! fmtPos
  let segVecPos := fmtPos + 1
  let segments ← decodeSegmentVec buf segVecPos
  let otsProof ← decodeOptionalBytes buf (segVecPos + 8)
  pure {
    relPath := relPath
    contentBlake3 := contentBlake3
    segmentFormat := segmentFormat
    segments := segments
    otsProof := otsProof
  }

/-- Decode rkyv FilepackManifestWire v2 (`catalogBaoRoot` from `.adam.cXX` filename). -/
def decodeRkyvManifest (bytes : ByteArray) (catalogBaoRoot : ByteArray) :
    Except FilepackError FilepackManifest := do
  if bytes.size == 0 then throw .invalidWire
  if bytes.size > maxRkyvPayloadLen then throw .tooManyEntries
  if bytes.size < rootSize then throw .invalidWire
  if catalogBaoRoot.size != hashLen then throw .invalidHashLength
  let rootPos := bytes.size - rootSize
  let version := UInt32.toNat (← readU32LE bytes rootPos)
  let formatLevel := bytes.get! (rootPos + 4)
  let entriesVecPos := rootPos + 5
  let entriesTarget ← resolveRelPtr bytes entriesVecPos
  let entryCount := UInt32.toNat (← readU32LE bytes (entriesVecPos + 4))
  if entryCount > maxFilepackEntries then throw .tooManyEntries
  let mut entries : Array FilepackEntry := #[]
  for i in [:entryCount] do
    entries := entries.push (← decodeEntry bytes (entriesTarget + i * entryMetaSize))
  let m : FilepackManifest := {
    version := version
    formatLevel := formatLevel
    catalogBaoRoot := catalogBaoRoot
    entries := entries
  }
  m.validate
  pure m

/-- Nested-data resolver for one entry (rkyv serialize phase). -/
structure EntryResolver where
  pathBytes : ByteArray
  pathOol : Bool
  pathDataPos : Nat
  segsPos : Nat
  segsLen : Nat
  /-- `none` = Option::None; `some (pos, len)` = Some(vec) with data at pos. -/
  ots : Option (Nat × Nat)
  entry : FilepackEntry
  deriving Inhabited

/--
  Encode `FilepackManifestWire` v2 as rkyv 0.8.16 + unaligned bytes.

  Fail-closed: runs `FilepackManifest.validate` first (paths, version,
  format_level, segment geometry). Payload size capped at `maxRkyvPayloadLen`.
-/
def encodeRkyvManifest (m : FilepackManifest) : Except FilepackError ByteArray :=
  match m.validate with
  | .error e => .error e
  | .ok () =>
    Id.run do
      -- Phase 1: nested pointed-to data in entry / field order (rkyv serialize).
      let mut buf := ByteArray.empty
      let mut resolvers : Array EntryResolver := Array.mkEmpty m.entries.size
      let mut err : Option FilepackError := none
      for i in [:m.entries.size] do
        if err.isNone then
          let e := m.entries[i]!
          let pathBytes := utf8 e.relPath
          if pathBytes.size > maxRelPathLen then
            err := some .relPathTooLong
          else
            let mut pathOol := false
            let mut pathDataPos : Nat := 0
            if pathBytes.size > stringInlineCap then
              pathOol := true
              pathDataPos := buf.size
              buf := appendBA buf pathBytes
            -- SegmentRef array (60 B each; POD layout matches ArchivedSegmentRef).
            let segsPos := buf.size
            for j in [:e.segments.size] do
              if err.isNone then
                match (e.segments[j]!).toBytes with
                | .error se => err := some se
                | .ok sb =>
                  if sb.size != segmentRefSize then
                    err := some .invalidWire
                  else
                    buf := appendBA buf sb
            if err.isNone then
              let mut ots : Option (Nat × Nat) := none
              match e.otsProof with
              | none => pure ()
              | some proof =>
                if proof.size > maxOtsProofLen then
                  err := some .otsProofTooLarge
                else
                  let p := buf.size
                  buf := appendBA buf proof
                  ots := some (p, proof.size)
              if err.isNone then
                resolvers := resolvers.push {
                  pathBytes := pathBytes
                  pathOol := pathOol
                  pathDataPos := pathDataPos
                  segsPos := segsPos
                  segsLen := e.segments.size
                  ots := ots
                  entry := e
                }
      match err with
      | some e => pure (.error e)
      | none =>
        -- Phase 2: contiguous ArchivedFilepackEntry records (resolve_aligned, zeroed).
        let entriesPos := buf.size
        for i in [:resolvers.size] do
          let r := resolvers[i]!
          let entryPos := buf.size
          if r.pathOol then
            buf := appendBA buf (encodeOolStringHeader entryPos r.pathDataPos r.pathBytes.size)
          else
            buf := appendBA buf (encodeInlineString r.pathBytes)
          buf := appendBA buf r.entry.contentBlake3
          buf := buf.push r.entry.segmentFormat
          let segVecPos := buf.size
          buf := appendBA buf (putRelPtr segVecPos r.segsPos)
          buf := appendBA buf (putUInt32LE (UInt32.ofNat r.segsLen))
          match r.ots with
          | none =>
            -- ArchivedOption::None: tag 0 + zero padding (resolve_aligned zeros).
            buf := appendBA buf (replicate optionVecSlot 0)
          | some (op, olen) =>
            buf := buf.push 1
            let relPtrPos := buf.size
            buf := appendBA buf (putRelPtr relPtrPos op)
            buf := appendBA buf (putUInt32LE (UInt32.ofNat olen))
        -- Phase 3: root at end.
        buf := appendBA buf (putUInt32LE (UInt32.ofNat m.version))
        buf := buf.push m.formatLevel
        let entriesVecPos := buf.size
        buf := appendBA buf (putRelPtr entriesVecPos entriesPos)
        buf := appendBA buf (putUInt32LE (UInt32.ofNat m.entries.size))
        if buf.size > maxRkyvPayloadLen then
          pure (.error .tooManyEntries)
        else
          pure (.ok buf)

/-- Product catalog body encode: **rkyv** FilepackManifestWire v2 (W3). -/
def encodeCatalogBody (m : FilepackManifest) : Except FilepackError ByteArray :=
  encodeRkyvManifest m

def isCfp2 (bytes : ByteArray) : Bool :=
  bytes.size ≥ 4 &&
    bytes.get! 0 == 0x43 && bytes.get! 1 == 0x46 &&
    bytes.get! 2 == 0x50 && bytes.get! 3 == 0x32

/--
  Dual-decode catalog body: **prefer rkyv** (product wire / W3), fall back to CFP2.

  Do **not** sniffer-dispatch solely on the first four bytes equaling `CFP2`: a valid
  rkyv body can begin with nested data whose first four bytes are `0x43 0x46 0x50 0x32`
  (e.g. a segment Bao root). Trying rkyv first keeps those catalogs decodable.
  Genuine CFP2 fails rkyv validate and then succeeds via `fromWireBytes`.
-/
def decodeCatalogBody (bytes : ByteArray) (catalogBaoRoot : ByteArray) :
    Except FilepackError FilepackManifest :=
  match decodeRkyvManifest bytes catalogBaoRoot with
  | .ok m => .ok m
  | .error rkyvErr =>
    if isCfp2 bytes then
      FilepackManifest.fromWireBytes bytes catalogBaoRoot
    else
      .error rkyvErr

/-- Empty-entries golden (Rust FilepackManifest v2, format c14). -/
def goldenEmptyHex : String := "020000000efbffffff00000000"

/-- Single-entry golden: `a.txt`, one SegmentRef, no OTS. -/
def goldenSingleHex : String :=
  "1111111111111111111111111111111111111111111111111111111111111111" ++
  "00000000640000000000000000000000400000004000000080000000" ++
  "612e747874ffffff" ++
  "2222222222222222222222222222222222222222222222222222222222222222" ++
  "0e9bffffff01000000000000000000000000" ++
  "020000000ec1ffffff01000000"

/-- Multi-entry golden: `a.txt` + out-of-line long path + OTS Some (275 B).

  Regenerated via `cargo run --example dump_rkyv_r9` → `tests/fixtures/rkyv/multi_entry_ots.bin`.
-/
def goldenMultiOtsHex : String :=
  "1111111111111111111111111111111111111111111111111111111111111111" ++
  "00000000640000000000000000000000400000004000000080000000" ++
  "622f6c6f6e6765722d706174682d6e616d652e747874" ++
  "4444444444444444444444444444444444444444444444444444444444444444" ++
  "00000000c80000000000000000000000400000004000000080000000" ++
  "abcdef01" ++
  "612e747874ffffff" ++
  "2222222222222222222222222222222222222222222222222222222222222222" ++
  "0e45ffffff01000000000000000000000000" ++
  "9600000070ffffff" ++
  "3333333333333333333333333333333333333333333333333333333333333333" ++
  "0e5dffffff010000000190ffffff04000000" ++
  "020000000e87ffffff02000000"

/-- Exactly 8-byte path (inline boundary). -/
def goldenPathInline8Hex : String :=
  "1111111111111111111111111111111111111111111111111111111111111111" ++
  "00000000640000000000000000000000400000004000000080000000" ++
  "3132333435363738" ++
  "2222222222222222222222222222222222222222222222222222222222222222" ++
  "0e9bffffff01000000000000000000000000" ++
  "020000000ec1ffffff01000000"

/-- Exactly 9-byte path (out-of-line boundary). -/
def goldenPathOol9Hex : String :=
  "313233343536373839" ++
  "1111111111111111111111111111111111111111111111111111111111111111" ++
  "00000000640000000000000000000000400000004000000080000000" ++
  "89000000bbffffff" ++
  "2222222222222222222222222222222222222222222222222222222222222222" ++
  "0e9bffffff01000000000000000000000000" ++
  "020000000ec1ffffff01000000"

/-- One entry, two SegmentRefs (contiguous 0..1). -/
def goldenTwoSegmentsHex : String :=
  "1111111111111111111111111111111111111111111111111111111111111111" ++
  "00000000640000000000000000000000400000004000000080000000" ++
  "1212121212121212121212121212121212121212121212121212121212121212" ++
  "010000003200000000000000c0000000400000000001000080000000" ++
  "612e747874ffffff" ++
  "2222222222222222222222222222222222222222222222222222222222222222" ++
  "0e5fffffff02000000000000000000000000" ++
  "020000000ec1ffffff01000000"

/-- OTS Some on first entry only; second None. -/
def goldenOtsFirstOnlyHex : String :=
  "1111111111111111111111111111111111111111111111111111111111111111" ++
  "00000000640000000000000000000000400000004000000080000000" ++
  "dead" ++
  "4444444444444444444444444444444444444444444444444444444444444444" ++
  "00000000c80000000000000000000000400000004000000080000000" ++
  "612e747874ffffff" ++
  "2222222222222222222222222222222222222222222222222222222222222222" ++
  "0e5dffffff010000000190ffffff02000000" ++
  "622e747874ffffff" ++
  "3333333333333333333333333333333333333333333333333333333333333333" ++
  "0e61ffffff01000000000000000000000000" ++
  "020000000e87ffffff02000000"

/-- rkyv body beginning with ASCII `CFP2` (segment root prefix) — sniffer regression. -/
def goldenRkyvCfp2PrefixHex : String :=
  "4346503211111111111111111111111111111111111111111111111111111111" ++
  "00000000640000000000000000000000400000004000000080000000" ++
  "612e747874ffffff" ++
  "2222222222222222222222222222222222222222222222222222222222222222" ++
  "0e9bffffff01000000000000000000000000" ++
  "020000000ec1ffffff01000000"

theorem golden_empty_hex_len : goldenEmptyHex.length = 26 := by native_decide

end Carbonado.RkyvFilepack
