/-
  FilepackManifest v2 for Adamantine catalogs (Program G).

  **Wire note (LIMITS):** Rust uses rkyv `FilepackManifestWire`. Lean ships a
  deterministic **CFP2** native codec with the same *logical* fields (version,
  format_level, entries with SegmentRef + content_blake3). Adamantine envelope
  framing matches Rust (`manifest_len` + body + `bundle_len` + bundle); the
  *manifest body* is Lean-native CFP2, not rkyv — interop with Rust-produced
  catalogs requires a converter (tracked LIMITS). Product CLI uses CFP2 end-to-end.

  Path rules: fail-closed (no `..`, no absolute, no backslash, length caps).
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Adamantine

namespace Carbonado.Filepack

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Adamantine

/-- FilepackManifest wire schema version (v2). -/
def filepackManifestVersion : Nat := 2

/-- Max entries (DoS). -/
def maxFilepackEntries : Nat := 100000

/-- Max rel_path bytes. -/
def maxRelPathLen : Nat := 4096

/-- Max OTS proof blob. -/
def maxOtsProofLen : Nat := 65536

/-- Max segments per entry. -/
def maxSegmentsPerEntry : Nat := 10000

/-- Max total segment refs. -/
def maxTotalSegmentRefs : Nat := 1000000

/-- Max bare segment main bytes. -/
def maxSegmentMainLen : Nat := 256 * 1024 * 1024

/-- CFP2 magic (`CFP2`). -/
def cfp2Magic : List UInt8 := [0x43, 0x46, 0x50, 0x32]

theorem cfp2Magic_length : cfp2Magic.length = 4 := by native_decide

/-- Segment format constants (directory). -/
def segmentFormatPublicRaw : UInt8 := 0x0C       -- c12
def segmentFormatPublicCompressed : UInt8 := 0x0E -- c14
def segmentFormatEncryptedRaw : UInt8 := 0x0D     -- c13
def segmentFormatEncryptedCompressed : UInt8 := 0x0F -- c15

/-- Strict Filepack / path error taxonomy. -/
inductive FilepackError where
  /-- Empty relative path. -/
  | emptyRelPath
  /-- rel_path exceeds max length. -/
  | relPathTooLong
  /-- Backslash present (must use `/`). -/
  | relPathBackslash
  /-- Absolute path (leading `/`). -/
  | relPathAbsolute
  /-- `..` component present. -/
  | relPathTraversal
  /-- Empty path component (e.g. `//` or trailing `/` with empty). -/
  | relPathEmptyComponent
  /-- Null byte in path. -/
  | relPathNullByte
  /-- Manifest version ≠ 2. -/
  | unsupportedVersion (v : Nat)
  /-- format_level not c14/c15. -/
  | invalidFormatLevel (fmt : UInt8)
  /-- Segment format not c12–c15 or encryption mismatch. -/
  | segmentFormatMismatch (fmt : UInt8)
  /-- Legacy c4–c7 segment format rejected. -/
  | legacySegmentFormat (fmt : UInt8)
  /-- Entry has zero segments. -/
  | emptySegments
  /-- chunk_index not contiguous 0..n-1. -/
  | invalidChunkSequence
  /-- main_len exceeds DoS cap. -/
  | mainLenTooLarge
  /-- Entry count / total refs / wire length cap. -/
  | tooManyEntries
  /-- Too many segments on one entry. -/
  | tooManySegments
  /-- Wire parse failure (truncated / bad magic / length). -/
  | invalidWire
  /-- Root / hash field wrong size. -/
  | invalidHashLength
  /-- OTS proof too large. -/
  | otsProofTooLarge
  /-- Entries not sorted by rel_path. -/
  | entriesUnsorted
  deriving DecidableEq, Repr

/-- One bare segment main reference (bundle offsets into Adamantine Bao bundle). -/
structure SegmentRef where
  segmentBaoRoot : ByteArray
  chunkIndex : UInt32
  mainLen : UInt64
  verificationOutboardOffset : UInt32
  verificationOutboardLen : UInt32
  fecParityOffset : UInt32
  fecParityLen : UInt32
  deriving DecidableEq, Inhabited

/-- One file entry in the catalog. -/
structure FilepackEntry where
  relPath : String
  contentBlake3 : ByteArray
  segmentFormat : UInt8
  segments : Array SegmentRef
  /-- Optional OTS proof (wire-encoded when present). -/
  otsProof : Option ByteArray
  deriving DecidableEq, Inhabited

/-- Directory catalog manifest (API view; catalog_bao_root bound from filename). -/
structure FilepackManifest where
  version : Nat
  formatLevel : UInt8
  catalogBaoRoot : ByteArray
  entries : Array FilepackEntry
  deriving DecidableEq, Inhabited

/--
  Fail-closed relative path validation (AGENTS / Rust `validate_rel_path` + extras).

  Rejects: empty, too long, `\`, absolute `/`, `..`, empty components, NUL.
-/
def validateRelPath (rel : String) : Except FilepackError Unit :=
  if rel.isEmpty then
    .error .emptyRelPath
  else if rel.length > maxRelPathLen then
    .error .relPathTooLong
  else if rel.contains '\\' then
    .error .relPathBackslash
  else if rel.startsWith "/" then
    .error .relPathAbsolute
  else if rel.contains (Char.ofNat 0) then
    .error .relPathNullByte
  else
    Id.run do
      let parts := rel.splitOn "/"
      let mut err : Option FilepackError := none
      for p in parts do
        if err.isNone then
          if p == ".." then
            err := some .relPathTraversal
          else if p.isEmpty then
            err := some .relPathEmptyComponent
      match err with
      | some e => pure (.error e)
      | none => pure (.ok ())

/-- Segment format is one of c12–c15. -/
def isDirectorySegmentFormat (fmt : UInt8) : Bool :=
  fmt == segmentFormatPublicRaw || fmt == segmentFormatPublicCompressed ||
  fmt == segmentFormatEncryptedRaw || fmt == segmentFormatEncryptedCompressed

/-- Legacy c4–c7. -/
def isLegacySegmentFormat (fmt : UInt8) : Bool :=
  fmt ≥ 0x04 && fmt ≤ 0x07

/-- Segment encryption bit must match catalog encryption. -/
def segmentMatchesCatalogEncryption (segmentFmt : UInt8) (catalogEncrypted : Bool) : Bool :=
  let segEnc := segmentFmt &&& 1 != 0
  segEnc == catalogEncrypted

/-- Validate segment format against catalog. -/
def validateSegmentFormat (segmentFmt : UInt8) (catalogEncrypted : Bool) :
    Except FilepackError Unit :=
  if isLegacySegmentFormat segmentFmt then
    .error (.legacySegmentFormat segmentFmt)
  else if !isDirectorySegmentFormat segmentFmt then
    .error (.segmentFormatMismatch segmentFmt)
  else if !segmentMatchesCatalogEncryption segmentFmt catalogEncrypted then
    .error (.segmentFormatMismatch segmentFmt)
  else
    -- c12–c15 all include Verification|Fec bits by definition of the four codes
    .ok ()

/-- Validate segments: non-empty, contiguous chunk_index 0..n-1, root size, main_len cap. -/
def validateSegments (segments : Array SegmentRef) : Except FilepackError Unit :=
  if segments.size == 0 then
    .error .emptySegments
  else if segments.size > maxSegmentsPerEntry then
    .error .tooManySegments
  else
    Id.run do
      let n := segments.size
      let mut err : Option FilepackError := none
      for i in [:n] do
        if err.isNone then
          let s := segments[i]!
          if s.segmentBaoRoot.size != hashLen then
            err := some .invalidHashLength
          else if UInt64.toNat s.mainLen > maxSegmentMainLen then
            err := some .mainLenTooLarge
          else if UInt32.toNat s.chunkIndex != i then
            err := some .invalidChunkSequence
      match err with
      | some e => pure (.error e)
      | none => pure (.ok ())

/-- Validate full manifest semantics (caller supplies expected catalog root). -/
def FilepackManifest.validate (m : FilepackManifest) : Except FilepackError Unit :=
  if m.version != filepackManifestVersion then
    .error (.unsupportedVersion m.version)
  else if m.formatLevel != adamantineFmtPublic && m.formatLevel != adamantineFmtEncrypted then
    .error (.invalidFormatLevel m.formatLevel)
  else if m.catalogBaoRoot.size != hashLen then
    .error .invalidHashLength
  else if m.entries.size > maxFilepackEntries then
    .error .tooManyEntries
  else
    let catalogEnc := m.formatLevel &&& 1 != 0
    Id.run do
      let mut err : Option FilepackError := none
      let mut totalSegs : Nat := 0
      let mut prevPath : Option String := none
      for i in [:m.entries.size] do
        if err.isNone then
          let e := m.entries[i]!
          match validateRelPath e.relPath with
          | .error pe => err := some pe
          | .ok () =>
            match prevPath with
            | some p =>
              if e.relPath ≤ p then
                err := some .entriesUnsorted
            | none => pure ()
            prevPath := some e.relPath
            if e.contentBlake3.size != hashLen then
              err := some .invalidHashLength
            else
              match validateSegmentFormat e.segmentFormat catalogEnc with
              | .error se => err := some se
              | .ok () =>
                match validateSegments e.segments with
                | .error se => err := some se
                | .ok () =>
                  totalSegs := totalSegs + e.segments.size
                  if totalSegs > maxTotalSegmentRefs then
                    err := some .tooManyEntries
                  match e.otsProof with
                  | some p =>
                    if p.size > maxOtsProofLen then
                      err := some .otsProofTooLarge
                  | none => pure ()
      match err with
      | some e => pure (.error e)
      | none => pure (.ok ())

/-- Serialize SegmentRef (fixed 32+4+8+4+4+4+4 = 60 bytes). -/
def SegmentRef.toBytes (s : SegmentRef) : Except FilepackError ByteArray :=
  if s.segmentBaoRoot.size != hashLen then
    .error .invalidHashLength
  else
    Id.run do
      let mut out := s.segmentBaoRoot
      out := appendBA out (putUInt32LE s.chunkIndex)
      out := appendBA out (putUInt64LE s.mainLen)
      out := appendBA out (putUInt32LE s.verificationOutboardOffset)
      out := appendBA out (putUInt32LE s.verificationOutboardLen)
      out := appendBA out (putUInt32LE s.fecParityOffset)
      out := appendBA out (putUInt32LE s.fecParityLen)
      pure (.ok out)

/-- Parse SegmentRef from bytes at offset; returns (ref, next_offset). -/
def parseSegmentRef (bs : ByteArray) (off : Nat) :
    Except FilepackError (SegmentRef × Nat) :=
  if off + 60 > bs.size then
    .error .invalidWire
  else
    let root := bs.extract off (off + 32)
    let chunkIndex := getUInt32LE bs (off + 32)
    let mainLen := getUInt64LE bs (off + 36)
    let vo := getUInt32LE bs (off + 44)
    let vl := getUInt32LE bs (off + 48)
    let fo := getUInt32LE bs (off + 52)
    let fl := getUInt32LE bs (off + 56)
    .ok ({
      segmentBaoRoot := root
      chunkIndex := chunkIndex
      mainLen := mainLen
      verificationOutboardOffset := vo
      verificationOutboardLen := vl
      fecParityOffset := fo
      fecParityLen := fl
    }, off + 60)

/-- Serialize one entry. -/
def FilepackEntry.toBytes (e : FilepackEntry) : Except FilepackError ByteArray :=
  match validateRelPath e.relPath with
  | .error err => .error err
  | .ok () =>
    if e.contentBlake3.size != hashLen then
      .error .invalidHashLength
    else
      let pathBytes := utf8 e.relPath
      if pathBytes.size > maxRelPathLen then
        .error .relPathTooLong
      else if pathBytes.size > 65535 then
        .error .relPathTooLong
      else
        match validateSegments e.segments with
        | .error err => .error err
        | .ok () =>
          Id.run do
            let mut out := ByteArray.empty
            out := appendBA out (putUInt32LE (UInt32.ofNat pathBytes.size))
            out := appendBA out pathBytes
            out := appendBA out e.contentBlake3
            out := out.push e.segmentFormat
            out := appendBA out (putUInt32LE (UInt32.ofNat e.segments.size))
            let mut err : Option FilepackError := none
            for i in [:e.segments.size] do
              if err.isNone then
                match (e.segments[i]!).toBytes with
                | .error se => err := some se
                | .ok sb => out := appendBA out sb
            match err with
            | some se => pure (.error se)
            | none =>
              match e.otsProof with
              | none =>
                out := out.push 0
                pure (.ok out)
              | some proof =>
                if proof.size > maxOtsProofLen then
                  pure (.error .otsProofTooLarge)
                else
                  out := out.push 1
                  out := appendBA out (putUInt32LE (UInt32.ofNat proof.size))
                  out := appendBA out proof
                  pure (.ok out)

/-- Parse entry at offset. -/
def parseEntry (bs : ByteArray) (off : Nat) : Except FilepackError (FilepackEntry × Nat) :=
  if off + 4 > bs.size then
    .error .invalidWire
  else
    let pathLen := UInt32.toNat (getUInt32LE bs off)
    let pathStart := off + 4
    let pathEnd := pathStart + pathLen
    if pathEnd + 32 + 1 + 4 > bs.size then
      .error .invalidWire
    else
      let pathBytes := bs.extract pathStart pathEnd
      match String.fromUTF8? pathBytes with
      | none => .error .invalidWire
      | some relPath =>
        match validateRelPath relPath with
        | .error e => .error e
        | .ok () =>
          let contentBlake3 := bs.extract pathEnd (pathEnd + 32)
          let segmentFormat := bs.get! (pathEnd + 32)
          let segCount := UInt32.toNat (getUInt32LE bs (pathEnd + 33))
          if segCount > maxSegmentsPerEntry then
            .error .tooManySegments
          else
            Id.run do
              let mut segs : Array SegmentRef := Array.mkEmpty segCount
              let mut cur := pathEnd + 37
              let mut err : Option FilepackError := none
              for _ in [:segCount] do
                if err.isNone then
                  match parseSegmentRef bs cur with
                  | .error e => err := some e
                  | .ok (s, next) =>
                    segs := segs.push s
                    cur := next
              match err with
              | some e => pure (.error e)
              | none =>
                if cur ≥ bs.size then
                  pure (.error .invalidWire)
                else
                  let hasOts := bs.get! cur
                  cur := cur + 1
                  if hasOts == 0 then
                    pure (.ok ({
                      relPath := relPath
                      contentBlake3 := contentBlake3
                      segmentFormat := segmentFormat
                      segments := segs
                      otsProof := none
                    }, cur))
                  else if hasOts == 1 then
                    if cur + 4 > bs.size then
                      pure (.error .invalidWire)
                    else
                      let otsLen := UInt32.toNat (getUInt32LE bs cur)
                      cur := cur + 4
                      if otsLen > maxOtsProofLen then
                        pure (.error .otsProofTooLarge)
                      else if cur + otsLen > bs.size then
                        pure (.error .invalidWire)
                      else
                        let proof := bs.extract cur (cur + otsLen)
                        pure (.ok ({
                          relPath := relPath
                          contentBlake3 := contentBlake3
                          segmentFormat := segmentFormat
                          segments := segs
                          otsProof := some proof
                        }, cur + otsLen))
                  else
                    pure (.error .invalidWire)

/-- Serialize wire body (no catalog root — bound out-of-band). -/
def FilepackManifest.toWireBytes (m : FilepackManifest) : Except FilepackError ByteArray :=
  match m.validate with
  | .error e => .error e
  | .ok () =>
    Id.run do
      let mut out := ofList cfp2Magic
      out := appendBA out (putUInt32LE (UInt32.ofNat m.version))
      out := out.push m.formatLevel
      out := appendBA out (putUInt32LE (UInt32.ofNat m.entries.size))
      let mut err : Option FilepackError := none
      for i in [:m.entries.size] do
        if err.isNone then
          match (m.entries[i]!).toBytes with
          | .error e => err := some e
          | .ok eb => out := appendBA out eb
      match err with
      | some e => pure (.error e)
      | none => pure (.ok out)

/-- Parse wire body; bind catalog root from filename / caller. -/
def FilepackManifest.fromWireBytes (bytes : ByteArray) (catalogBaoRoot : ByteArray) :
    Except FilepackError FilepackManifest :=
  if catalogBaoRoot.size != hashLen then
    .error .invalidHashLength
  else if bytes.size < 4 + 4 + 1 + 4 then
    .error .invalidWire
  else if !ctEq (bytes.extract 0 4) (ofList cfp2Magic) then
    .error .invalidWire
  else
    let version := UInt32.toNat (getUInt32LE bytes 4)
    if version != filepackManifestVersion then
      .error (.unsupportedVersion version)
    else
      let formatLevel := bytes.get! 8
      let entryCount := UInt32.toNat (getUInt32LE bytes 9)
      if entryCount > maxFilepackEntries then
        .error .tooManyEntries
      else
        Id.run do
          let mut entries : Array FilepackEntry := Array.mkEmpty entryCount
          let mut cur : Nat := 13
          let mut err : Option FilepackError := none
          for _ in [:entryCount] do
            if err.isNone then
              match parseEntry bytes cur with
              | .error e => err := some e
              | .ok (e, next) =>
                entries := entries.push e
                cur := next
          match err with
          | some e => pure (.error e)
          | none =>
            if cur != bytes.size then
              pure (.error .invalidWire)
            else
              let m : FilepackManifest := {
                version := version
                formatLevel := formatLevel
                catalogBaoRoot := catalogBaoRoot
                entries := entries
              }
              match m.validate with
              | .error e => pure (.error e)
              | .ok () => pure (.ok m)

/-- Segment format policy (subset of Rust). -/
inductive SegmentFormatPolicy where
  | auto
  | forceRaw
  | forceCompressed
  | forceC12
  | forceC14
  | forceC13
  | forceC15
  deriving DecidableEq, Repr

/-- Simple incompressible heuristic: empty or high-entropy-looking magic prefixes. -/
def isLikelyIncompressible (data : ByteArray) : Bool :=
  if data.size == 0 then
    true
  else if data.size ≥ 4 then
    -- gzip, zip, png, jpeg, zstd, 7z, pdf, webp-ish
    let b0 := data.get! 0
    let b1 := data.get! 1
    let b2 := data.get! 2
    let b3 := data.get! 3
    (b0 == 0x1f && b1 == 0x8b) || -- gzip
    (b0 == 0x50 && b1 == 0x4b) || -- zip/pk
    (b0 == 0x89 && b1 == 0x50 && b2 == 0x4e && b3 == 0x47) || -- png
    (b0 == 0xff && b1 == 0xd8) || -- jpeg
    (b0 == 0x28 && b1 == 0xb5 && b2 == 0x2f && b3 == 0xfd) || -- zstd
    (b0 == 0x37 && b1 == 0x7a) || -- 7z
    (b0 == 0x25 && b1 == 0x50 && b2 == 0x44 && b3 == 0x46) -- %PDF
  else
    false

/-- Resolve segment format for one file. -/
def SegmentFormatPolicy.resolve (self : SegmentFormatPolicy) (catalogEncrypted : Bool)
    (data : ByteArray) : Except FilepackError UInt8 :=
  let fmt : UInt8 :=
    match self with
    | .auto =>
      if catalogEncrypted then
        if isLikelyIncompressible data then segmentFormatEncryptedRaw
        else segmentFormatEncryptedCompressed
      else if isLikelyIncompressible data then segmentFormatPublicRaw
      else segmentFormatPublicCompressed
    | .forceRaw =>
      if catalogEncrypted then segmentFormatEncryptedRaw else segmentFormatPublicRaw
    | .forceCompressed =>
      if catalogEncrypted then segmentFormatEncryptedCompressed
      else segmentFormatPublicCompressed
    | .forceC12 => segmentFormatPublicRaw
    | .forceC14 => segmentFormatPublicCompressed
    | .forceC13 => segmentFormatEncryptedRaw
    | .forceC15 => segmentFormatEncryptedCompressed
  validateSegmentFormat fmt catalogEncrypted |>.map (fun _ => fmt)

/-- Path validation unit tests as theorems. -/
theorem rel_empty :
    (match validateRelPath "" with | .error .emptyRelPath => true | _ => false) = true := by
  native_decide

theorem rel_traversal :
    (match validateRelPath "a/../b" with | .error .relPathTraversal => true | _ => false) =
      true := by
  native_decide

theorem rel_absolute :
    (match validateRelPath "/etc/passwd" with | .error .relPathAbsolute => true | _ => false) =
      true := by
  native_decide

theorem rel_backslash :
    (match validateRelPath "a\\b" with | .error .relPathBackslash => true | _ => false) =
      true := by
  native_decide

theorem rel_ok :
    (match validateRelPath "src/main.lean" with | .ok () => true | _ => false) = true := by
  native_decide

theorem rel_empty_component :
    (match validateRelPath "a//b" with | .error .relPathEmptyComponent => true | _ => false) =
      true := by
  native_decide

/-- Path with embedded NUL is rejected (`relPathNullByte`). -/
theorem rel_null :
    (match validateRelPath ("a" ++ String.singleton (Char.ofNat 0) ++ "b") with
     | .error .relPathNullByte => true
     | _ => false) = true := by
  native_decide

end Carbonado.Filepack
