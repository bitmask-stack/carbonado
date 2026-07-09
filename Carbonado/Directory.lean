/-
  Adamantine directory archive pure model (Program G).

  Layout (AGENTS §7.1):
  * Catalog: inboard headered `{catalog_root}.adam.c14` / `.adam.c15`
    body = Adamantine10 envelope (CFP2 FilepackManifest + centralized Bao bundle)
  * Segments: bare mains `{seg_root}.c12|c13|c14|c15` (no .out/.par on disk)
  * Bundle: per-segment [verification_outboard][fec_parity] indexed by SegmentRef

  Path rules fail-closed via Filepack.validateRelPath.
  Content integrity: BLAKE3 of recovered plaintext vs entry.content_blake3.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Header
import Carbonado.Pipeline
import Carbonado.Outboard
import Carbonado.Adamantine
import Carbonado.Filepack
import Carbonado.Bao.Blake3
import Carbonado.Fec.Inboard

namespace Carbonado.Directory

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Header
open Carbonado.Pipeline
open Carbonado.Outboard
open Carbonado.Adamantine
open Carbonado.Filepack
open Carbonado.Bao.Blake3
open Carbonado.Fec.Inboard

/-- Strict directory error taxonomy (exact-match in tests; no lumped diagnostics). -/
inductive DirectoryError where
  -- Path / layout
  | pathTraversal
  | pathAbsolute
  | pathBackslash
  | pathEmpty
  | pathEmptyComponent
  | pathTooLong
  | pathNullByte
  | notADirectory
  | symlinkNotAllowed
  | directoryLayoutMismatch
  | missingSegment
  | segmentMainLenMismatch
  | catalogBaoRootMismatch
  | contentBlake3Mismatch
  | invalidCatalogPath
  | zeroMasterKeyNotAllowed
  | encryptedDirectoryNotRequested
  -- Adamantine
  | invalidAdamantineHeader
  | invalidAdamantineMagic
  | unsupportedAdamantineVersion (major minor : UInt8)
  | invalidAdamantineCarbonadoFormat (fmt : UInt8)
  | invalidAdamantineFlags (flags : UInt8)
  | adamantinePayloadTooLarge
  | adamantinePayloadLengthMismatch
  -- Filepack
  | invalidFilepackManifest
  | unsupportedFilepackVersion (v : Nat)
  | invalidFormatLevel (fmt : UInt8)
  | segmentFormatMismatch (fmt : UInt8)
  | legacySegmentFormat (fmt : UInt8)
  | emptySegments
  | invalidChunkSequence
  | mainLenTooLarge
  | tooManyEntries
  | tooManySegments
  | entriesUnsorted
  | invalidWire
  | missingVerificationOutboard
  | missingFecParity
  /-- FEC parity length does not match encode geometry for main_len. -/
  | fecParityLenMismatch
  /-- FEC parity present when segment format lacks FEC (or zero main). -/
  | unexpectedFecParity
  | otsFeatureRequired
  | otsProofTooLarge
  -- Pipeline / lower
  | pipeline (e : PipelineError)
  | invalidHashLength
  | insufficientNonces
  deriving DecidableEq, Repr

def ofFilepackError : FilepackError → DirectoryError
  | .emptyRelPath => .pathEmpty
  | .relPathTooLong => .pathTooLong
  | .relPathBackslash => .pathBackslash
  | .relPathAbsolute => .pathAbsolute
  | .relPathTraversal => .pathTraversal
  | .relPathEmptyComponent => .pathEmptyComponent
  | .relPathNullByte => .pathNullByte
  | .unsupportedVersion v => .unsupportedFilepackVersion v
  | .invalidFormatLevel f => .invalidFormatLevel f
  | .segmentFormatMismatch f => .segmentFormatMismatch f
  | .legacySegmentFormat f => .legacySegmentFormat f
  | .emptySegments => .emptySegments
  | .invalidChunkSequence => .invalidChunkSequence
  | .mainLenTooLarge => .mainLenTooLarge
  | .tooManyEntries => .tooManyEntries
  | .tooManySegments => .tooManySegments
  | .invalidWire => .invalidWire
  | .invalidHashLength => .invalidHashLength
  | .otsProofTooLarge => .otsProofTooLarge
  | .entriesUnsorted => .entriesUnsorted

def ofAdamantineError : AdamantineError → DirectoryError
  | .invalidHeader => .invalidAdamantineHeader
  | .invalidMagic => .invalidAdamantineMagic
  | .unsupportedVersion maj min => .unsupportedAdamantineVersion maj min
  | .invalidCarbonadoFormat f => .invalidAdamantineCarbonadoFormat f
  | .invalidFlags f => .invalidAdamantineFlags f
  | .payloadTooLarge _ _ => .adamantinePayloadTooLarge
  | .payloadLengthMismatch _ _ => .adamantinePayloadLengthMismatch

def ofPipelineError (e : PipelineError) : DirectoryError := .pipeline e

/-- One logical file input for pure directory encode. -/
structure DirFile where
  relPath : String
  content : ByteArray
  deriving DecidableEq, Inhabited

/-- One encoded bare segment artifact. -/
structure SegmentArtifact where
  filename : String
  main : ByteArray
  baoRoot : ByteArray
  segmentFormat : UInt8
  chunkIndex : UInt32
  deriving DecidableEq, Inhabited

/-- Full encoded directory archive (in-memory). -/
structure DirectoryArchive where
  catalogFilename : String
  catalogBytes : ByteArray
  catalogBaoRoot : ByteArray
  catalogFormat : UInt8
  segments : Array SegmentArtifact
  entryCount : Nat
  deriving DecidableEq, Inhabited

/-- Default segment budget = u32::MAX. -/
def defaultSegmentPlaintextBudget : Nat := 4294967295

/-- Encode options (pure). -/
structure DirectoryEncodeOptions where
  catalogEncrypted : Bool := false
  segmentPolicy : SegmentFormatPolicy := .auto
  segmentPlaintextBudget : Nat := defaultSegmentPlaintextBudget
  /--
    Require OTS flag in Adamantine header.
    **Rejected at encode** until OTS stamps exist (`otsFeatureRequired`) — never mints
    archives that always fail decode.
  -/
  requireOts : Bool := false
  deriving DecidableEq, Repr

/-- Expected outboard FEC parity byte length for bare `main_len` (Rust `expected_fec_parity_len`). -/
def expectedFecParityLen (mainLen : Nat) : Nat :=
  if mainLen == 0 then 0
  else
    let chunk := (calcPaddingLen mainLen).chunkLen
    (fecM - fecK) * chunk

/--
  Validate SegmentRef bundle semantics for a directory segment (Rust
  `validate_segment_bundle_semantics` subset: FEC length geometry + non-FEC hygiene).
-/
def validateSegmentBundleSemantics (segmentFormat : UInt8) (sref : SegmentRef) :
    Except DirectoryError Unit :=
  let fmtBits := FormatBits.ofUInt8 segmentFormat
  let mainLen := UInt64.toNat sref.mainLen
  let fecLen := UInt32.toNat sref.fecParityLen
  if mainLen > maxSegmentMainLen then
    .error .mainLenTooLarge
  else if fmtBits.fec then
    if mainLen > 0 && fecLen == 0 then
      .error .missingFecParity
    else if mainLen == 0 && fecLen != 0 then
      .error .unexpectedFecParity
    else if mainLen > 0 && fecLen != expectedFecParityLen mainLen then
      .error .fecParityLenMismatch
    else
      -- Contiguous: fec_parity_offset should follow verification outboard when both present.
      let expectedFecOff :=
        UInt32.toNat sref.verificationOutboardOffset + UInt32.toNat sref.verificationOutboardLen
      if fecLen > 0 && UInt32.toNat sref.fecParityOffset != expectedFecOff then
        .error .invalidWire
      else
        .ok ()
  else if fecLen != 0 then
    .error .unexpectedFecParity
  else
    .ok ()

/-- Hex lowercase of a 32-byte root for filenames. -/
def rootHex (root : ByteArray) : Except DirectoryError String :=
  if root.size != hashLen then .error .invalidHashLength
  else .ok (toHex root)

/-- Decimal segment filename `{root}.c{fmt}`. -/
def segmentFilename (root : ByteArray) (fmt : UInt8) : Except DirectoryError String :=
  match rootHex root with
  | .error e => .error e
  | .ok h => .ok s!"{h}.c{fmt.toNat}"

/-- Catalog filename `{root}.adam.c{14|15}`. -/
def catalogFilename (root : ByteArray) (fmt : UInt8) : Except DirectoryError String :=
  match rootHex root with
  | .error e => .error e
  | .ok h => .ok s!"{h}.adam.c{fmt.toNat}"

/-- Parse `{64hex}.adam.c14` / `.adam.c15` → (root, format). -/
def parseCatalogName (name : String) : Except DirectoryError (ByteArray × UInt8) :=
  -- Expect at least 64 + ".adam.c" + digits
  if !name.endsWith ".adam.c14" && !name.endsWith ".adam.c15" then
    .error .invalidCatalogPath
  else
    let fmt : UInt8 := if name.endsWith ".adam.c15" then 15 else 14
    let suffixLen := if fmt == 15 then ".adam.c15".length else ".adam.c14".length
    if name.length < 64 + suffixLen then
      .error .invalidCatalogPath
    else
      let hexPart := name.dropRight suffixLen
      if hexPart.length != 64 then
        .error .invalidCatalogPath
      else
        match fromHex? hexPart with
        | none => .error .invalidCatalogPath
        | some root =>
          if root.size != hashLen then .error .invalidCatalogPath
          else .ok (root, fmt)

/-- Master key policy for catalog format. -/
def checkMasterPolicy (master : ByteArray) (catalogEncrypted : Bool) :
    Except DirectoryError Unit :=
  let allZero :=
    Id.run do
      let mut z := true
      for i in [:master.size] do
        if master.get! i != 0 then z := false
      pure z
  if master.size < 32 then
    .error (.pipeline .invalidKeyLength)
  else if catalogEncrypted && allZero then
    .error .zeroMasterKeyNotAllowed
  else if !catalogEncrypted && !allZero then
    .error .encryptedDirectoryNotRequested
  else
    .ok ()

/-- Split content by budget (last may be short; empty → one empty chunk). -/
def splitContent (content : ByteArray) (budget : Nat) : Array ByteArray :=
  let b := if budget == 0 then 1 else budget
  if content.size == 0 then
    #[ByteArray.empty]
  else
    Id.run do
      let mut out : Array ByteArray := #[]
      let mut off : Nat := 0
      while off < content.size do
        let end_ := min (off + b) content.size
        out := out.push (content.extract off end_)
        off := end_
      pure out

/-- Bundle builder (concat verification + fec blobs). -/
structure BundleBuilder where
  bytes : ByteArray
  deriving Inhabited

def BundleBuilder.empty : BundleBuilder := { bytes := ByteArray.empty }

def BundleBuilder.append (b : BundleBuilder) (blob : ByteArray) :
    Except DirectoryError (BundleBuilder × UInt32 × UInt32) :=
  let offset := b.bytes.size
  let len := blob.size
  let end_ := offset + len
  if end_ > maxBaoBundleLen then
    .error .adamantinePayloadTooLarge
  else if offset > u32Max || len > u32Max then
    .error .adamantinePayloadTooLarge
  else
    .ok ({ bytes := appendBA b.bytes blob }, UInt32.ofNat offset, UInt32.ofNat len)

/--
  Pure directory encode.

  `nonces` supplies one embedded-path nonce per **segment** when any segment is
  encrypted (c13/c15). Public archives may pass an empty nonce array.
-/
def encodeDirectory (master : ByteArray) (files : Array DirFile)
    (opts : DirectoryEncodeOptions) (nonces : Array ByteArray) :
    Except DirectoryError DirectoryArchive :=
  let catalogFmt : UInt8 :=
    if opts.catalogEncrypted then adamantineFmtEncrypted else adamantineFmtPublic
  -- OTS stamps not implemented: refuse to mint REQUIRE_OTS archives that always fail decode.
  if opts.requireOts then
    .error .otsFeatureRequired
  else
  match checkMasterPolicy master opts.catalogEncrypted with
  | .error e => .error e
  | .ok () =>
    Id.run do
      -- Sort files by rel_path for determinism
      let mut sorted := files
      -- simple insertion sort by relPath
      for i in [:sorted.size] do
        let mut j := i
        while j > 0 && (sorted[j]!).relPath < (sorted[j - 1]!).relPath do
          let tmp := sorted[j]!
          sorted := sorted.set! j (sorted[j - 1]!)
          sorted := sorted.set! (j - 1) tmp
          j := j - 1

      let mut entries : Array FilepackEntry := #[]
      let mut segments : Array SegmentArtifact := #[]
      let mut bundle := BundleBuilder.empty
      let mut nonceIdx : Nat := 0
      let mut err : Option DirectoryError := none

      for fi in [:sorted.size] do
        if err.isNone then
          let f := sorted[fi]!
          match validateRelPath f.relPath with
          | .error pe => err := some (ofFilepackError pe)
          | .ok () =>
            let contentHash := Carbonado.Bao.Blake3.hash f.content
            match opts.segmentPolicy.resolve opts.catalogEncrypted f.content with
            | .error pe => err := some (ofFilepackError pe)
            | .ok segFmt =>
              let fmtBits := FormatBits.ofUInt8 segFmt
              let chunks := splitContent f.content opts.segmentPlaintextBudget
              let mut segs : Array SegmentRef := #[]
              for ci in [:chunks.size] do
                if err.isNone then
                  let chunk := chunks[ci]!
                  let nonce : ByteArray :=
                    if fmtBits.encrypted then
                      if nonceIdx < nonces.size then nonces[nonceIdx]!
                      else ByteArray.empty
                    else
                      replicate nonceLen 0
                  if fmtBits.encrypted && (nonceIdx ≥ nonces.size || nonce.size != nonceLen) then
                    err := some .insufficientNonces
                  else
                    if fmtBits.encrypted then nonceIdx := nonceIdx + 1
                    match encodeOutboardBody master nonce chunk fmtBits with
                    | .error pe => err := some (ofPipelineError pe)
                    | .ok oenc =>
                      -- Single-leaf trees may have empty post-order outboard (no parent pairs).
                      if fmtBits.fec && oenc.main.size > 0 && oenc.fecParity.size == 0 then
                        err := some .missingFecParity
                      if err.isNone then
                        match bundle.append oenc.verificationOutboard with
                        | .error e => err := some e
                        | .ok (b1, vo, vl) =>
                          bundle := b1
                          if fmtBits.fec then
                            match bundle.append oenc.fecParity with
                            | .error e => err := some e
                            | .ok (b2, fo, fl) =>
                              bundle := b2
                              match segmentFilename oenc.baoHash segFmt with
                              | .error e => err := some e
                              | .ok sname =>
                                segments := segments.push {
                                  filename := sname
                                  main := oenc.main
                                  baoRoot := oenc.baoHash
                                  segmentFormat := segFmt
                                  chunkIndex := UInt32.ofNat ci
                                }
                                segs := segs.push {
                                  segmentBaoRoot := oenc.baoHash
                                  chunkIndex := UInt32.ofNat ci
                                  mainLen := UInt64.ofNat oenc.main.size
                                  verificationOutboardOffset := vo
                                  verificationOutboardLen := vl
                                  fecParityOffset := fo
                                  fecParityLen := fl
                                }
                          else
                            match segmentFilename oenc.baoHash segFmt with
                            | .error e => err := some e
                            | .ok sname =>
                              segments := segments.push {
                                filename := sname
                                main := oenc.main
                                baoRoot := oenc.baoHash
                                segmentFormat := segFmt
                                chunkIndex := UInt32.ofNat ci
                              }
                              segs := segs.push {
                                segmentBaoRoot := oenc.baoHash
                                chunkIndex := UInt32.ofNat ci
                                mainLen := UInt64.ofNat oenc.main.size
                                verificationOutboardOffset := vo
                                verificationOutboardLen := vl
                                fecParityOffset := 0
                                fecParityLen := 0
                              }
              if err.isNone then
                entries := entries.push {
                  relPath := f.relPath
                  contentBlake3 := contentHash
                  segmentFormat := segFmt
                  segments := segs
                  otsProof := none
                }

      match err with
      | some e => pure (.error e)
      | none =>
        -- Build CFP2 manifest (catalog root placeholder zeros until headered encode).
        let placeholderRoot := replicate hashLen 0
        let manifest : FilepackManifest := {
          version := filepackManifestVersion
          formatLevel := catalogFmt
          catalogBaoRoot := placeholderRoot
          entries := entries
        }
        match manifest.toWireBytes with
        | .error pe => pure (.error (ofFilepackError pe))
        | .ok manBytes =>
          match buildPayload manBytes bundle.bytes with
          | .error ae => pure (.error (ofAdamantineError ae))
          | .ok payload =>
            let flags : UInt8 := if opts.requireOts then adamantineFlagRequireOts else 0
            let adamBody := encodeAdamantine payload catalogFmt flags
            -- Catalog nonce: public uses zeros; encrypted needs one more nonce.
            let catNonce : ByteArray :=
              if opts.catalogEncrypted then
                if nonceIdx < nonces.size then nonces[nonceIdx]!
                else ByteArray.empty
              else
                replicate nonceLen 0
            if opts.catalogEncrypted &&
                (nonceIdx ≥ nonces.size || catNonce.size != nonceLen) then
              pure (.error .insufficientNonces)
            else
              let catFmtBits := FormatBits.ofUInt8 catalogFmt
              match encodeHeadered master catNonce adamBody catFmtBits 0
                  (replicate slhPublicKeyLen 0) (replicate 8 0) with
              | .error pe => pure (.error (ofPipelineError pe))
              | .ok (hdr, catalogBytes) =>
                -- Rebind catalog root into manifest is not on wire; filename binds root.
                let root := hdr.hash
                match catalogFilename root catalogFmt with
                | .error e => pure (.error e)
                | .ok cname =>
                  pure (.ok {
                    catalogFilename := cname
                    catalogBytes := catalogBytes
                    catalogBaoRoot := root
                    catalogFormat := catalogFmt
                    segments := segments
                    entryCount := entries.size
                  })

/-- Content integrity: BLAKE3 of recovered plaintext vs entry slot (exact error). -/
def checkContentBlake3 (recovered expectedHash : ByteArray) : Except DirectoryError Unit :=
  if expectedHash.size != hashLen then
    .error .invalidHashLength
  else if !ctEq (Carbonado.Bao.Blake3.hash recovered) expectedHash then
    .error .contentBlake3Mismatch
  else
    .ok ()

/-- Look up segment main by root hex + format among artifacts. -/
def findSegment (segments : Array SegmentArtifact) (root : ByteArray) (fmt : UInt8) :
    Option SegmentArtifact :=
  Id.run do
    let mut found : Option SegmentArtifact := none
    for i in [:segments.size] do
      let s := segments[i]!
      if ctEq s.baoRoot root && s.segmentFormat == fmt then
        found := some s
    pure found

/--
  Pure directory decode from in-memory archive.

  Returns recovered files sorted by rel_path. Checks content BLAKE3.
-/
def decodeDirectory (master : ByteArray) (archive : DirectoryArchive) :
    Except DirectoryError (Array DirFile) :=
  match parseCatalogName archive.catalogFilename with
  | .error e => .error e
  | .ok (expectedRoot, catalogFmt) =>
    if catalogFmt != archive.catalogFormat then
      .error .invalidCatalogPath
    else if !ctEq expectedRoot archive.catalogBaoRoot then
      .error .catalogBaoRootMismatch
    else
      match checkMasterPolicy master (catalogFmt &&& 1 != 0) with
      | .error e => .error e
      | .ok () =>
        -- Headered decode of catalog
        match decodeHeaderedWithHeader master archive.catalogBytes with
        | .error pe => .error (ofPipelineError pe)
        | .ok (hdr, adamBody) =>
          if !ctEq hdr.hash expectedRoot then
            .error .catalogBaoRootMismatch
          else
            match decodeAdamantine adamBody with
            | .error ae => .error (ofAdamantineError ae)
            | .ok (payload, adamHdr) =>
              if adamHdr.carbonadoFmt != catalogFmt then
                .error (.invalidAdamantineCarbonadoFormat adamHdr.carbonadoFmt)
              else if adamHdr.flags &&& adamantineFlagRequireOts != 0 then
                -- OTS not implemented in Lean product path.
                .error .otsFeatureRequired
              else
                match splitPayload payload with
                | .error ae => .error (ofAdamantineError ae)
                | .ok (manBytes, baoBundle) =>
                  match FilepackManifest.fromWireBytes manBytes expectedRoot with
                  | .error pe => .error (ofFilepackError pe)
                  | .ok manifest =>
                    if manifest.formatLevel != catalogFmt then
                      .error (.invalidFormatLevel manifest.formatLevel)
                    else
                      Id.run do
                        let mut out : Array DirFile := #[]
                        let mut err : Option DirectoryError := none
                        for ei in [:manifest.entries.size] do
                          if err.isNone then
                            let entry := manifest.entries[ei]!
                            let mut recovered := ByteArray.empty
                            for si in [:entry.segments.size] do
                              if err.isNone then
                                let sref := entry.segments[si]!
                                match findSegment archive.segments sref.segmentBaoRoot
                                    entry.segmentFormat with
                                | none => err := some .missingSegment
                                | some art =>
                                  if art.main.size != UInt64.toNat sref.mainLen then
                                    err := some .segmentMainLenMismatch
                                  else
                                    match validateSegmentBundleSemantics entry.segmentFormat sref with
                                    | .error e => err := some e
                                    | .ok () =>
                                      match bundleSlice baoBundle
                                          (UInt32.toNat sref.verificationOutboardOffset)
                                          (UInt32.toNat sref.verificationOutboardLen) with
                                      | .error ae => err := some (ofAdamantineError ae)
                                      | .ok verOb =>
                                        let fmtBits := FormatBits.ofUInt8 entry.segmentFormat
                                        let fecParRes : Except DirectoryError ByteArray :=
                                          if fmtBits.fec then
                                            match bundleSlice baoBundle
                                                (UInt32.toNat sref.fecParityOffset)
                                                (UInt32.toNat sref.fecParityLen) with
                                            | .error ae => .error (ofAdamantineError ae)
                                            | .ok p => .ok p
                                          else
                                            .ok ByteArray.empty
                                        match fecParRes with
                                        | .error e => err := some e
                                        | .ok fecPar =>
                                          let pad := paddingForMainLen art.main.size fmtBits.fec
                                          match decodeOutboardBody master sref.segmentBaoRoot
                                              art.main verOb fecPar pad fmtBits with
                                          | .error pe => err := some (ofPipelineError pe)
                                          | .ok part =>
                                            recovered := appendBA recovered part
                            if err.isNone then
                              match checkContentBlake3 recovered entry.contentBlake3 with
                              | .error e => err := some e
                              | .ok () =>
                                out := out.push { relPath := entry.relPath, content := recovered }
                        match err with
                        | some e => pure (.error e)
                        | none => pure (.ok out)

/-- Round-trip pure directory archive. -/
def roundtripDirectory (master : ByteArray) (files : Array DirFile)
    (opts : DirectoryEncodeOptions) (nonces : Array ByteArray) :
    Except DirectoryError Bool :=
  match encodeDirectory master files opts nonces with
  | .error e => .error e
  | .ok arch =>
    match decodeDirectory master arch with
    | .error e => .error e
    | .ok got =>
      if got.size != files.size then
        .ok false
      else
        -- Compare as multisets by path+content (both sorted by encode).
        Id.run do
          let mut ok := true
          for i in [:got.size] do
            let g := got[i]!
            -- find matching original
            let mut found := false
            for j in [:files.size] do
              let f := files[j]!
              if f.relPath == g.relPath && ctEq f.content g.content then
                found := true
            if !found then ok := false
          pure (.ok ok)

/-- Map Filepack path errors are distinct (theorems use ofFilepackError). -/
theorem ofFilepack_traversal :
    ofFilepackError .relPathTraversal = DirectoryError.pathTraversal := by
  rfl

theorem ofFilepack_absolute :
    ofFilepackError .relPathAbsolute = DirectoryError.pathAbsolute := by
  rfl

theorem ofFilepack_backslash :
    ofFilepackError .relPathBackslash = DirectoryError.pathBackslash := by
  rfl

theorem ofFilepack_null :
    ofFilepackError .relPathNullByte = DirectoryError.pathNullByte := by
  rfl

theorem ofFilepack_empty_component :
    ofFilepackError .relPathEmptyComponent = DirectoryError.pathEmptyComponent := by
  rfl

theorem ofFilepack_too_many_segments :
    ofFilepackError .tooManySegments = DirectoryError.tooManySegments := by
  rfl

theorem ofFilepack_ots_too_large :
    ofFilepackError .otsProofTooLarge = DirectoryError.otsProofTooLarge := by
  rfl

theorem ofAdamantine_flags :
    ofAdamantineError (.invalidFlags 2) = DirectoryError.invalidAdamantineFlags 2 := by
  rfl

theorem ofAdamantine_magic :
    ofAdamantineError .invalidMagic = DirectoryError.invalidAdamantineMagic := by
  rfl

theorem expected_fec_parity_empty : expectedFecParityLen 0 = 0 := by native_decide

theorem expected_fec_parity_one : expectedFecParityLen 1 = 16384 := by native_decide

end Carbonado.Directory
