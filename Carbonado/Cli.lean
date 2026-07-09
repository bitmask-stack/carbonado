/-
  AOT product CLI (Program G).

  Subcommands:
  * `demo` / (no args) — full self-test suite (Programs A–G)
  * `version` / `help`
  * `encode <path>` — single-file (headered) or directory → archive
  * `decode <path>` — headered file or `.adam.c14`/`.adam.c15` catalog
  * `slh parse|verify` — SLH1 wire helpers

  Directory default outdir: `{input}-archive/` (never `.`).
  `--encrypted` for c15; `--master <64 hex>`; `--format <0-15>` single-file.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Header
import Carbonado.Pipeline
import Carbonado.Outboard
import Carbonado.Adamantine
import Carbonado.Filepack
import Carbonado.Directory
import Carbonado.Slh
import Carbonado.Bao.Blake3

namespace Carbonado.Cli

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Header
open Carbonado.Pipeline
open Carbonado.Outboard
open Carbonado.Adamantine
open Carbonado.Filepack
open Carbonado.Directory
open Carbonado.Slh
open Carbonado.Bao.Blake3

/-- CLI error taxonomy (exact; maps lower errors when needed). -/
inductive CliError where
  | usage (msg : String)
  | io (msg : String)
  | badMasterHex
  | zeroMasterEncrypted
  | invalidFormat
  | directory (e : DirectoryError)
  | pipeline (e : PipelineError)
  | slh (e : SlhError)
  | notFound (path : String)
  deriving Repr

def versionString : String := "lean-program-g-0"

def helpText : String :=
  "carbonado — apocalypse-resistant archival format (Lean 4 AOT)\n" ++
  "\n" ++
  "Usage:\n" ++
  "  carbonado                     Run built-in self-test demo\n" ++
  "  carbonado demo                Same as no-args demo\n" ++
  "  carbonado version             Print version\n" ++
  "  carbonado help                Show this help\n" ++
  "  carbonado encode <path> [opts]\n" ++
  "      Single file → headered {bao_root_hex}.c{fmt:02x}; directory → Adamantine archive\n" ++
  "      --format <0-15>   single-file format (default 0 public raw)\n" ++
  "      --encrypted       directory catalog c15 (requires --master)\n" ++
  "      --master <hex64>  32-byte master key as 64 hex chars\n" ++
  "      -o <path>         output file or directory (default for dir: {input}-archive/)\n" ++
  "  carbonado decode <path> [opts]\n" ++
  "      Headered archive or {root}.adam.c14/.adam.c15 catalog\n" ++
  "      --master <hex64>  master key (required for encrypted)\n" ++
  "      -o <path>         output file or directory\n" ++
  "  carbonado slh parse <file>    Validate SLH1 sidecar wire (7860 B)\n" ++
  "  carbonado slh verify <sidecar> --root <hex64> --pk <hex64>\n" ++
  "      Cryptographic bind-to-root (fails closed exit 1 until SLH-DSA FFI — LIMITS)\n"

/-- Parse 64 hex chars → 32 bytes. -/
def parseMaster (s : String) : Except CliError ByteArray :=
  match fromHex? s with
  | none => .error .badMasterHex
  | some b =>
    if b.size != 32 then .error .badMasterHex
    else .ok b

/-- All-zero master. -/
def zeroMaster : ByteArray := replicate 32 0

/-- Reject all-zero master on encrypted paths. -/
def rejectZeroEncrypted (master : ByteArray) (encrypted : Bool) : Except CliError Unit :=
  if !encrypted then .ok ()
  else
    let allZero :=
      Id.run do
        let mut z := true
        for i in [:master.size] do
          if master.get! i != 0 then z := false
        pure z
    if allZero then .error .zeroMasterEncrypted else .ok ()

/-- Read OS CSPRNG bytes (Linux/macOS `/dev/urandom`). -/
partial def readUrandom (n : Nat) : IO ByteArray := do
  if n == 0 then
    pure ByteArray.empty
  else
    let h ← IO.FS.Handle.mk "/dev/urandom" .read
    let mut acc := ByteArray.empty
    let mut left := n
    while left > 0 do
      let chunk ← h.read (USize.ofNat (min left 4096))
      if chunk.size == 0 then
        throw (IO.userError "urandom: unexpected EOF")
      acc := acc.append chunk
      left := left - chunk.size
    pure acc

/-- CLI options bag. -/
structure CliOpts where
  format : Option Nat := none
  encrypted : Bool := false
  master : Option ByteArray := none
  output : Option String := none
  rootHex : Option String := none
  pkHex : Option String := none
  deriving Inhabited

/-- Sequential parse allowing interleaved flags and positionals. -/
def parseArgsSimple (args : List String) : Except CliError (CliOpts × List String) :=
  Id.run do
    let mut opts : CliOpts := {}
    let mut pos : List String := []
    let mut rest := args
    let mut err : Option CliError := none
    while !rest.isEmpty && err.isNone do
      match rest with
      | [] => pure ()
      | "--encrypted" :: r =>
        opts := { opts with encrypted := true }
        rest := r
      | "--format" :: v :: r =>
        match v.toNat? with
        | none => err := some (.usage s!"bad --format: {v}")
        | some n =>
          if n > 15 then err := some .invalidFormat
          else
            opts := { opts with format := some n }
            rest := r
      | "--master" :: v :: r =>
        match parseMaster v with
        | .error e => err := some e
        | .ok m =>
          opts := { opts with master := some m }
          rest := r
      | "-o" :: v :: r =>
        opts := { opts with output := some v }
        rest := r
      | "--root" :: v :: r =>
        opts := { opts with rootHex := some v }
        rest := r
      | "--pk" :: v :: r =>
        opts := { opts with pkHex := some v }
        rest := r
      | flag :: r =>
        if flag.startsWith "-" then
          err := some (.usage s!"unknown flag: {flag}")
        else
          pos := pos ++ [flag]
          rest := r
    match err with
    | some e => pure (.error e)
    | none => pure (.ok (opts, pos))

/-- Default master from opts (zero if omitted). -/
def masterOrZero (opts : CliOpts) : ByteArray :=
  match opts.master with
  | some m => m
  | none => zeroMaster

/-- Two-digit lowercase hex for format byte (AGENTS single-file: `.c{fmt:02x}`). -/
def formatHex2 (fmt : Nat) : String :=
  toHex (ofList [UInt8.ofNat (fmt % 256)])

/-- Default single-file output: `{bao_root_hex}.c{fmt:02x}` (AGENTS §7.1). -/
def defaultFileOut (baoRoot : ByteArray) (fmt : Nat) : System.FilePath :=
  System.FilePath.mk s!"{toHex baoRoot}.c{formatHex2 fmt}"

/-- True if path is a symlink (`test -L`; fail-closed encode/decode policy). -/
def pathIsSymlink (path : System.FilePath) : IO Bool := do
  let r ← IO.Process.output {
    cmd := "test"
    args := #["-L", path.toString]
  }
  pure (r.exitCode == 0)

/-- Encode single file; when `outputPath` is none, write `{hash}.c{fmt:02x}`. -/
def encodeFile (inputPath : System.FilePath) (outputPath : Option System.FilePath)
    (master : ByteArray) (format : FormatBits) : IO (Except CliError Unit) := do
  try
    let data ← IO.FS.readBinFile inputPath
    let enc := format.encrypted
    match rejectZeroEncrypted master enc with
    | .error e => pure (.error e)
    | .ok () =>
      let nonce ← if enc then readUrandom 16 else pure (replicate 16 0)
      match encodeHeadered master nonce data format 0
          (replicate slhPublicKeyLen 0) (replicate 8 0) with
      | .error e => pure (.error (.pipeline e))
      | .ok (hdr, archive) =>
        let out :=
          match outputPath with
          | some p => p
          | none => defaultFileOut hdr.hash format.toUInt8.toNat
        IO.FS.writeBinFile out archive
        IO.println s!"encoded {inputPath} → {out} (format=0x{formatHex2 format.toUInt8.toNat}, root={toHex hdr.hash})"
        pure (.ok ())
  catch e =>
    pure (.error (.io (toString e)))

/-- Single-file decode (headered). -/
def decodeFile (inputPath outputPath : System.FilePath) (master : ByteArray) :
    IO (Except CliError Unit) := do
  try
    let data ← IO.FS.readBinFile inputPath
    match decodeHeadered master data with
    | .error e => pure (.error (.pipeline e))
    | .ok pt =>
      IO.FS.writeBinFile outputPath pt
      IO.println s!"decoded {inputPath} → {outputPath} ({pt.size} bytes)"
      pure (.ok ())
  catch e =>
    pure (.error (.io (toString e)))

/-- Recursively collect files under `dir` with relative paths (POSIX). Fail-closed. -/
partial def collectFiles (base : System.FilePath) (rel : String) :
    IO (Except DirectoryError (Array DirFile)) := do
  let entries ← base.readDir
  let mut files : Array DirFile := #[]
  for ent in entries do
    let name := ent.fileName
    if name == "." || name == ".." then
      pure ()
    else if name.any (fun c => c == '/' || c == '\\') then
      return .error .pathBackslash
    else if name.any (fun c => c == Char.ofNat 0) then
      return .error .pathNullByte
    else
      let path := ent.path
      if ← pathIsSymlink path then
        return .error .symlinkNotAllowed
      let childRel := if rel.isEmpty then name else s!"{rel}/{name}"
      let isDir ← path.isDir
      if isDir then
        match ← collectFiles path childRel with
        | .error e => return .error e
        | .ok sub => files := files ++ sub
      else
        match validateRelPath childRel with
        | .error e => return .error (ofFilepackError e)
        | .ok () =>
          let data ← IO.FS.readBinFile path
          files := files.push { relPath := childRel, content := data }
  pure (.ok files)

/-- Count encrypted segments for nonce preallocation. -/
def countEncryptedSegments (files : Array DirFile) (opts : DirectoryEncodeOptions) : Nat :=
  Id.run do
    let mut n := 0
    for i in [:files.size] do
      let f := files[i]!
      match opts.segmentPolicy.resolve opts.catalogEncrypted f.content with
      | .error _ => pure ()
      | .ok fmt =>
        let bits := FormatBits.ofUInt8 fmt
        if bits.encrypted then
          let chunks := splitContent f.content opts.segmentPlaintextBudget
          n := n + chunks.size
    if opts.catalogEncrypted then n := n + 1
    pure n

/-- Encode directory to outdir. -/
def encodeDir (inputDir outputDir : System.FilePath) (master : ByteArray)
    (encrypted : Bool) : IO (Except CliError Unit) := do
  try
    let isDir ← inputDir.isDir
    if !isDir then
      pure (.error (.directory .notADirectory))
    else
      match checkMasterPolicy master encrypted with
      | .error e => pure (.error (.directory e))
      | .ok () =>
        match ← collectFiles inputDir "" with
        | .error e => pure (.error (.directory e))
        | .ok files =>
          let opts : DirectoryEncodeOptions := {
            catalogEncrypted := encrypted
            segmentPolicy := .auto
          }
          let need := countEncryptedSegments files opts
          let mut nonces : Array ByteArray := #[]
          for _ in [:need] do
            let n ← readUrandom 16
            nonces := nonces.push n
          match encodeDirectory master files opts nonces with
          | .error e => pure (.error (.directory e))
          | .ok arch =>
            IO.FS.createDirAll outputDir
            IO.FS.writeBinFile (outputDir / arch.catalogFilename) arch.catalogBytes
            for i in [:arch.segments.size] do
              let s := arch.segments[i]!
              IO.FS.writeBinFile (outputDir / s.filename) s.main
            IO.println s!"encoded directory {inputDir} → {outputDir}/"
            IO.println s!"  catalog {arch.catalogFilename} ({arch.entryCount} entries, {arch.segments.size} segments)"
            pure (.ok ())
  catch e =>
    pure (.error (.io (toString e)))

/-- Decode directory catalog into outdir (reads segment mains from catalog parent). -/
def decodeDir (catalogPath outputDir : System.FilePath) (master : ByteArray) :
    IO (Except CliError Unit) := do
  try
    let name := catalogPath.fileName.getD ""
    match parseCatalogName name with
    | .error e => pure (.error (.directory e))
    | .ok (expectedRoot, catalogFmt) =>
      match checkMasterPolicy master (catalogFmt &&& 1 != 0) with
      | .error e => pure (.error (.directory e))
      | .ok () =>
        let catalogBytes ← IO.FS.readBinFile catalogPath
        let parent := catalogPath.parent.getD (System.FilePath.mk ".")
        match decodeHeaderedWithHeader master catalogBytes with
        | .error e => pure (.error (.pipeline e))
        | .ok (hdr, adamBody) =>
          if !ctEq hdr.hash expectedRoot then
            pure (.error (.directory .catalogBaoRootMismatch))
          else
            match decodeAdamantine adamBody with
            | .error ae => pure (.error (.directory (ofAdamantineError ae)))
            | .ok (payload, adamHdr) =>
              -- Same format consistency as pure `decodeDirectory`.
              if adamHdr.carbonadoFmt != catalogFmt then
                pure (.error (.directory (.invalidAdamantineCarbonadoFormat adamHdr.carbonadoFmt)))
              else if adamHdr.flags &&& adamantineFlagRequireOts != 0 then
                pure (.error (.directory .otsFeatureRequired))
              else
                match splitPayload payload with
                | .error ae => pure (.error (.directory (ofAdamantineError ae)))
                | .ok (manBytes, baoBundle) =>
                  match FilepackManifest.fromWireBytes manBytes expectedRoot with
                  | .error pe => pure (.error (.directory (ofFilepackError pe)))
                  | .ok manifest =>
                    if manifest.formatLevel != catalogFmt then
                      pure (.error (.directory (.invalidFormatLevel manifest.formatLevel)))
                    else
                      IO.FS.createDirAll outputDir
                      for ei in [:manifest.entries.size] do
                        let entry := manifest.entries[ei]!
                        let mut recovered := ByteArray.empty
                        for si in [:entry.segments.size] do
                          let sref := entry.segments[si]!
                          match validateSegmentBundleSemantics entry.segmentFormat sref with
                          | .error e => return .error (.directory e)
                          | .ok () => pure ()
                          match segmentFilename sref.segmentBaoRoot entry.segmentFormat with
                          | .error e => return .error (.directory e)
                          | .ok sname =>
                            let spath := parent / sname
                            if ← pathIsSymlink spath then
                              return .error (.directory .symlinkNotAllowed)
                            let main ← IO.FS.readBinFile spath
                            if main.size != UInt64.toNat sref.mainLen then
                              return .error (.directory .segmentMainLenMismatch)
                            match bundleSlice baoBundle
                                (UInt32.toNat sref.verificationOutboardOffset)
                                (UInt32.toNat sref.verificationOutboardLen) with
                            | .error ae => return .error (.directory (ofAdamantineError ae))
                            | .ok verOb =>
                              let fmtBits := FormatBits.ofUInt8 entry.segmentFormat
                              let fecPar ←
                                if fmtBits.fec then
                                  match bundleSlice baoBundle
                                      (UInt32.toNat sref.fecParityOffset)
                                      (UInt32.toNat sref.fecParityLen) with
                                  | .error ae => return .error (.directory (ofAdamantineError ae))
                                  | .ok p => pure p
                                else pure ByteArray.empty
                              let pad := paddingForMainLen main.size fmtBits.fec
                              match decodeOutboardBody master sref.segmentBaoRoot main verOb
                                  fecPar pad fmtBits with
                              | .error pe => return .error (.pipeline pe)
                              | .ok part => recovered := appendBA recovered part
                        match checkContentBlake3 recovered entry.contentBlake3 with
                        | .error e => return .error (.directory e)
                        | .ok () => pure ()
                        match validateRelPath entry.relPath with
                        | .error pe => return .error (.directory (ofFilepackError pe))
                        | .ok () =>
                          let outPath := outputDir / entry.relPath
                          if ← pathIsSymlink outPath then
                            return .error (.directory .symlinkNotAllowed)
                          if let some p := outPath.parent then
                            IO.FS.createDirAll p
                          IO.FS.writeBinFile outPath recovered
                      IO.println s!"decoded catalog {name} → {outputDir}/ ({manifest.entries.size} files)"
                      pure (.ok ())
  catch e =>
    pure (.error (.io (toString e)))

/-- Detect if path is directory catalog by name. -/
def isAdamCatalogName (name : String) : Bool :=
  name.endsWith ".adam.c14" || name.endsWith ".adam.c15"

/-- Default output for encode directory: `{input}-archive`. -/
def defaultArchiveDir (input : System.FilePath) : System.FilePath :=
  System.FilePath.mk s!"{input}-archive"

/-- Format CLI error for stderr. -/
def formatCliError : CliError → String
  | .usage m => s!"usage: {m}"
  | .io m => s!"io: {m}"
  | .badMasterHex => "invalid --master (need 64 hex chars)"
  | .zeroMasterEncrypted => "zero master key not allowed for encrypted formats"
  | .invalidFormat => "invalid --format (0-15)"
  | .directory e => s!"directory: {repr e}"
  | .pipeline e => s!"pipeline: {repr e}"
  | .slh e => s!"slh: {repr e}"
  | .notFound p => s!"not found: {p}"

/-- Dispatch encode/decode/slh (not demo). -/
def runCommand (cmd : String) (args : List String) : IO UInt32 := do
  match parseArgsSimple args with
  | .error e =>
    IO.eprintln (formatCliError e)
    pure 2
  | .ok (opts, pos) =>
    match cmd with
    | "version" =>
      IO.println versionString
      pure 0
    | "help" | "--help" | "-h" =>
      IO.println helpText
      pure 0
    | "encode" =>
      match pos with
      | [input] =>
        let master := masterOrZero opts
        let inPath := System.FilePath.mk input
        let isDir ← inPath.isDir
        if isDir then
          let out :=
            match opts.output with
            | some o => System.FilePath.mk o
            | none => defaultArchiveDir inPath
          match ← encodeDir inPath out master opts.encrypted with
          | .error e => IO.eprintln (formatCliError e); pure 1
          | .ok () => pure 0
        else
          let fmtN := opts.format.getD 0
          if fmtN > 15 then
            IO.eprintln (formatCliError .invalidFormat); pure 2
          else
            let format :=
              let base := FormatBits.ofUInt8 (UInt8.ofNat fmtN)
              if opts.encrypted && !base.encrypted then
                FormatBits.ofUInt8 (UInt8.ofNat (fmtN ||| 1))
              else base
            let outOpt := opts.output.map System.FilePath.mk
            match ← encodeFile inPath outOpt master format with
            | .error e => IO.eprintln (formatCliError e); pure 1
            | .ok () => pure 0
      | _ =>
        IO.eprintln (formatCliError (.usage "encode <path> [-o out] [--format N] [--encrypted] [--master HEX]"))
        pure 2
    | "decode" =>
      match pos with
      | [input] =>
        let master := masterOrZero opts
        let inPath := System.FilePath.mk input
        let name := inPath.fileName.getD input
        if isAdamCatalogName name then
          let out :=
            match opts.output with
            | some o => System.FilePath.mk o
            | none => System.FilePath.mk s!"{input}-decoded"
          match ← decodeDir inPath out master with
          | .error e => IO.eprintln (formatCliError e); pure 1
          | .ok () => pure 0
        else
          let out :=
            match opts.output with
            | some o => System.FilePath.mk o
            | none => System.FilePath.mk s!"{input}.out"
          match ← decodeFile inPath out master with
          | .error e => IO.eprintln (formatCliError e); pure 1
          | .ok () => pure 0
      | _ =>
        IO.eprintln (formatCliError (.usage "decode <path> [-o out] [--master HEX]"))
        pure 2
    | "slh" =>
      match pos with
      | "parse" :: [file] =>
        try
          let bytes ← IO.FS.readBinFile file
          match parseSidecar bytes with
          | .error e => IO.eprintln (formatCliError (.slh e)); pure 1
          | .ok sig =>
            IO.println s!"SLH1 sidecar ok (signature {sig.size} bytes)"
            pure 0
        catch e =>
          IO.eprintln (formatCliError (.io (toString e))); pure 1
      | "verify" :: [file] =>
        match opts.rootHex, opts.pkHex with
        | some rh, some ph =>
          match fromHex? rh, fromHex? ph with
          | some root, some pk =>
            try
              let bytes ← IO.FS.readBinFile file
              match parseSidecar bytes with
              | .error e => IO.eprintln (formatCliError (.slh e)); pure 1
              | .ok sig =>
                -- Fail-closed: never exit 0 without real SLH-DSA verify.
                -- Until FFI is linked, always-false oracle → verificationFailed → exit 1.
                match verifyBound (fun _ _ _ => false) pk root sig with
                | .error .verificationFailed
                | .error .signatureUnavailable =>
                  IO.eprintln "slh verify: cryptographic verification unavailable (LIMITS: no SLH-DSA FFI)"
                  IO.eprintln s!"  wire parse ok (sigLen={sig.size}); NOT verified — exit 1"
                  pure 1
                | .error e => IO.eprintln (formatCliError (.slh e)); pure 1
                | .ok () =>
                  -- Only reachable once real oracle is linked and accepts.
                  IO.println s!"slh verify ok root={toHex root}"
                  pure 0
            catch e =>
              IO.eprintln (formatCliError (.io (toString e))); pure 1
          | _, _ => IO.eprintln "slh verify: bad --root/--pk hex"; pure 2
        | _, _ =>
          IO.eprintln (formatCliError (.usage "slh verify <file> --root HEX --pk HEX"))
          pure 2
      | _ =>
        IO.eprintln (formatCliError (.usage "slh parse <file> | slh verify <file> --root HEX --pk HEX"))
        pure 2
    | other =>
      IO.eprintln (formatCliError (.usage s!"unknown command: {other}"))
      pure 2

end Carbonado.Cli
