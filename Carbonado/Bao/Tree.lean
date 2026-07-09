/-
  Keyed Bao tree (bao-tree 76-keyed-bao semantics) for Carbonado product paths.

  Geometry: BLAKE3 chunk = 1024 B; Carbonado leaf group = 4 chunks = 4096 B
  (`BlockSize::from_chunk_log(2)` / `sliceLen`).

  Tree recursion is over **leaf groups** (4 KiB), matching `BaoTree` + `keyed_encode_ranges_*`
  with `BAO_BLOCK_SIZE`. Leaf hashes use BLAKE3 keyed subtree hashing over the group bytes.

  Slice verification authenticates untrusted response bytes against `(key, root, contentLen)`
  via `decodeRec` (bao-tree `keyed_decode_ranges` analogue) — not re-encode oracles.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Bao.Blake3

namespace Carbonado.Bao.Tree

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Bao.Blake3

/-- Strict Bao / verification errors (distinct failure modes). -/
inductive BaoError where
  /-- Expected root / leaf / parent hash did not match under the given key. -/
  | authenticationFailed
  /-- Response stream ended before required parent pair or leaf bytes. -/
  | truncatedResponse
  /-- Response longer than geometry consumed (trailing garbage after a valid decode). -/
  | trailingData
  /-- Inboard prefix missing or shorter than 8 bytes. -/
  | invalidPrefix
  /-- Root hash argument not 32 bytes. -/
  | invalidRootLength
  /-- Slice index past end of content. -/
  | invalidSliceIndex
  /-- `count = 0` on verify/decode-slice APIs (empty success would skip auth). -/
  | invalidSliceCount
  deriving DecidableEq, Repr

/-- Carbonado Bao chunk-group log: 2 → 4 KiB leaves. -/
def blockChunkLog : Nat := baoChunkLog

/-- Bytes per leaf group (= `sliceLen` = 4096). -/
def leafBytes : Nat := chunkLen * (2 ^ blockChunkLog)

theorem leafBytes_eq_sliceLen : leafBytes = sliceLen := by native_decide

/-- Blake3 chunks covered by one Carbonado slice / leaf group. -/
def chunksPerSlice : Nat := 2 ^ blockChunkLog

/-- Smallest power of two ≥ `n` (n ≥ 1). -/
def nextPow2 (n : Nat) : Nat :=
  if n ≤ 1 then 1
  else 2 ^ (Nat.log2 (n - 1) + 1)

/-- Query over leaf-group indices (not BLAKE3 chunks). -/
inductive LeafQuery where
  | all
  | range (start end_ : Nat)
  deriving DecidableEq, Repr

def LeafQuery.isEmpty : LeafQuery → Bool
  | .all => false
  | .range s e => decide (e ≤ s)

def LeafQuery.isAll : LeafQuery → Bool
  | .all => true
  | .range _ _ => false

def LeafQuery.split (q : LeafQuery) (startLeaf midLeaf : Nat) : LeafQuery × LeafQuery :=
  match q with
  | .all => (.all, .all)
  | .range s e =>
      let leftS := max s startLeaf
      let leftE := min e midLeaf
      let rightS := max s midLeaf
      let rightE := e
      let left : LeafQuery :=
        if leftE ≤ leftS then .range 0 0 else .range leftS leftE
      let right : LeafQuery :=
        if rightE ≤ rightS then .range 0 0 else .range rightS rightE
      (left, right)

/-- Number of leaf groups covering `dataLen` bytes. -/
def leafGroupCount (dataLen : Nat) : Nat :=
  if dataLen == 0 then 0
  else (dataLen + leafBytes - 1) / leafBytes

/-- Hash one leaf group (up to 4 KiB) at blake3 start chunk `startChunk`. -/
def hashLeafGroup (startChunk : Nat) (group : ByteArray) (isRoot : Bool)
    (key : ByteArray) : ByteArray :=
  keyedHashSubtree startChunk group isRoot key

/-- Recursive keyed encode over 4 KiB leaf groups.

  Returns `(hash, emitted_bytes)`. Parent pairs are pre-order (before children),
  matching bao-tree full-range / range responses at `BlockSize` log=2.
-/
partial def encodeRec (startLeaf : Nat) (data : ByteArray) (isRoot : Bool)
    (query : LeafQuery) (emitData : Bool) (key : ByteArray) : ByteArray × ByteArray :=
  let nLeaves := leafGroupCount data.size
  if nLeaves ≤ 1 then
    let startChunk := startLeaf * chunksPerSlice
    let h := hashLeafGroup startChunk data isRoot key
    let emitted :=
      if emitData && !query.isEmpty then data else ByteArray.empty
    (h, emitted)
  else
    let groups := nextPow2 nLeaves
    let mid := groups / 2
    let midBytes := mid * leafBytes
    let midLeaf := startLeaf + mid
    let (lQ, rQ) := query.split startLeaf midLeaf
    let leftData := data.extract 0 (min midBytes data.size)
    let rightData := data.extract (min midBytes data.size) data.size
    let (leftH, leftEm) := encodeRec startLeaf leftData false lQ emitData key
    let (rightH, rightEm) := encodeRec midLeaf rightData false rQ emitData key
    let parentH := keyedParentCV leftH rightH isRoot key
    let emitParent := !query.isEmpty
    let emitted :=
      if emitParent then
        appendBA (appendBA leftH rightH) (appendBA leftEm rightEm)
      else
        appendBA leftEm rightEm
    (parentH, emitted)

/-- Keyed Bao root over full data (≡ `blake3::keyed_hash` / `create_keyed` root). -/
def keyedRoot (key data : ByteArray) : ByteArray :=
  keyedHash key data

/-- Full-range inboard response bytes (no length prefix). -/
def encodeResponseAll (key data : ByteArray) : ByteArray × ByteArray :=
  encodeRec 0 data true .all true key

/-- Post-order outboard sidecar (parent pairs only). -/
partial def outboardRec (startLeaf : Nat) (data : ByteArray) (isRoot : Bool)
    (key : ByteArray) : ByteArray × ByteArray :=
  let nLeaves := leafGroupCount data.size
  if nLeaves ≤ 1 then
    let startChunk := startLeaf * chunksPerSlice
    (hashLeafGroup startChunk data isRoot key, ByteArray.empty)
  else
    let groups := nextPow2 nLeaves
    let mid := groups / 2
    let midBytes := mid * leafBytes
    let midLeaf := startLeaf + mid
    let leftData := data.extract 0 (min midBytes data.size)
    let rightData := data.extract (min midBytes data.size) data.size
    let (leftH, leftOb) := outboardRec startLeaf leftData false key
    let (rightH, rightOb) := outboardRec midLeaf rightData false key
    let parentH := keyedParentCV leftH rightH isRoot key
    let pair := appendBA leftH rightH
    (parentH, appendBA (appendBA leftOb rightOb) pair)

/-- Post-order outboard for full data under `key`. -/
def createOutboard (key data : ByteArray) : ByteArray × ByteArray :=
  outboardRec 0 data true key

/-- Inboard artifact: `[u64le content_len | response]`. -/
def encodeInboard (key data : ByteArray) : ByteArray × ByteArray :=
  let (root, resp) := encodeResponseAll key data
  let lenPrefix := putUInt64LE (UInt64.ofNat data.size)
  (root, appendBA lenPrefix resp)

/-- Parse inboard content-length prefix. -/
def contentLenPrefix (input : ByteArray) : Except BaoError Nat :=
  if input.size < 8 then
    .error .invalidPrefix
  else
    .ok (UInt64.toNat (getUInt64LE input 0))

/-- Decode full-range / partial response over leaf groups.

  Authenticates included leaves and parent pairs against `expected` (root or CV).
  Sibling hashes for unqueried sides are still read from the stream and bound into
  the parent CV (bao-tree range decode semantics).
-/
partial def decodeRec (startLeaf : Nat) (contentLen : Nat) (isRoot : Bool)
    (query : LeafQuery) (key : ByteArray) (expected : ByteArray)
    (input : ByteArray) (pos : Nat) : Except BaoError (ByteArray × Nat) := do
  if query.isEmpty then
    -- Empty sub-query: no bytes consumed; caller already authenticated via parent pair.
    pure (ByteArray.empty, pos)
  else
    let nLeaves := leafGroupCount contentLen
    if nLeaves ≤ 1 then
      if pos + contentLen > input.size then
        throw .truncatedResponse
      let data := input.extract pos (pos + contentLen)
      let startChunk := startLeaf * chunksPerSlice
      let h := hashLeafGroup startChunk data isRoot key
      if !ctEq h expected then
        throw .authenticationFailed
      pure (data, pos + contentLen)
    else
      let groups := nextPow2 nLeaves
      let mid := groups / 2
      let midBytes := mid * leafBytes
      let midLeaf := startLeaf + mid
      let leftLen := min midBytes contentLen
      let rightLen := contentLen - leftLen
      let (lQ, rQ) := query.split startLeaf midLeaf
      if pos + 64 > input.size then
        throw .truncatedResponse
      let leftH := input.extract pos (pos + 32)
      let rightH := input.extract (pos + 32) (pos + 64)
      let parentH := keyedParentCV leftH rightH isRoot key
      if !ctEq parentH expected then
        throw .authenticationFailed
      let pos := pos + 64
      let (leftData, pos) ←
        decodeRec startLeaf leftLen false lQ key leftH input pos
      let (rightData, pos) ←
        decodeRec midLeaf rightLen false rQ key rightH input pos
      pure (appendBA leftData rightData, pos)

/-- Verify and decode full inboard `[u64le|response]` under `key` and expected root. -/
def decodeInboard (key root input : ByteArray) : Except BaoError ByteArray := do
  if root.size != outLen then
    throw .invalidRootLength
  let contentLen ← contentLenPrefix input
  let response := input.extract 8 input.size
  if contentLen == 0 then
    let expect := keyedRoot key ByteArray.empty
    if !ctEq expect root then
      throw .authenticationFailed
    if response.size != 0 then
      throw .trailingData
    pure ByteArray.empty
  else
    let (data, endPos) ←
      decodeRec 0 contentLen true .all key root response 0
    if endPos < response.size then
      throw .trailingData
    if endPos > response.size then
      throw .truncatedResponse
    if data.size != contentLen then
      throw .authenticationFailed
    if !ctEq (keyedRoot key data) root then
      throw .authenticationFailed
    pure data

/-- Verify inboard without retaining body. -/
def verifyInboard (key root input : ByteArray) : Except BaoError Unit := do
  let _ ← decodeInboard key root input
  pure ()

/-- Verify bare main + post-order outboard against root. -/
def verifyOutboard (key root bare outboard : ByteArray) : Except BaoError Unit := do
  if root.size != outLen then
    throw .invalidRootLength
  let (gotRoot, gotOb) := createOutboard key bare
  if !ctEq gotRoot root then
    throw .authenticationFailed
  if !ctEq gotOb outboard then
    throw .authenticationFailed
  pure ()

/-- Slice index/count → leaf-group query. -/
def sliceLeafQuery (index count : Nat) : LeafQuery :=
  .range index (index + count)

/-- Encode keyed slice response for `count` slices starting at `index`. -/
def encodeSliceResponse (key data : ByteArray) (index count : Nat) :
    ByteArray × ByteArray :=
  encodeRec 0 data true (sliceLeafQuery index count) true key

/-- Authenticate and decode a standalone slice response (stream verify).

  Does **not** require full plaintext. Uses `decodeRec` against `(key, root, contentLen)`.
  Returns only the authenticated slice bytes recovered from `response`.

  * `count = 0` → `invalidSliceCount` (empty success would skip authentication)
  * short stream → `truncatedResponse`
  * trailing garbage after geometry → `trailingData`
  * hash mismatch / wrong key → `authenticationFailed`
-/
def decodeSliceResponse (key root : ByteArray) (contentLen index count : Nat)
    (response : ByteArray) : Except BaoError ByteArray := do
  if root.size != outLen then
    throw .invalidRootLength
  if count == 0 then
    throw .invalidSliceCount
  if contentLen == 0 then
    throw .invalidSliceIndex
  let sliceStart := index * leafBytes
  if sliceStart ≥ contentLen then
    throw .invalidSliceIndex
  let (data, endPos) ←
    decodeRec 0 contentLen true (sliceLeafQuery index count) key root response 0
  if endPos < response.size then
    throw .trailingData
  if endPos > response.size then
    throw .truncatedResponse
  pure data

/-- Test-oracle helper: re-encode slice and compare (not a product verify path).

  Prefer `decodeSliceResponse` for authentication of untrusted responses.
-/
def sliceResponseMatchesEncode (key data : ByteArray) (index count : Nat)
    (response : ByteArray) : Bool :=
  let (_root, enc) := encodeSliceResponse key data index count
  ctEq enc response

/-- Decode full inboard (always authenticates), then extract `count` slices at `index`.

  Integrity runs **before** the `count = 0` empty return — corrupt inboard never succeeds.
  `count = 0` after successful decode returns empty (extract semantics, not skip-auth).
-/
def extractSliceFromInboard (key root input : ByteArray) (index count : Nat) :
    Except BaoError ByteArray := do
  let data ← decodeInboard key root input
  if count == 0 then
    return ByteArray.empty
  let sliceStart := index * leafBytes
  if sliceStart ≥ data.size then
    throw .invalidSliceIndex
  let sliceEnd := min data.size (sliceStart + count * leafBytes)
  pure (data.extract sliceStart sliceEnd)

/-- Strict verify of slice inside full inboard: full decode then extract.

  Same auth-first contract as `extractSliceFromInboard`.
-/
def verifySliceInboard (key root input : ByteArray) (index count : Nat) :
    Except BaoError ByteArray :=
  extractSliceFromInboard key root input index count

/-- Root equals keyed_hash (determinism / multi-dimensional naming basis). -/
theorem root_eq_keyed_hash (key data : ByteArray) :
    keyedRoot key data = keyedHash key data := rfl

end Carbonado.Bao.Tree
