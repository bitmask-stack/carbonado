/-
  BLAKE3 (reference algorithm) — pure Lean.

  Parity target: `ref/blake3` 1.8.5 (portable / reference semantics).
  Used for keyed Bao: `hash`, `keyed_hash`, `derive_key`, hazmat subtree/parent CVs.
-/
import Carbonado.Crypto.Util

namespace Carbonado.Bao.Blake3

open Carbonado.Crypto.Util

def outLen : Nat := 32
def keyLen : Nat := 32
def blockLen : Nat := 64
def chunkLen : Nat := 1024

private def CHUNK_START : UInt32 := (1 : UInt32) <<< 0
private def CHUNK_END : UInt32 := (1 : UInt32) <<< 1
private def PARENT : UInt32 := (1 : UInt32) <<< 2
private def ROOT : UInt32 := (1 : UInt32) <<< 3
private def KEYED_HASH : UInt32 := (1 : UInt32) <<< 4
private def DERIVE_KEY_CONTEXT : UInt32 := (1 : UInt32) <<< 5
private def DERIVE_KEY_MATERIAL : UInt32 := (1 : UInt32) <<< 6

private def IV : Array UInt32 := #[
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
]

private def MSG_PERM : Array Nat := #[
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
]

/-- 8-word chaining value. -/
abbrev CV := Array UInt32

private def rotr32 (x : UInt32) (n : Nat) : UInt32 :=
  let n32 : UInt32 := UInt32.ofNat n
  let m32 : UInt32 := UInt32.ofNat (32 - n)
  (x >>> n32) ||| (x <<< m32)

private def g (state : Array UInt32) (a b c d : Nat) (mx my : UInt32) : Array UInt32 :=
  Id.run do
    let mut s := state
    s := s.set! a (s[a]! + s[b]! + mx)
    s := s.set! d (rotr32 (s[d]! ^^^ s[a]!) 16)
    s := s.set! c (s[c]! + s[d]!)
    s := s.set! b (rotr32 (s[b]! ^^^ s[c]!) 12)
    s := s.set! a (s[a]! + s[b]! + my)
    s := s.set! d (rotr32 (s[d]! ^^^ s[a]!) 8)
    s := s.set! c (s[c]! + s[d]!)
    s := s.set! b (rotr32 (s[b]! ^^^ s[c]!) 7)
    pure s

private def round (state : Array UInt32) (m : Array UInt32) : Array UInt32 :=
  Id.run do
    let mut s := state
    s := g s 0 4 8 12 m[0]! m[1]!
    s := g s 1 5 9 13 m[2]! m[3]!
    s := g s 2 6 10 14 m[4]! m[5]!
    s := g s 3 7 11 15 m[6]! m[7]!
    s := g s 0 5 10 15 m[8]! m[9]!
    s := g s 1 6 11 12 m[10]! m[11]!
    s := g s 2 7 8 13 m[12]! m[13]!
    s := g s 3 4 9 14 m[14]! m[15]!
    pure s

private def permute (m : Array UInt32) : Array UInt32 :=
  Id.run do
    let mut out : Array UInt32 := Array.replicate 16 0
    for i in [:16] do
      out := out.set! i m[MSG_PERM[i]!]!
    pure out

private def getUInt32LE (bs : ByteArray) (off : Nat) : UInt32 :=
  let b0 := (bs.get! off).toUInt32
  let b1 := (bs.get! (off + 1)).toUInt32
  let b2 := (bs.get! (off + 2)).toUInt32
  let b3 := (bs.get! (off + 3)).toUInt32
  b0 ||| (b1 <<< 8) ||| (b2 <<< 16) ||| (b3 <<< 24)

private def putUInt32LE (x : UInt32) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    out := out.push (UInt8.ofNat (UInt32.toNat x % 256))
    out := out.push (UInt8.ofNat (UInt32.toNat (x >>> 8) % 256))
    out := out.push (UInt8.ofNat (UInt32.toNat (x >>> 16) % 256))
    out := out.push (UInt8.ofNat (UInt32.toNat (x >>> 24) % 256))
    pure out

private def wordsFromLE (bs : ByteArray) (nWords : Nat) : Array UInt32 :=
  Id.run do
    let mut w : Array UInt32 := Array.replicate nWords 0
    for i in [:nWords] do
      w := w.set! i (getUInt32LE bs (i * 4))
    pure w

private def compress (cv : CV) (blockWords : Array UInt32) (counter : UInt64)
    (blockLen' : UInt32) (flags : UInt32) : Array UInt32 :=
  Id.run do
    let counterLow : UInt32 := UInt32.ofNat (UInt64.toNat (counter &&& 0xffffffff))
    let counterHigh : UInt32 := UInt32.ofNat (UInt64.toNat (counter >>> 32))
    let mut state : Array UInt32 := #[
      cv[0]!, cv[1]!, cv[2]!, cv[3]!,
      cv[4]!, cv[5]!, cv[6]!, cv[7]!,
      IV[0]!, IV[1]!, IV[2]!, IV[3]!,
      counterLow, counterHigh, blockLen', flags
    ]
    let mut block := blockWords
    for _ in [:7] do
      state := round state block
      block := permute block
    for i in [:8] do
      state := state.set! i (state[i]! ^^^ state[i + 8]!)
      state := state.set! (i + 8) (state[i + 8]! ^^^ cv[i]!)
    pure state

private def first8 (full : Array UInt32) : CV :=
  #[full[0]!, full[1]!, full[2]!, full[3]!, full[4]!, full[5]!, full[6]!, full[7]!]

/-- Output just prior to choosing CV vs root bytes. -/
private structure Output where
  inputCV : CV
  blockWords : Array UInt32
  counter : UInt64
  blockLen' : UInt32
  flags : UInt32
  deriving Repr

private def Output.chainingValue (o : Output) : CV :=
  first8 (compress o.inputCV o.blockWords o.counter o.blockLen' o.flags)

private def Output.rootOutputBytes (o : Output) (outLen' : Nat) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    let mut blockCounter : UInt64 := 0
    while out.size < outLen' do
      let words := compress o.inputCV o.blockWords blockCounter o.blockLen' (o.flags ||| ROOT)
      for wi in [:16] do
        if out.size ≥ outLen' then break
        let wordBytes := putUInt32LE words[wi]!
        for bi in [:4] do
          if out.size < outLen' then
            out := out.push (wordBytes.get! bi)
      blockCounter := blockCounter + 1
    pure out

private structure ChunkState where
  chainingValue : CV
  chunkCounter : UInt64
  block : ByteArray
  blockLen' : Nat
  blocksCompressed : Nat
  flags : UInt32

private def ChunkState.new (keyWords : CV) (chunkCounter : UInt64) (flags : UInt32) : ChunkState :=
  { chainingValue := keyWords
    chunkCounter := chunkCounter
    block := replicate blockLen 0
    blockLen' := 0
    blocksCompressed := 0
    flags := flags }

private def ChunkState.len (cs : ChunkState) : Nat :=
  blockLen * cs.blocksCompressed + cs.blockLen'

private def ChunkState.startFlag (cs : ChunkState) : UInt32 :=
  if cs.blocksCompressed == 0 then CHUNK_START else 0

private def ChunkState.update (cs : ChunkState) (input : ByteArray) : ChunkState :=
  Id.run do
    let mut cs := cs
    let mut off : Nat := 0
    while off < input.size do
      if cs.blockLen' == blockLen then
        let blockWords := wordsFromLE cs.block 16
        cs := { cs with
          chainingValue := first8 (compress cs.chainingValue blockWords cs.chunkCounter
            (UInt32.ofNat blockLen) (cs.flags ||| cs.startFlag))
          blocksCompressed := cs.blocksCompressed + 1
          block := replicate blockLen 0
          blockLen' := 0 }
      let want := blockLen - cs.blockLen'
      let take := min want (input.size - off)
      for i in [:take] do
        cs := { cs with block := cs.block.set! (cs.blockLen' + i) (input.get! (off + i)) }
      cs := { cs with blockLen' := cs.blockLen' + take }
      off := off + take
    pure cs

private def ChunkState.output (cs : ChunkState) : Output :=
  let blockWords := wordsFromLE cs.block 16
  { inputCV := cs.chainingValue
    blockWords := blockWords
    counter := cs.chunkCounter
    blockLen' := UInt32.ofNat cs.blockLen'
    flags := cs.flags ||| cs.startFlag ||| CHUNK_END }

private def parentOutput (left right keyWords : CV) (flags : UInt32) : Output :=
  Id.run do
    let mut blockWords : Array UInt32 := Array.replicate 16 0
    for i in [:8] do
      blockWords := blockWords.set! i left[i]!
      blockWords := blockWords.set! (i + 8) right[i]!
    pure {
      inputCV := keyWords
      blockWords := blockWords
      counter := 0
      blockLen' := UInt32.ofNat blockLen
      flags := PARENT ||| flags
    }

private def parentCV (left right keyWords : CV) (flags : UInt32) : CV :=
  (parentOutput left right keyWords flags).chainingValue

/-- Incremental hasher (reference §5.1). -/
structure Hasher where
  chunkState : ChunkState
  keyWords : CV
  cvStack : Array CV
  cvStackLen : Nat
  flags : UInt32

private def Hasher.newInternal (keyWords : CV) (flags : UInt32) : Hasher :=
  { chunkState := ChunkState.new keyWords 0 flags
    keyWords := keyWords
    cvStack := Array.replicate 54 (Array.replicate 8 (0 : UInt32))
    cvStackLen := 0
    flags := flags }

def Hasher.new : Hasher := Hasher.newInternal IV 0

def Hasher.newKeyed (key : ByteArray) : Hasher :=
  let keyWords := wordsFromLE (resize key keyLen) 8
  Hasher.newInternal keyWords KEYED_HASH

private def Hasher.pushStack (h : Hasher) (cv : CV) : Hasher :=
  { h with
    cvStack := h.cvStack.set! h.cvStackLen cv
    cvStackLen := h.cvStackLen + 1 }

private def Hasher.popStack (h : Hasher) : Hasher × CV :=
  let len := h.cvStackLen - 1
  ({ h with cvStackLen := len }, h.cvStack[len]!)

private def Hasher.addChunkCV (h : Hasher) (newCV : CV) (totalChunks : UInt64) : Hasher :=
  Id.run do
    let mut h := h
    let mut newCV := newCV
    let mut total := totalChunks
    while (total &&& 1) == 0 do
      let (h', left) := h.popStack
      h := h'
      newCV := parentCV left newCV h.keyWords h.flags
      total := total >>> 1
    pure (h.pushStack newCV)

/-- Bytes accepted so far by this hasher. -/
def Hasher.count (h : Hasher) : Nat :=
  (UInt64.toNat h.chunkState.chunkCounter) * chunkLen + h.chunkState.len

/-- Set input byte offset (must be multiple of 1024; hasher must be empty). -/
def Hasher.setInputOffset (h : Hasher) (offset : UInt64) : Hasher :=
  let counter := offset / UInt64.ofNat chunkLen
  { h with chunkState := ChunkState.new h.keyWords counter h.flags }

def Hasher.update (h : Hasher) (input : ByteArray) : Hasher :=
  Id.run do
    let mut h := h
    let mut off : Nat := 0
    while off < input.size do
      if h.chunkState.len == chunkLen then
        let chunkCV := h.chunkState.output.chainingValue
        let totalChunks := h.chunkState.chunkCounter + 1
        h := h.addChunkCV chunkCV totalChunks
        h := { h with chunkState := ChunkState.new h.keyWords totalChunks h.flags }
      let want := chunkLen - h.chunkState.len
      let take := min want (input.size - off)
      h := { h with chunkState := h.chunkState.update (input.extract off (off + take)) }
      off := off + take
    pure h

def Hasher.finalize (h : Hasher) : ByteArray :=
  Id.run do
    let mut output := h.chunkState.output
    let mut remaining := h.cvStackLen
    while remaining > 0 do
      remaining := remaining - 1
      output := parentOutput h.cvStack[remaining]! output.chainingValue h.keyWords h.flags
    pure (output.rootOutputBytes outLen)

/-- Non-root chaining value of the current subtree (hazmat; for Bao leaves). -/
def Hasher.finalizeNonRoot (h : Hasher) : CV :=
  Id.run do
    let mut output := h.chunkState.output
    let mut remaining := h.cvStackLen
    while remaining > 0 do
      remaining := remaining - 1
      output := parentOutput h.cvStack[remaining]! output.chainingValue h.keyWords h.flags
    pure output.chainingValue

def Hasher.newDeriveKey (context : String) : Hasher :=
  Id.run do
    let mut ctxH := Hasher.newInternal IV DERIVE_KEY_CONTEXT
    ctxH := ctxH.update (utf8 context)
    let contextKey := ctxH.finalize
    let contextKeyWords := wordsFromLE contextKey 8
    pure (Hasher.newInternal contextKeyWords DERIVE_KEY_MATERIAL)

/-- CV → 32 little-endian bytes (as blake3::Hash). -/
def cvToBytes (cv : CV) : ByteArray :=
  Id.run do
    let mut out := ByteArray.empty
    for i in [:8] do
      out := appendBA out (putUInt32LE cv[i]!)
    pure out

def bytesToCV (bs : ByteArray) : CV :=
  wordsFromLE (resize bs outLen) 8

/-- Standard BLAKE3 hash. -/
def hash (data : ByteArray) : ByteArray :=
  (Hasher.new.update data).finalize

/-- BLAKE3 keyed hash (32-byte key). -/
def keyedHash (key data : ByteArray) : ByteArray :=
  ((Hasher.newKeyed key).update data).finalize

/-- BLAKE3 `derive_key(context, key_material)` → 32 bytes. -/
def deriveKey (context : String) (keyMaterial : ByteArray) : ByteArray :=
  ((Hasher.newDeriveKey context).update keyMaterial).finalize

/-- Hash a Bao/BLAKE3 subtree (keyed mode).

  * `isRoot = true` → `keyed_hash(key, data)` (must be start_chunk 0).
  * else → non-root CV at `start_chunk * 1024` input offset.
-/
def keyedHashSubtree (startChunk : Nat) (data : ByteArray) (isRoot : Bool)
    (key : ByteArray) : ByteArray :=
  if isRoot then
    keyedHash key data
  else
    let h0 := Hasher.newKeyed key
    let h1 := h0.setInputOffset (UInt64.ofNat (startChunk * chunkLen))
    let h2 := h1.update data
    cvToBytes h2.finalizeNonRoot

/-- Merge two child CVs (keyed mode). -/
def keyedParentCV (left right : ByteArray) (isRoot : Bool) (key : ByteArray) : ByteArray :=
  let keyWords := wordsFromLE (resize key keyLen) 8
  let leftCV := bytesToCV left
  let rightCV := bytesToCV right
  let o := parentOutput leftCV rightCV keyWords KEYED_HASH
  if isRoot then
    o.rootOutputBytes outLen
  else
    cvToBytes o.chainingValue

/-- Empty-string hash golden (official). -/
theorem hash_empty :
    toHex (hash ByteArray.empty) =
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" := by
  native_decide

/-- Official `abc` hash golden. -/
theorem hash_abc :
    toHex (hash (utf8 "abc")) =
      "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85" := by
  native_decide

end Carbonado.Bao.Blake3
