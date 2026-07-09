/-
  Carbonado v2 Header wire codec (177 bytes).

  Normative layout (AGENTS.md / Rust `file::Header`):
    MAGIC(12) + payload_nonce(16) + header_mac(64) + hash(32) + slh_public_key(32)
    + format(1) + chunk_index(u32 LE) + encoded_len(u32 LE) + padding_len(u32 LE)
    + metadata(8) = 177

  Header is **never encrypted**. Integrity via `header_mac` under `header-auth` subkey.
  Verification must happen before trusting any metadata (header-MAC-before-body).
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Crypto.EtM

namespace Carbonado.Header

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Crypto.EtM

/-- Header parse / build errors (distinct; not folded into payload EtM failures). -/
inductive HeaderError where
  /-- Input shorter than `headerLen` (177). -/
  | invalidHeaderLength
  /-- Magic prefix is not `CARBONADO20\n`. -/
  | badMagic
  /-- `header_mac` did not verify under the master key. -/
  | headerAuthenticationFailed
  /-- Master key shorter than 32 bytes when computing/verifying MAC. -/
  | invalidKeyLength
  /-- Hash / slh / nonce field wrong size when constructing. -/
  | invalidFieldLength
  deriving DecidableEq, Repr

/-- Parsed / constructed v2 Header (public metadata only). -/
structure Header where
  payloadNonce : ByteArray
  headerMac : ByteArray
  hash : ByteArray
  slhPublicKey : ByteArray
  format : UInt8
  chunkIndex : UInt32
  encodedLen : UInt32
  paddingLen : UInt32
  /-- Always 8 bytes on the wire; all-zero when absent. -/
  metadata : ByteArray
  deriving DecidableEq, Inhabited

/-- Build `auth_data` for header MAC (113 bytes; no separate domain string). -/
def buildAuthData
    (payloadNonce hash slhPublicKey : ByteArray)
    (format : UInt8)
    (chunkIndex encodedLen paddingLen : UInt32)
    (metadata : ByteArray) : Except HeaderError ByteArray :=
  if payloadNonce.size != nonceLen then
    .error .invalidFieldLength
  else if hash.size != hashLen then
    .error .invalidFieldLength
  else if slhPublicKey.size != slhPublicKeyLen then
    .error .invalidFieldLength
  else if metadata.size != 8 then
    .error .invalidFieldLength
  else
    Id.run do
      let mut out := ByteArray.empty
      for b in magicBytes do
        out := out.push b
      out := appendBA out payloadNonce
      out := appendBA out hash
      out := appendBA out slhPublicKey
      out := out.push format
      out := appendBA out (putUInt32LE chunkIndex)
      out := appendBA out (putUInt32LE encodedLen)
      out := appendBA out (putUInt32LE paddingLen)
      out := appendBA out metadata
      pure (.ok out)

/-- auth_data length is fixed at 113 (= headerLen − header_mac). -/
theorem authData_len_formula :
    magicBytes.length + nonceLen + hashLen + slhPublicKeyLen + 1 + 4 + 4 + 4 + 8 = 113 := by
  native_decide

/-- Construct Header, computing `header_mac` under `master`. -/
def Header.new
    (master payloadNonce hash slhPublicKey : ByteArray)
    (format : UInt8)
    (chunkIndex encodedLen paddingLen : UInt32)
    (metadata : ByteArray) : Except HeaderError Header :=
  match buildAuthData payloadNonce hash slhPublicKey format chunkIndex encodedLen paddingLen
      metadata with
  | .error e => .error e
  | .ok auth =>
    -- Exhaustive CryptoError match (no catch-all → invalidKeyLength).
    match computeHeaderMac master auth with
    | .error .invalidKeyLength => .error .invalidKeyLength
    | .error .invalidCiphertextLength => .error .invalidKeyLength
    | .error .invalidNonceLength => .error .invalidKeyLength
    | .error .authenticationFailed => .error .invalidKeyLength
    | .ok mac =>
      .ok {
        payloadNonce := payloadNonce
        headerMac := mac
        hash := hash
        slhPublicKey := slhPublicKey
        format := format
        chunkIndex := chunkIndex
        encodedLen := encodedLen
        paddingLen := paddingLen
        metadata := metadata
      }

/-- Serialize Header to exactly 177 wire bytes. -/
def Header.toBytes (h : Header) : Except HeaderError ByteArray :=
  if h.payloadNonce.size != nonceLen then .error .invalidFieldLength
  else if h.headerMac.size != hmacTagLen then .error .invalidFieldLength
  else if h.hash.size != hashLen then .error .invalidFieldLength
  else if h.slhPublicKey.size != slhPublicKeyLen then .error .invalidFieldLength
  else if h.metadata.size != 8 then .error .invalidFieldLength
  else
    Id.run do
      let mut out := ByteArray.empty
      for b in magicBytes do
        out := out.push b
      out := appendBA out h.payloadNonce
      out := appendBA out h.headerMac
      out := appendBA out h.hash
      out := appendBA out h.slhPublicKey
      out := out.push h.format
      out := appendBA out (putUInt32LE h.chunkIndex)
      out := appendBA out (putUInt32LE h.encodedLen)
      out := appendBA out (putUInt32LE h.paddingLen)
      out := appendBA out h.metadata
      pure (.ok out)

/-- Parse Header from wire bytes (no MAC verify — call `verify` next). -/
def parse (bytes : ByteArray) : Except HeaderError Header :=
  if bytes.size < headerLen then
    .error .invalidHeaderLength
  else
    Id.run do
      let mut magicOk := true
      for i in [:magicBytes.length] do
        if bytes.get! i != magicBytes[i]! then
          magicOk := false
      if !magicOk then
        pure (.error .badMagic)
      else
        let payloadNonce := bytes.extract 12 28
        let headerMac := bytes.extract 28 92
        let hash := bytes.extract 92 124
        let slhPublicKey := bytes.extract 124 156
        let format := bytes.get! 156
        let chunkIndex := getUInt32LE bytes 157
        let encodedLen := getUInt32LE bytes 161
        let paddingLen := getUInt32LE bytes 165
        let metadata := bytes.extract 169 177
        pure (.ok {
          payloadNonce := payloadNonce
          headerMac := headerMac
          hash := hash
          slhPublicKey := slhPublicKey
          format := format
          chunkIndex := chunkIndex
          encodedLen := encodedLen
          paddingLen := paddingLen
          metadata := metadata
        })

/-- Verify `header_mac` under master; does not return plaintext body. -/
def verify (master : ByteArray) (h : Header) : Except HeaderError Unit :=
  match buildAuthData h.payloadNonce h.hash h.slhPublicKey h.format
      h.chunkIndex h.encodedLen h.paddingLen h.metadata with
  | .error e => .error e
  | .ok auth =>
    -- Exhaustive CryptoError match (computeHeaderMac only yields invalidKeyLength today).
    match verifyHeaderMac master auth h.headerMac with
    | .error .invalidKeyLength => .error .invalidKeyLength
    | .error .invalidCiphertextLength => .error .invalidKeyLength
    | .error .invalidNonceLength => .error .invalidKeyLength
    | .error .authenticationFailed => .error .invalidKeyLength
    | .ok true => .ok ()
    | .ok false => .error .headerAuthenticationFailed

/-- Parse + verify in one step (header MAC before trusting metadata). -/
def parseAndVerify (master bytes : ByteArray) : Except HeaderError Header :=
  match parse bytes with
  | .error e => .error e
  | .ok h =>
    match verify master h with
    | .error e => .error e
    | .ok () => .ok h

/-- Wire length of a successful `toBytes` is `headerLen`. -/
theorem headerLen_eq_177 : headerLen = 177 := by native_decide

end Carbonado.Header
