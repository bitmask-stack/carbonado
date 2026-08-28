/-
  Normative constants for the Carbonado v2 wire format and pipeline geometry.

  These match the Rust implementation (AGENTS.md / `src/constants.rs`) so Lean
  models and parity oracles share a single source of sizes and labels.
-/

namespace Carbonado.Constants

/-- v2 container magic: `CARBONADO20\n` (12 bytes). -/
def magicBytes : List UInt8 :=
  [0x43, 0x41, 0x52, 0x42, 0x4f, 0x4e, 0x41, 0x44, 0x4f, 0x32, 0x30, 0x0a]

theorem magicBytes_length : magicBytes.length = 12 := by native_decide

/-- Magic is exactly ASCII `CARBONADO20` + LF (no trailing NUL). -/
theorem magicBytes_eq_literal :
    magicBytes =
      [0x43, 0x41, 0x52, 0x42, 0x4f, 0x4e, 0x41, 0x44, 0x4f, 0x32, 0x30, 0x0a] := by
  rfl

/-- Header wire length (MAGIC + nonce + header_mac + hash + slh_pk + format + fields). -/
def headerLen : Nat := 177

/-- AES-CTR / payload nonce size. -/
def nonceLen : Nat := 16

/-- Full HMAC-SHA512 tag size (never truncated). -/
def hmacTagLen : Nat := 64

/-- Bao / BLAKE3 root size. -/
def hashLen : Nat := 32

/-- SLH-DSA public key slot in the header. -/
def slhPublicKeyLen : Nat := 32

/-- One Bao leaf / slice length (4 KiB). -/
def sliceLen : Nat := 4096

/-- Bao-tree `BlockSize::from_chunk_log` argument (2 → 4 × 1 KiB chunks = 4 KiB groups). -/
def baoChunkLog : Nat := 2

theorem sliceLen_eq_bao_group : sliceLen = 1024 * 2 ^ baoChunkLog := by native_decide

/-- RS data shards. -/
def fecK : Nat := 4

/-- RS total shards (data + parity). -/
def fecM : Nat := 8

/-- Stripe alignment: `sliceLen * fecK` = 16 KiB logical stripe unit for padding. -/
def stripeUnit : Nat := sliceLen * fecK

theorem stripeUnit_eq : stripeUnit = 16384 := by native_decide

theorem fecM_eq_twice_fecK : fecM = 2 * fecK := by native_decide

/-- SLH1 sidecar magic. -/
def slh1Magic : List UInt8 := [0x53, 0x4c, 0x48, 0x31] -- "SLH1"

theorem slh1Magic_length : slh1Magic.length = 4 := by native_decide

theorem slh1Magic_eq_literal :
    slh1Magic = [0x53, 0x4c, 0x48, 0x31] := by
  rfl

/-- SLH-DSA-SHA2-128s raw signature length. -/
def slh1SignatureLen : Nat := 7856

/-- Total SLH1 sidecar file length: magic + signature. -/
def slh1SidecarLen : Nat := 4 + slh1SignatureLen

theorem slh1SidecarLen_eq : slh1SidecarLen = 7860 := by native_decide

/-- Subkey domain prefix for HMAC-SHA512 derivation. -/
def subkeyDomainPrefix : String := "carbonado-v2/"

/-- Payload EtM MAC domain string. -/
def etmDomain : String := "carbonado-v2-etm"

/-- Keyed Bao KDF context (BLAKE3 derive_key). -/
def verificationContext : String := "carbonado-v2/verification"

/-!
  Full Subkey Label Registry (AGENTS.md). Wire strings match the Rust product.

  * Master-key derived: `aes-ctr`, `etm-hmac`, `header-auth`
  * Hybrid only: `ecc-chacha-poly` — PRF input is ECDH shared secret, **not** master
  * SLH convenience wrappers only: `slh-dsa-seed`, `slh-dsa-seed-2` (not container security)

  Program B implements master-derived EtM subkeys (`aes-ctr`, `etm-hmac`, `header-auth`).
  Hybrid/SLH seed labels remain registry-only until those programs.
-/
inductive SubkeyLabel where
  | aesCtr
  | etmHmac
  | headerAuth
  | eccChaChaPoly
  | slhDsaSeed
  | slhDsaSeed2
  deriving DecidableEq, Repr

def SubkeyLabel.toString : SubkeyLabel → String
  | .aesCtr => "aes-ctr"
  | .etmHmac => "etm-hmac"
  | .headerAuth => "header-auth"
  | .eccChaChaPoly => "ecc-chacha-poly"
  | .slhDsaSeed => "slh-dsa-seed"
  | .slhDsaSeed2 => "slh-dsa-seed-2"

/-- Labels derived from the archive master key (container security). -/
def SubkeyLabel.isMasterDerived : SubkeyLabel → Bool
  | .aesCtr | .etmHmac | .headerAuth => true
  | .eccChaChaPoly | .slhDsaSeed | .slhDsaSeed2 => false

/-- Format bitmask bit values (lowest bit = Encrypted → unencrypted formats are even). -/
def formatBitEncrypted : UInt8 := 1
def formatBitCompression : UInt8 := 2
def formatBitVerification : UInt8 := 4
def formatBitFec : UInt8 := 8

/-- Format bitmask bits (lowest bit = Encrypted, so unencrypted formats are even). -/
structure FormatBits where
  encrypted : Bool
  compression : Bool
  verification : Bool
  fec : Bool
  deriving DecidableEq, Repr

def FormatBits.toUInt8 (f : FormatBits) : UInt8 :=
  let e : UInt8 := if f.encrypted then formatBitEncrypted else 0
  let c : UInt8 := if f.compression then formatBitCompression else 0
  let v : UInt8 := if f.verification then formatBitVerification else 0
  let z : UInt8 := if f.fec then formatBitFec else 0
  e + c + v + z

def FormatBits.ofUInt8 (b : UInt8) : FormatBits :=
  { encrypted := b &&& formatBitEncrypted != 0
    compression := b &&& formatBitCompression != 0
    verification := b &&& formatBitVerification != 0
    fec := b &&& formatBitFec != 0 }

theorem formatBits_roundtrip (f : FormatBits) :
    FormatBits.ofUInt8 f.toUInt8 = f := by
  cases f with
  | mk e c v z =>
    cases e <;> cases c <;> cases v <;> cases z <;> native_decide

/-- Unencrypted formats have even numeric codes. -/
theorem unencrypted_format_even (f : FormatBits) (h : f.encrypted = false) :
    f.toUInt8 % 2 = 0 := by
  cases f with
  | mk e c v z =>
    simp [FormatBits.toUInt8, formatBitEncrypted, formatBitCompression,
      formatBitVerification, formatBitFec] at h ⊢
    subst h
    cases c <;> cases v <;> cases z <;> native_decide

/-- Public catalog format c14 = Compression | Verification | Fec = 14. -/
def formatC14 : FormatBits :=
  { encrypted := false, compression := true, verification := true, fec := true }

theorem formatC14_byte : formatC14.toUInt8 = 14 := by native_decide

/-- Encrypted catalog format c15 = Encrypted | Compression | Verification | Fec = 15. -/
def formatC15 : FormatBits :=
  { encrypted := true, compression := true, verification := true, fec := true }

theorem formatC15_byte : formatC15.toUInt8 = 15 := by native_decide

/-- All 16 format codes round-trip through `FormatBits`. -/
theorem format_codes_roundtrip :
    (List.range 16).all (fun n =>
      let b := UInt8.ofNat n
      (FormatBits.ofUInt8 b).toUInt8 = b) = true := by
  native_decide

/-- Header layout field sizes sum to `headerLen`. -/
theorem headerLen_sum :
    magicBytes.length + nonceLen + hmacTagLen + hashLen + slhPublicKeyLen
      + 1 + 4 + 4 + 4 + 8 = headerLen := by
  native_decide

end Carbonado.Constants
