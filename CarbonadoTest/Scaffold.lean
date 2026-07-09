/-
  Program A scaffold tests.

  Named `CarbonadoTest` (not `Tests/`) so it does not collide with legacy Rust
  `tests/` on case-insensitive filesystems (Darwin APFS default).

  Product theorems live next to definitions under `Carbonado/`.
  This module re-states critical wire invariants so the test tree is non-empty
  and ready for Programs B–G vector / parity modules.

  Dependency direction: CarbonadoTest → Carbonado only (never reverse).
-/
import Carbonado.Constants

namespace CarbonadoTest.Scaffold

open Carbonado.Constants

theorem magic_len : magicBytes.length = 12 := magicBytes_length
theorem header_177 : headerLen = 177 := rfl
theorem slice_4k : sliceLen = 4096 := rfl
theorem fec_4_of_8 : fecK = 4 ∧ fecM = 8 := ⟨rfl, rfl⟩
theorem stripe_16k : stripeUnit = 16384 := stripeUnit_eq
theorem slh_sidecar_7860 : slh1SidecarLen = 7860 := slh1SidecarLen_eq
theorem c14_public : formatC14.toUInt8 = 14 := formatC14_byte
theorem c15_encrypted : formatC15.toUInt8 = 15 := formatC15_byte

end CarbonadoTest.Scaffold
