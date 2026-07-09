/-
  Carbonado — apocalypse-resistant archival format.

  Product implementation and proofs: Lean 4.
  Build and packaging: Nix flakes.
-/
import Carbonado.Constants
import Carbonado.Crypto
import Carbonado.Fec
import Carbonado.Bao
import Carbonado.Header
import Carbonado.Compress
import Carbonado.Slh
import Carbonado.Pipeline
import Carbonado.Stream
import Carbonado.Scrub
import Carbonado.Shard
import Carbonado.Adamantine
import Carbonado.Filepack
import Carbonado.Outboard
import Carbonado.Directory
import Carbonado.Cli
import Carbonado.Ffi

/-- Library root namespace. -/
def Carbonado.versionString : String := "lean-dual-backend-0"
