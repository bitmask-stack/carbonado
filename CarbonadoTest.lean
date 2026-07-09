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
import CarbonadoTest.Scaffold
import CarbonadoTest.EtM
import CarbonadoTest.Fec
import CarbonadoTest.Bao
import CarbonadoTest.Pipeline
import CarbonadoTest.Compress
import CarbonadoTest.Slh
import CarbonadoTest.Directory

/- Test root. Name is deliberately *not* `Tests/` — collides with Rust `tests/`
   on case-insensitive filesystems (macOS APFS). -/
