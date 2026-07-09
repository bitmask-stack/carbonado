/-
  Program F — zstd compress API + status mapping tests.

  Dependency direction: CarbonadoTest → Carbonado only.
-/
import Carbonado.Constants
import Carbonado.Crypto.Util
import Carbonado.Compress
import Carbonado.Pipeline
import CarbonadoTest.Scaffold

namespace CarbonadoTest.Compress

open Carbonado.Constants
open Carbonado.Crypto.Util
open Carbonado.Compress
open Carbonado.Pipeline

theorem magic_len : zstdMagic.length = 4 := zstdMagic_length

theorem ofStatus_1 : ofStatus 1 = .compressionFailed := ofStatus_compress
theorem ofStatus_2 : ofStatus 2 = .decompressionFailed := ofStatus_decompress
theorem ofStatus_3 : ofStatus 3 = .outputTooLarge := ofStatus_too_large
theorem ofStatus_4 : ofStatus 4 = .invalidInput := ofStatus_invalid_4
theorem ofStatus_unknown : ofStatus 99 = .invalidInput := ofStatus_invalid_99

theorem empty_raw :
    (match decodeStatusPayload ByteArray.empty with
     | .error .invalidInput => true
     | _ => false) = true := decode_empty_raw

theorem status_1 :
    (match decodeStatusPayload (ofList [1]) with
     | .error .compressionFailed => true
     | _ => false) = true := decode_status_1

theorem status_2 :
    (match decodeStatusPayload (ofList [2]) with
     | .error .decompressionFailed => true
     | _ => false) = true := decode_status_2

theorem status_3 :
    (match decodeStatusPayload (ofList [3]) with
     | .error .outputTooLarge => true
     | _ => false) = true := decode_status_3

theorem status_4 :
    (match decodeStatusPayload (ofList [4]) with
     | .error .invalidInput => true
     | _ => false) = true := decode_status_4

theorem status_ok :
    (match decodeStatusPayload (ofList [0, 0x68, 0x69]) with
     | .ok b => ctEq b (ofList [0x68, 0x69])
     | .error _ => false) = true := decode_status_ok_hello

theorem framing_identity :
    (match decodeStatusPayload (statusOkPayload (ofList [1, 2, 3])) with
     | .ok b => ctEq b (ofList [1, 2, 3])
     | .error _ => false) = true := statusOk_payload_identity

/-- Pipeline ofZstdError maps are injective per mode. -/
theorem map_zstd_compress :
    ofZstdError ZstdError.compressionFailed = PipelineError.compressionFailed := rfl

theorem map_zstd_decompress :
    ofZstdError ZstdError.decompressionFailed = PipelineError.decompressionFailed := rfl

theorem map_zstd_too_large :
    ofZstdError ZstdError.outputTooLarge = PipelineError.decompressOutputTooLarge := rfl

theorem map_zstd_invalid :
    ofZstdError ZstdError.invalidInput = PipelineError.zstdInvalidInput := rfl

theorem pipeline_map_decompress :
    ofZstdError (ofStatus 2) = PipelineError.decompressionFailed := rfl

theorem pipeline_map_too_large :
    ofZstdError (ofStatus 3) = PipelineError.decompressOutputTooLarge := rfl

/-- compressStep with bit clear is identity (no zstd). -/
theorem compress_bit_clear :
    (match compressStep (ofList [9, 8, 7]) false with
     | .ok (b, n) => ctEq b (ofList [9, 8, 7]) && n == 0
     | .error _ => false) = true := by
  native_decide

/-- decompressStep bit clear is identity. -/
theorem decompress_bit_clear :
    (match decompressStep (ofList [9, 8, 7]) false with
     | .ok b => ctEq b (ofList [9, 8, 7])
     | .error _ => false) = true := by
  native_decide

/-- Level constant is 20. -/
theorem level_20 : zstdLevel = 20 := by native_decide

end CarbonadoTest.Compress
