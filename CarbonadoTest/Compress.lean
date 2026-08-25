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
theorem level_20 : zstdLevel = 20 := zstdLevel_eq_20

theorem magic_literal : zstdMagic = [0x28, 0xb5, 0x2f, 0xfd] := zstdMagic_eq_literal

theorem checksum_off : zstdContentChecksum = false := zstdContentChecksum_off

theorem no_dictionary : zstdDictionaryIdFlag = 0 := zstdDictionaryIdFlag_none

theorem buffer_content_size_on : zstdBufferContentSizeFlag = true := zstdBufferContentSizeFlag_on

theorem stream_content_size_off : zstdStreamContentSizeFlag = false := zstdStreamContentSizeFlag_off

theorem window_log_large : zstdLevel20WindowLogLarge = 25 := zstdLevel20WindowLogLarge_eq

theorem aot_small_fd : frameHeaderDescriptionByte 0 0 1 0 = 0x20 := aot_small_descriptor_byte

theorem stream_unknown_fd : frameHeaderDescriptionByte 0 0 0 0 = 0x00 := stream_unknown_descriptor_byte

theorem window_byte_25 : windowDescriptorByte 25 = 0x78 := level20_large_window_descriptor_byte

theorem window_0x78 : windowLogFromDescriptor 0x78 = 25 := window_0x78_log

theorem hello_frame :
    (match parseZstdFrameHeader (ofList helloLevel20Golden) with
     | .ok h => productBufferSmallFrameOk h 5
     | .error _ => false) = true := parse_hello_golden_header

theorem empty_frame :
    (match parseZstdFrameHeader (ofList emptyLevel20Golden) with
     | .ok h => productBufferSmallFrameOk h 0
     | .error _ => false) = true := parse_empty_golden_header

theorem g9_lean_c14_frame :
    (match parseZstdFrameHeader (ofList g9LeanC14Header) with
     | .ok h => productBufferSmallFrameOk h 26
     | .error _ => false) = true := parse_g9_lean_c14_header

theorem g9_rust_c14_frame :
    (match parseZstdFrameHeader (ofList g9RustC14Header) with
     | .ok h => productStreamUnknownSizeFrameOk h
     | .error _ => false) = true := parse_g9_rust_c14_header

theorem reserved_rejected :
    (match parseZstdFrameHeader (ofList [0x28, 0xb5, 0x2f, 0xfd, 0x08]) with
     | .error .reservedBitSet => true
     | _ => false) = true := parse_reserved_bit

theorem bad_magic :
    (match parseZstdFrameHeader (ofList [0x00, 0x01, 0x02, 0x03, 0x20]) with
     | .error .badMagic => true
     | _ => false) = true := parse_bad_magic

end CarbonadoTest.Compress
