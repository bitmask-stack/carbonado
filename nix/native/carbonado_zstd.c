/*
 * Carbonado zstd FFI (Program F).
 *
 * Wire format to Lean: ByteArray = [status_u8 | payload...]
 *   status 0 = success; payload is compressed/decompressed bytes
 *   status 1 = compression failed
 *   status 2 = decompression failed
 *   status 3 = decompressed output exceeds max
 *   status 4 = invalid input / size error
 *
 * Linked into the AOT product via flake staticLibDeps:
 *   libcarbonado_native.a = this FFI + static libzstd objects from ref/zstd.
 * No shared -lzstd. Lean elaborator uses the `@[extern]` body (identity fallback).
 */
#include <lean/lean.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

/* Match Rust MAX_SEGMENT_MAIN_LEN (filepack_manifest). */
#ifndef CARBONADO_ZSTD_MAX_DECOMPRESSED
#define CARBONADO_ZSTD_MAX_DECOMPRESSED ((size_t)256 * 1024 * 1024)
#endif

enum {
  ST_OK = 0,
  ST_COMPRESS_FAILED = 1,
  ST_DECOMPRESS_FAILED = 2,
  ST_OUTPUT_TOO_LARGE = 3,
  ST_INVALID_INPUT = 4
};

static lean_obj_res mk_status(uint8_t status, const uint8_t *payload, size_t payload_len) {
  size_t total = 1 + payload_len;
  lean_obj_res out = lean_alloc_sarray(1, total, total);
  uint8_t *p = lean_sarray_cptr(out);
  p[0] = status;
  if (payload_len > 0 && payload != NULL) {
    memcpy(p + 1, payload, payload_len);
  }
  return out;
}

static lean_obj_res mk_status_only(uint8_t status) {
  return mk_status(status, NULL, 0);
}

/*
 * carbonado_zstd_compress : @& ByteArray → UInt32 → ByteArray
 * Lean calling convention: borrowed ByteArray, UInt32 by value.
 */
LEAN_EXPORT lean_obj_res carbonado_zstd_compress(b_lean_obj_arg input, uint32_t level) {
  size_t in_size = lean_sarray_size(input);
  const void *in_data = lean_sarray_cptr(input);

  if (level > 22u) {
    return mk_status_only(ST_INVALID_INPUT);
  }

  size_t bound = ZSTD_compressBound(in_size);
  if (bound == 0 && in_size > 0) {
    return mk_status_only(ST_COMPRESS_FAILED);
  }

  /* Allocate payload buffer (status byte added later). */
  void *buf = malloc(bound == 0 ? 1 : bound);
  if (buf == NULL) {
    return mk_status_only(ST_COMPRESS_FAILED);
  }

  size_t n = ZSTD_compress(buf, bound == 0 ? 1 : bound, in_data, in_size, (int)level);
  if (ZSTD_isError(n)) {
    free(buf);
    return mk_status_only(ST_COMPRESS_FAILED);
  }

  lean_obj_res out = mk_status(ST_OK, (const uint8_t *)buf, n);
  free(buf);
  return out;
}

/*
 * carbonado_zstd_decompress : @& ByteArray → UInt64 → ByteArray
 * max_out caps decompressed size (DoS guard); 0 means use CARBONADO_ZSTD_MAX_DECOMPRESSED.
 */
LEAN_EXPORT lean_obj_res carbonado_zstd_decompress(b_lean_obj_arg input, uint64_t max_out) {
  size_t in_size = lean_sarray_size(input);
  const void *in_data = lean_sarray_cptr(input);

  size_t cap = max_out == 0 ? CARBONADO_ZSTD_MAX_DECOMPRESSED : (size_t)max_out;
  if (cap == 0) {
    return mk_status_only(ST_INVALID_INPUT);
  }

  unsigned long long frame_size = ZSTD_getFrameContentSize(in_data, in_size);
  if (frame_size == ZSTD_CONTENTSIZE_ERROR) {
    return mk_status_only(ST_DECOMPRESS_FAILED);
  }

  size_t out_cap;
  if (frame_size != ZSTD_CONTENTSIZE_UNKNOWN) {
    if (frame_size > cap) {
      return mk_status_only(ST_OUTPUT_TOO_LARGE);
    }
    out_cap = (size_t)frame_size;
    if (out_cap == 0) {
      /* Empty content still needs a successful decompress of the frame. */
      out_cap = 1;
    }
  } else {
    /* Unknown size: grow heuristically up to cap. */
    out_cap = in_size * 3 + 64;
    if (out_cap > cap) {
      out_cap = cap;
    }
    if (out_cap == 0) {
      out_cap = 1;
    }
  }

  void *buf = malloc(out_cap);
  if (buf == NULL) {
    return mk_status_only(ST_DECOMPRESS_FAILED);
  }

  size_t n = ZSTD_decompress(buf, out_cap, in_data, in_size);
  if (ZSTD_isError(n)) {
    /* Retry with larger buffer if content size was unknown and we under-allocated. */
    if (frame_size == ZSTD_CONTENTSIZE_UNKNOWN && out_cap < cap) {
      free(buf);
      out_cap = cap;
      buf = malloc(out_cap);
      if (buf == NULL) {
        return mk_status_only(ST_DECOMPRESS_FAILED);
      }
      n = ZSTD_decompress(buf, out_cap, in_data, in_size);
      if (ZSTD_isError(n)) {
        free(buf);
        /* Distinguish capacity vs corrupt when possible. */
        if (ZSTD_getErrorCode(n) == ZSTD_error_dstSize_tooSmall) {
          return mk_status_only(ST_OUTPUT_TOO_LARGE);
        }
        return mk_status_only(ST_DECOMPRESS_FAILED);
      }
    } else {
      free(buf);
      if (ZSTD_getErrorCode(n) == ZSTD_error_dstSize_tooSmall) {
        return mk_status_only(ST_OUTPUT_TOO_LARGE);
      }
      return mk_status_only(ST_DECOMPRESS_FAILED);
    }
  }

  lean_obj_res out = mk_status(ST_OK, (const uint8_t *)buf, n);
  free(buf);
  return out;
}
