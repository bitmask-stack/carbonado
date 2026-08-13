/**
 * C ABI surface for libcarbonado (docs/ABI.md, include/carbonado.h).
 *
 * Phase 1+2 + R3: strong symbols for encode/decode/headered/verification_key plus
 * outboard/scrub/slice that call Lean `@[export]` helpers (`l_carbonado_*`
 * from Carbonado/Ffi.lean). Lean runtime is initialized once on first use.
 *
 * Lean pack layouts are internal to libcarbonado (co-versioned with this C glue);
 * the public C API stays additive at ABI version 1 (nullable out-params).
 *
 * Packed Lean success layouts (errors are status-first: [u32 LE status] only):
 *   status payload:   [u32 LE status][bytes…]
 *   encode body:      [u32 LE status][pad:4][chunk:4][ecc:4][vsc:4]
 *                     [comp:4][enc:4][32 hash][body…]           (prefix 60)
 *   encode headered:  [u32 LE status][pad:4][chunk:4][ecc:4][vsc:4]
 *                     [comp:4][enc:4][archive…]                 (prefix 28)
 *   encode outboard:  [u32 LE status][pad:4][chunk:4][comp:4][enc:4]
 *                     [32 hash][u32 main_len][main][u32 ob_len][ob]
 *                     [u32 par_len][par]                        (fixed prefix 52)
 */
#include <lean/lean.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "carbonado.h"

/* Lean runtime (symbols in Lean Init / leanrt). */
extern void lean_initialize_runtime_module(void);
extern void lean_io_mark_end_initialization(void);
extern bool lean_io_result_is_ok(b_lean_obj_arg r);
extern void lean_io_result_show_error(b_lean_obj_arg r);

/* Module initializer generated for Carbonado.Ffi (chains Pipeline deps). */
extern lean_obj_res initialize_Carbonado_Ffi(uint8_t builtin);

/* @[export] helpers from Carbonado/Ffi.lean — callee owns arguments. */
extern lean_obj_res l_carbonado_verification_key(uint8_t format);
extern lean_obj_res l_carbonado_encode_headered(lean_obj_arg master, lean_obj_arg nonce,
                                                 lean_obj_arg plaintext, lean_obj_arg slh_pk,
                                                 lean_obj_arg metadata, uint8_t format);
extern lean_obj_res l_carbonado_decode_headered(lean_obj_arg master, lean_obj_arg archive);
extern lean_obj_res l_carbonado_encode(lean_obj_arg master, lean_obj_arg nonce,
                                       lean_obj_arg plaintext, uint8_t format);
extern lean_obj_res l_carbonado_decode(lean_obj_arg master, lean_obj_arg hash,
                                       lean_obj_arg body, uint32_t padding, uint8_t format);
extern lean_obj_res l_carbonado_encode_outboard(lean_obj_arg master, lean_obj_arg nonce,
                                                 lean_obj_arg plaintext, uint8_t format,
                                                 uint8_t header_path);
extern lean_obj_res l_carbonado_decode_outboard(lean_obj_arg master, lean_obj_arg hash,
                                                 lean_obj_arg main, lean_obj_arg ver_outboard,
                                                 lean_obj_arg fec_parity, uint32_t padding,
                                                 uint8_t format, uint8_t header_path,
                                                 lean_obj_arg nonce);
extern lean_obj_res l_carbonado_scrub(lean_obj_arg body, lean_obj_arg hash, uint32_t padding,
                                      uint8_t format);
extern lean_obj_res l_carbonado_scrub_outboard(lean_obj_arg main, lean_obj_arg ver_outboard,
                                               lean_obj_arg fec_parity, lean_obj_arg hash,
                                               uint32_t padding, uint32_t chunk_len,
                                               uint8_t format);
extern lean_obj_res l_carbonado_verify_slice(lean_obj_arg body, lean_obj_arg hash,
                                             uint32_t index, uint32_t count, uint8_t format);
extern lean_obj_res l_carbonado_verify_slice_outboard(lean_obj_arg main, lean_obj_arg outboard,
                                                       lean_obj_arg hash, uint32_t index,
                                                       uint32_t count, uint8_t format);

static pthread_once_t g_lean_once = PTHREAD_ONCE_INIT;
static int g_lean_init_rc = -1;

static void lean_init_once(void) {
  lean_initialize_runtime_module();
  lean_obj_res res = initialize_Carbonado_Ffi(1);
  if (!lean_io_result_is_ok(res)) {
    lean_io_result_show_error(res);
    lean_dec(res);
    g_lean_init_rc = -1;
    return;
  }
  lean_dec_ref(res);
  lean_io_mark_end_initialization();
  g_lean_init_rc = 0;
}

static int ensure_lean(void) {
  (void)pthread_once(&g_lean_once, lean_init_once);
  return g_lean_init_rc;
}

uint32_t carbonado_abi_version(void) {
  return CARBONADO_ABI_VERSION;
}

void carbonado_free(void *p) {
  free(p);
}

/* Build a Lean ByteArray; takes a copy of `data` (may be NULL when len==0). */
static lean_object *mk_byte_array(const uint8_t *data, size_t len) {
  lean_object *ba = lean_alloc_sarray(1, len, len);
  if (len > 0) {
    if (data == NULL) {
      lean_dec(ba);
      return NULL;
    }
    memcpy(lean_sarray_cptr(ba), data, len);
  }
  return ba;
}

static uint32_t read_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

/* Copy Lean ByteArray payload into malloc'd buffer. */
static int copy_sarray_payload(lean_object *ba, size_t offset, uint8_t **out, size_t *out_len) {
  size_t n = lean_sarray_size(ba);
  if (offset > n) {
    return CARBONADO_ERR_INTERNAL;
  }
  size_t len = n - offset;
  if (len == 0) {
    *out = NULL;
    *out_len = 0;
    return CARBONADO_OK;
  }
  uint8_t *buf = (uint8_t *)malloc(len);
  if (buf == NULL) {
    return CARBONADO_ERR_INTERNAL;
  }
  memcpy(buf, lean_sarray_cptr(ba) + offset, len);
  *out = buf;
  *out_len = len;
  return CARBONADO_OK;
}

/* Unpack `[status:4][payload…]` → malloc payload on OK. */
static int unpack_status_payload(lean_object *packed, uint8_t **out, size_t *out_len) {
  size_t n = lean_sarray_size(packed);
  if (n < 4) {
    lean_dec(packed);
    return CARBONADO_ERR_INTERNAL;
  }
  const uint8_t *p = lean_sarray_cptr(packed);
  uint32_t status = read_u32_le(p);
  if (status != CARBONADO_OK) {
    lean_dec(packed);
    return (int)status;
  }
  int rc = copy_sarray_payload(packed, 4, out, out_len);
  lean_dec(packed);
  return rc;
}

/* Read length-prefixed segment; advances *off. */
static int read_len_prefixed(const uint8_t *p, size_t n, size_t *off, uint8_t **out,
                             size_t *out_len) {
  if (*off + 4 > n) {
    return CARBONADO_ERR_INTERNAL;
  }
  uint32_t len = read_u32_le(p + *off);
  *off += 4;
  if (*off + len > n) {
    return CARBONADO_ERR_INTERNAL;
  }
  if (len == 0) {
    *out = NULL;
    *out_len = 0;
    return CARBONADO_OK;
  }
  uint8_t *buf = (uint8_t *)malloc(len);
  if (buf == NULL) {
    return CARBONADO_ERR_INTERNAL;
  }
  memcpy(buf, p + *off, len);
  *off += len;
  *out = buf;
  *out_len = len;
  return CARBONADO_OK;
}

int carbonado_verification_key(uint8_t format, uint8_t key_out[32]) {
  if (key_out == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }
  lean_obj_res ba = l_carbonado_verification_key(format);
  if (lean_sarray_size(ba) != 32) {
    lean_dec(ba);
    return CARBONADO_ERR_INTERNAL;
  }
  memcpy(key_out, lean_sarray_cptr(ba), 32);
  lean_dec(ba);
  return CARBONADO_OK;
}

int carbonado_encode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *slh_pk,
    const uint8_t *metadata,
    uint8_t **out, size_t *out_len,
    uint32_t *padding_out,
    uint32_t *chunk_len_out,
    uint32_t *bytes_ecc_out,
    uint32_t *verifiable_slice_count_out,
    uint32_t *bytes_compressed_out,
    uint32_t *bytes_encrypted_out) {
  if (out == NULL || out_len == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *out = NULL;
  *out_len = 0;
  if (padding_out) *padding_out = 0;
  if (chunk_len_out) *chunk_len_out = 0;
  if (bytes_ecc_out) *bytes_ecc_out = 0;
  if (verifiable_slice_count_out) *verifiable_slice_count_out = 0;
  if (bytes_compressed_out) *bytes_compressed_out = 0;
  if (bytes_encrypted_out) *bytes_encrypted_out = 0;
  if (master == NULL || (plaintext == NULL && plaintext_len != 0)) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (nonce == NULL && nonce_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *m = mk_byte_array(master, master_len);
  lean_object *n = mk_byte_array(nonce, nonce_len);
  lean_object *pt = mk_byte_array(plaintext, plaintext_len);
  /* Empty ByteArray when null → Lean zeros SLH/meta fields. */
  lean_object *slh = mk_byte_array(slh_pk, slh_pk != NULL ? 32 : 0);
  lean_object *meta = mk_byte_array(metadata, metadata != NULL ? 8 : 0);
  if (m == NULL || n == NULL || pt == NULL || slh == NULL || meta == NULL) {
    if (m) lean_dec(m);
    if (n) lean_dec(n);
    if (pt) lean_dec(pt);
    if (slh) lean_dec(slh);
    if (meta) lean_dec(meta);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed = l_carbonado_encode_headered(m, n, pt, slh, meta, format);
  size_t nlen = lean_sarray_size(packed);
  /* Status-first: errors are packed as [status:4] only (see packEncodeErr). */
  if (nlen < 4) {
    lean_dec(packed);
    return CARBONADO_ERR_INTERNAL;
  }
  const uint8_t *p = lean_sarray_cptr(packed);
  uint32_t status = read_u32_le(p);
  if (status != CARBONADO_OK) {
    lean_dec(packed);
    return (int)status;
  }
  /* Success: status(4)+pad(4)+chunk(4)+ecc(4)+vsc(4)+comp(4)+enc(4)+archive = 28 + archive. */
  if (nlen < 28) {
    lean_dec(packed);
    return CARBONADO_ERR_INTERNAL;
  }
  if (padding_out) *padding_out = read_u32_le(p + 4);
  if (chunk_len_out) *chunk_len_out = read_u32_le(p + 8);
  if (bytes_ecc_out) *bytes_ecc_out = read_u32_le(p + 12);
  if (verifiable_slice_count_out) *verifiable_slice_count_out = read_u32_le(p + 16);
  if (bytes_compressed_out) *bytes_compressed_out = read_u32_le(p + 20);
  if (bytes_encrypted_out) *bytes_encrypted_out = read_u32_le(p + 24);
  int rc = copy_sarray_payload(packed, 28, out, out_len);
  lean_dec(packed);
  return rc;
}

int carbonado_decode_headered(
    const uint8_t *master, size_t master_len,
    const uint8_t *archive, size_t archive_len,
    uint8_t **out, size_t *out_len) {
  if (out == NULL || out_len == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *out = NULL;
  *out_len = 0;
  if (master == NULL || (archive == NULL && archive_len != 0)) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *m = mk_byte_array(master, master_len);
  lean_object *a = mk_byte_array(archive, archive_len);
  if (m == NULL || a == NULL) {
    if (m) lean_dec(m);
    if (a) lean_dec(a);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed = l_carbonado_decode_headered(m, a);
  return unpack_status_payload(packed, out, out_len);
}

int carbonado_encode(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t **out, size_t *out_len,
    uint8_t hash_out[32],
    uint32_t *padding_out,
    uint32_t *chunk_len_out,
    uint32_t *bytes_ecc_out,
    uint32_t *verifiable_slice_count_out,
    uint32_t *bytes_compressed_out,
    uint32_t *bytes_encrypted_out) {
  if (out == NULL || out_len == NULL || hash_out == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *out = NULL;
  *out_len = 0;
  if (padding_out) *padding_out = 0;
  if (chunk_len_out) *chunk_len_out = 0;
  if (bytes_ecc_out) *bytes_ecc_out = 0;
  if (verifiable_slice_count_out) *verifiable_slice_count_out = 0;
  if (bytes_compressed_out) *bytes_compressed_out = 0;
  if (bytes_encrypted_out) *bytes_encrypted_out = 0;
  if (master == NULL || (plaintext == NULL && plaintext_len != 0)) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (nonce == NULL && nonce_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *m = mk_byte_array(master, master_len);
  lean_object *n = mk_byte_array(nonce, nonce_len);
  lean_object *pt = mk_byte_array(plaintext, plaintext_len);
  if (m == NULL || n == NULL || pt == NULL) {
    if (m) lean_dec(m);
    if (n) lean_dec(n);
    if (pt) lean_dec(pt);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed = l_carbonado_encode(m, n, pt, format);
  size_t nlen = lean_sarray_size(packed);
  /* Status-first: errors are packed as [status:4] only (see packEncodeErr). */
  if (nlen < 4) {
    lean_dec(packed);
    return CARBONADO_ERR_INTERNAL;
  }
  const uint8_t *p = lean_sarray_cptr(packed);
  uint32_t status = read_u32_le(p);
  if (status != CARBONADO_OK) {
    lean_dec(packed);
    return (int)status;
  }
  /* Success: status(4)+pad(4)+chunk(4)+ecc(4)+vsc(4)+comp(4)+enc(4)+hash(32)+body = 60 + body. */
  if (nlen < 60) {
    lean_dec(packed);
    return CARBONADO_ERR_INTERNAL;
  }
  if (padding_out) *padding_out = read_u32_le(p + 4);
  if (chunk_len_out) *chunk_len_out = read_u32_le(p + 8);
  if (bytes_ecc_out) *bytes_ecc_out = read_u32_le(p + 12);
  if (verifiable_slice_count_out) *verifiable_slice_count_out = read_u32_le(p + 16);
  if (bytes_compressed_out) *bytes_compressed_out = read_u32_le(p + 20);
  if (bytes_encrypted_out) *bytes_encrypted_out = read_u32_le(p + 24);
  memcpy(hash_out, p + 28, 32);
  int rc = copy_sarray_payload(packed, 60, out, out_len);
  lean_dec(packed);
  return rc;
}

int carbonado_decode(
    const uint8_t *master, size_t master_len,
    const uint8_t *hash, size_t hash_len,
    const uint8_t *body, size_t body_len,
    uint32_t padding,
    uint8_t format,
    uint8_t **out, size_t *out_len) {
  if (out == NULL || out_len == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *out = NULL;
  *out_len = 0;
  if (master == NULL || hash == NULL || hash_len != 32) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (body == NULL && body_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *m = mk_byte_array(master, master_len);
  lean_object *h = mk_byte_array(hash, hash_len);
  lean_object *b = mk_byte_array(body, body_len);
  if (m == NULL || h == NULL || b == NULL) {
    if (m) lean_dec(m);
    if (h) lean_dec(h);
    if (b) lean_dec(b);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed = l_carbonado_decode(m, h, b, padding, format);
  return unpack_status_payload(packed, out, out_len);
}

int carbonado_encode_outboard(
    const uint8_t *master, size_t master_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t format,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t header_path,
    uint8_t **main_out, size_t *main_len,
    uint8_t **outboard_out, size_t *outboard_len,
    uint8_t **parity_out, size_t *parity_len,
    uint8_t hash_out[32],
    uint32_t *padding_out,
    uint32_t *chunk_len_out,
    uint32_t *bytes_compressed_out,
    uint32_t *bytes_encrypted_out) {
  if (main_out == NULL || main_len == NULL || outboard_out == NULL || outboard_len == NULL ||
      parity_out == NULL || parity_len == NULL || hash_out == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *main_out = NULL;
  *main_len = 0;
  *outboard_out = NULL;
  *outboard_len = 0;
  *parity_out = NULL;
  *parity_len = 0;
  if (padding_out) *padding_out = 0;
  if (chunk_len_out) *chunk_len_out = 0;
  if (bytes_compressed_out) *bytes_compressed_out = 0;
  if (bytes_encrypted_out) *bytes_encrypted_out = 0;
  if (master == NULL || (plaintext == NULL && plaintext_len != 0)) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (nonce == NULL && nonce_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *m = mk_byte_array(master, master_len);
  lean_object *n = mk_byte_array(nonce, nonce_len);
  lean_object *pt = mk_byte_array(plaintext, plaintext_len);
  if (m == NULL || n == NULL || pt == NULL) {
    if (m) lean_dec(m);
    if (n) lean_dec(n);
    if (pt) lean_dec(pt);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed = l_carbonado_encode_outboard(m, n, pt, format, header_path);
  size_t nlen = lean_sarray_size(packed);
  if (nlen < 4) {
    lean_dec(packed);
    return CARBONADO_ERR_INTERNAL;
  }
  const uint8_t *p = lean_sarray_cptr(packed);
  uint32_t status = read_u32_le(p);
  if (status != CARBONADO_OK) {
    lean_dec(packed);
    return (int)status;
  }
  /* status(4)+pad(4)+chunk(4)+comp(4)+enc(4)+hash(32) = 52 */
  if (nlen < 52) {
    lean_dec(packed);
    return CARBONADO_ERR_INTERNAL;
  }
  if (padding_out) *padding_out = read_u32_le(p + 4);
  if (chunk_len_out) *chunk_len_out = read_u32_le(p + 8);
  if (bytes_compressed_out) *bytes_compressed_out = read_u32_le(p + 12);
  if (bytes_encrypted_out) *bytes_encrypted_out = read_u32_le(p + 16);
  memcpy(hash_out, p + 20, 32);
  size_t off = 52;
  int rc = read_len_prefixed(p, nlen, &off, main_out, main_len);
  if (rc != CARBONADO_OK) {
    lean_dec(packed);
    return rc;
  }
  rc = read_len_prefixed(p, nlen, &off, outboard_out, outboard_len);
  if (rc != CARBONADO_OK) {
    free(*main_out);
    *main_out = NULL;
    *main_len = 0;
    lean_dec(packed);
    return rc;
  }
  rc = read_len_prefixed(p, nlen, &off, parity_out, parity_len);
  if (rc != CARBONADO_OK) {
    free(*main_out);
    free(*outboard_out);
    *main_out = NULL;
    *main_len = 0;
    *outboard_out = NULL;
    *outboard_len = 0;
    lean_dec(packed);
    return rc;
  }
  lean_dec(packed);
  return CARBONADO_OK;
}

int carbonado_decode_outboard(
    const uint8_t *master, size_t master_len,
    const uint8_t *hash, size_t hash_len,
    const uint8_t *main, size_t main_len,
    const uint8_t *outboard, size_t outboard_len,
    const uint8_t *parity, size_t parity_len,
    uint32_t padding,
    uint8_t format,
    uint8_t header_path,
    const uint8_t *nonce, size_t nonce_len,
    uint8_t **out, size_t *out_len) {
  if (out == NULL || out_len == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *out = NULL;
  *out_len = 0;
  if (master == NULL || hash == NULL || hash_len != 32) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (main == NULL && main_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (outboard == NULL && outboard_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (parity == NULL && parity_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (nonce == NULL && nonce_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *m = mk_byte_array(master, master_len);
  lean_object *h = mk_byte_array(hash, hash_len);
  lean_object *mn = mk_byte_array(main, main_len);
  lean_object *ob = mk_byte_array(outboard, outboard_len);
  lean_object *pr = mk_byte_array(parity, parity_len);
  lean_object *n = mk_byte_array(nonce, nonce_len);
  if (m == NULL || h == NULL || mn == NULL || ob == NULL || pr == NULL || n == NULL) {
    if (m) lean_dec(m);
    if (h) lean_dec(h);
    if (mn) lean_dec(mn);
    if (ob) lean_dec(ob);
    if (pr) lean_dec(pr);
    if (n) lean_dec(n);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed =
      l_carbonado_decode_outboard(m, h, mn, ob, pr, padding, format, header_path, n);
  return unpack_status_payload(packed, out, out_len);
}

int carbonado_scrub(
    const uint8_t *body, size_t body_len,
    const uint8_t *hash, size_t hash_len,
    uint32_t padding,
    uint8_t format,
    uint8_t **out, size_t *out_len) {
  if (out == NULL || out_len == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *out = NULL;
  *out_len = 0;
  if (hash == NULL || hash_len != 32) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (body == NULL && body_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *b = mk_byte_array(body, body_len);
  lean_object *h = mk_byte_array(hash, hash_len);
  if (b == NULL || h == NULL) {
    if (b) lean_dec(b);
    if (h) lean_dec(h);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed = l_carbonado_scrub(b, h, padding, format);
  return unpack_status_payload(packed, out, out_len);
}

int carbonado_scrub_outboard(
    const uint8_t *main, size_t main_len,
    const uint8_t *outboard, size_t outboard_len,
    const uint8_t *parity, size_t parity_len,
    const uint8_t *hash, size_t hash_len,
    uint32_t padding,
    uint32_t chunk_len,
    uint8_t format,
    uint8_t **out, size_t *out_len) {
  if (out == NULL || out_len == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *out = NULL;
  *out_len = 0;
  if (hash == NULL || hash_len != 32) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (main == NULL && main_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (outboard == NULL && outboard_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (parity == NULL && parity_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *mn = mk_byte_array(main, main_len);
  lean_object *ob = mk_byte_array(outboard, outboard_len);
  lean_object *pr = mk_byte_array(parity, parity_len);
  lean_object *h = mk_byte_array(hash, hash_len);
  if (mn == NULL || ob == NULL || pr == NULL || h == NULL) {
    if (mn) lean_dec(mn);
    if (ob) lean_dec(ob);
    if (pr) lean_dec(pr);
    if (h) lean_dec(h);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed =
      l_carbonado_scrub_outboard(mn, ob, pr, h, padding, chunk_len, format);
  return unpack_status_payload(packed, out, out_len);
}

int carbonado_verify_slice(
    const uint8_t *body, size_t body_len,
    const uint8_t *hash, size_t hash_len,
    uint32_t index,
    uint32_t count,
    uint8_t format,
    uint8_t **out, size_t *out_len) {
  if (out == NULL || out_len == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *out = NULL;
  *out_len = 0;
  if (hash == NULL || hash_len != 32) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (body == NULL && body_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *b = mk_byte_array(body, body_len);
  lean_object *h = mk_byte_array(hash, hash_len);
  if (b == NULL || h == NULL) {
    if (b) lean_dec(b);
    if (h) lean_dec(h);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed = l_carbonado_verify_slice(b, h, index, count, format);
  return unpack_status_payload(packed, out, out_len);
}

int carbonado_verify_slice_outboard(
    const uint8_t *main, size_t main_len,
    const uint8_t *outboard, size_t outboard_len,
    const uint8_t *hash, size_t hash_len,
    uint32_t index,
    uint32_t count,
    uint8_t format,
    uint8_t **out, size_t *out_len) {
  if (out == NULL || out_len == NULL) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  *out = NULL;
  *out_len = 0;
  if (hash == NULL || hash_len != 32) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (main == NULL && main_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (outboard == NULL && outboard_len != 0) {
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }
  if (ensure_lean() != 0) {
    return CARBONADO_ERR_INTERNAL;
  }

  lean_object *mn = mk_byte_array(main, main_len);
  lean_object *ob = mk_byte_array(outboard, outboard_len);
  lean_object *h = mk_byte_array(hash, hash_len);
  if (mn == NULL || ob == NULL || h == NULL) {
    if (mn) lean_dec(mn);
    if (ob) lean_dec(ob);
    if (h) lean_dec(h);
    return CARBONADO_ERR_INVALID_ARGUMENT;
  }

  lean_obj_res packed =
      l_carbonado_verify_slice_outboard(mn, ob, h, index, count, format);
  return unpack_status_payload(packed, out, out_len);
}
