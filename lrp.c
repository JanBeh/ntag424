#include "lrp.h"

#include <string.h>

static void lrp_eval_step(
  lrp_ctx_t *restrict ctx,
  lrp_block_t *restrict state,
  const uint8_t *restrict counter,
  int offset
) {
  aes_ctx_t *const aes_ctx = &ctx->aes_ctx;
  lrp_block_t *const pts = ctx->pts;
  aes_key(aes_ctx, state->bytes);
  memcpy(
    state->bytes,
    !(offset & 1) ?
    pts[counter[offset>>1] >> 4].bytes :
    pts[counter[offset>>1] & 0x0F].bytes,
    LRP_BLOCK_LEN
  );
  aes_enc(aes_ctx, state->bytes);
}

static void lrp_eval_final(
  lrp_ctx_t *restrict ctx,
  lrp_block_t *restrict state
) {
  aes_ctx_t *const aes_ctx = &ctx->aes_ctx;
  aes_key(aes_ctx, state->bytes);
  memset(state->bytes, 0, LRP_BLOCK_LEN);
  aes_enc(aes_ctx, state->bytes);
}

void lrp_key(
  lrp_ctx_t *restrict ctx,
  uint8_t *restrict key,
  bool encryption
) {
  aes_ctx_t *const aes_ctx = &ctx->aes_ctx;
  aes_key(aes_ctx, key);
  for (int i=0; i<LRP_PT_COUNT; i++) {
    memset(ctx->pts[i].bytes, 0x55, LRP_BLOCK_LEN);
    aes_enc(aes_ctx, ctx->pts[i].bytes);
    aes_key(aes_ctx, ctx->pts[i].bytes);
    memset(ctx->pts[i].bytes, 0xAA, LRP_BLOCK_LEN);
    aes_enc(aes_ctx, ctx->pts[i].bytes);
  }
  aes_key(aes_ctx, key);
  memset(ctx->mac_keys[0].bytes, 0xAA, LRP_BLOCK_LEN);
  aes_enc(aes_ctx, ctx->mac_keys[0].bytes);
  aes_key(aes_ctx, ctx->mac_keys[0].bytes);
  memset(ctx->mac_keys[0].bytes, 0xAA, LRP_BLOCK_LEN);
  aes_enc(aes_ctx, ctx->mac_keys[0].bytes);
  if (encryption) {
    memset(ctx->enc_states[0].bytes, 0x55, LRP_BLOCK_LEN);
    aes_enc(aes_ctx, ctx->enc_states[0].bytes);
    aes_key(aes_ctx, ctx->enc_states[0].bytes);
    memset(ctx->enc_states[0].bytes, 0xAA, LRP_BLOCK_LEN);
    aes_enc(aes_ctx, ctx->enc_states[0].bytes);
    memset(ctx->enc_counter, 0, LRP_ENC_IV_LEN);
    ctx->enc_counter_pos = 0;
  }
  bool msb_set, tmp;
  static const uint8_t zero = 0;
  memcpy(ctx->mac_keys[1].bytes, ctx->mac_keys[0].bytes, LRP_BLOCK_LEN);
  for (int i=0; i<2*LRP_BLOCK_LEN; i++) {
    lrp_eval_step(ctx, ctx->mac_keys+1, &zero, 0);
  }
  lrp_eval_final(ctx, ctx->mac_keys+1);
  msb_set = false;
  for (int i=LRP_BLOCK_LEN-1; i>=0; i--) {
    tmp = ctx->mac_keys[1].bytes[i] & 0x80;
    ctx->mac_keys[1].bytes[i] <<= 1;
    if (msb_set) ctx->mac_keys[1].bytes[i] |= 1;
    msb_set = tmp;
  }
  if (msb_set) ctx->mac_keys[1].bytes[LRP_BLOCK_LEN-1] ^= 0x87;
  memcpy(ctx->mac_keys[2].bytes, ctx->mac_keys[1].bytes, LRP_BLOCK_LEN);
  msb_set = false;
  for (int i=LRP_BLOCK_LEN-1; i>=0; i--) {
    tmp = ctx->mac_keys[2].bytes[i] & 0x80;
    ctx->mac_keys[2].bytes[i] <<= 1;
    if (msb_set) ctx->mac_keys[2].bytes[i] |= 1;
    msb_set = tmp;
  }
  if (msb_set) ctx->mac_keys[2].bytes[LRP_BLOCK_LEN-1] ^= 0x87;
}

void lrp_enc_iv(
  lrp_ctx_t *restrict ctx,
  uint8_t *restrict iv
) {
  memcpy(ctx->enc_counter, iv, LRP_ENC_IV_LEN);
  ctx->enc_counter_pos = 0;
}

static void lrp_enc_block(
  lrp_ctx_t *restrict ctx,
  lrp_block_t *restrict data,
  bool decrypt
) {
  aes_ctx_t *const aes_ctx = &ctx->aes_ctx;
  for (int i=ctx->enc_counter_pos; i<LRP_ENC_IV_LEN; i++) {
    memcpy(ctx->enc_states+i+1, ctx->enc_states+i, LRP_BLOCK_LEN);
    lrp_eval_step(ctx, ctx->enc_states+i+1, ctx->enc_counter, 2*i+0);
    lrp_eval_step(ctx, ctx->enc_states+i+1, ctx->enc_counter, 2*i+1);
  }
  lrp_eval_final(ctx, ctx->enc_states+LRP_ENC_IV_LEN);
  aes_key(aes_ctx, ctx->enc_states[LRP_ENC_IV_LEN].bytes);
  if (decrypt) {
    aes_dec(aes_ctx, data->bytes);
  } else {
    aes_enc(aes_ctx, data->bytes);
  }
  for (ctx->enc_counter_pos=LRP_ENC_IV_LEN-1; ; ctx->enc_counter_pos--) {
    if (++ctx->enc_counter[ctx->enc_counter_pos]) break;
    if (ctx->enc_counter_pos == 0) break;
  }
}

size_t lrp_enc(
  lrp_ctx_t *restrict ctx,
  uint8_t *data,
  size_t len,
  bool padding,
  bool decrypt
) {
  size_t outlen = 0;
  // NOTE: memcpy to block.bytes is unneccary and causes minor overhead
  // if AES_BLOCK_ALIGN == 1, but done in either case to keep code simpler
  // and avoid further conditional compilation directives.
  lrp_block_t block;
  for (; len >= LRP_BLOCK_LEN; len -= LRP_BLOCK_LEN) {
    memcpy(block.bytes, data, LRP_BLOCK_LEN);
    lrp_enc_block(ctx, &block, decrypt);
    memcpy(data, block.bytes, LRP_BLOCK_LEN);
    data += LRP_BLOCK_LEN;
    outlen += LRP_BLOCK_LEN;
  }
  if (padding) {
    if (!decrypt) {
      memcpy(block.bytes, data, len);
      block.bytes[len] = 0x80;
      memset(block.bytes+len+1, 0, LRP_BLOCK_LEN-len-1);
      lrp_enc_block(ctx, &block, false);
      memcpy(data, block.bytes, LRP_BLOCK_LEN);
      outlen += LRP_BLOCK_LEN;
    } else {
      if (len || !outlen) return LRP_INVALID;
      for (int i=LRP_BLOCK_LEN-1; i>=0; i--) {
        if (block.bytes[i] == 0x80) return --outlen;
        if (!block.bytes[i]) outlen--;
      }
      return LRP_INVALID;
    }
  }
  return outlen;
}

void lrp_mac(
  lrp_ctx_t *restrict ctx,
  uint8_t *restrict mac,
  uint8_t *restrict data,
  size_t len
) {
  lrp_block_t res = { .bytes = { 0, } };
  uint8_t tmp[LRP_BLOCK_LEN];
  for (; len > LRP_BLOCK_LEN; len -= LRP_BLOCK_LEN) {
    for (int i=0; i<LRP_BLOCK_LEN; i++) tmp[i] = res.bytes[i] ^ *(data++);
    memcpy(res.bytes, ctx->mac_keys[0].bytes, LRP_BLOCK_LEN);
    for (int i=0; i<2*LRP_BLOCK_LEN; i++) lrp_eval_step(ctx, &res, tmp, i);
    lrp_eval_final(ctx, &res);
  }
  for (int i=0; i<len; i++) tmp[i] = res.bytes[i] ^ *(data++);
  memcpy(tmp+len, res.bytes+len, LRP_BLOCK_LEN-len);
  if (len == LRP_BLOCK_LEN) {
    for (int i=0; i<LRP_BLOCK_LEN; i++) tmp[i] ^= ctx->mac_keys[1].bytes[i];
  } else {
    tmp[len] ^= 0x80;
    for (int i=0; i<LRP_BLOCK_LEN; i++) tmp[i] ^= ctx->mac_keys[2].bytes[i];
  }
  memcpy(res.bytes, ctx->mac_keys[0].bytes, LRP_BLOCK_LEN);
  for (int i=0; i<2*LRP_BLOCK_LEN; i++) lrp_eval_step(ctx, &res, tmp, i);
  lrp_eval_final(ctx, &res);
  memcpy(mac, res.bytes, LRP_BLOCK_LEN);
}
