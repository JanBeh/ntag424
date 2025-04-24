#ifndef AES_H_
#define AES_H_

#include <stdint.h>

// 128 bit block length:
#define AES_BLOCK_LEN 16

// 128 bit key length:
#define AES_KEY_LEN 16

// Alignment of buf pointer passed to aes_enc and aes_dec functions:
#define AES_BLOCK_ALIGN 4

// Number of rounds:
#define AES_ROUNDS 10

// Context:
typedef struct {
  uint32_t round_key[(AES_ROUNDS+1) * AES_BLOCK_LEN];
} aes_ctx_t;

// Set key (no alignment required):
void aes_key(aes_ctx_t *ctx, const uint8_t *key);

// Encrypt block (must be aligned according to AES_BLOCK_ALIGN):
void aes_enc(const aes_ctx_t *ctx, void *buf);

// Decrypt block (must be aligned according to AES_BLOCK_ALIGN):
void aes_dec(const aes_ctx_t *ctx, void *buf);

#endif
