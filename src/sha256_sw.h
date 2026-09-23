// Portable software SHA-256. Used as an independent on-chip reference so the
// firmware can cross-check the hardware accelerator, and as a baseline for the
// speed comparison.
#ifndef SHA256_SW_H
#define SHA256_SW_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint32_t buflen;
    uint8_t  buf[64];
} sha256_sw_t;

void sha256_sw_init(sha256_sw_t *c);
void sha256_sw_update(sha256_sw_t *c, const uint8_t *data, size_t len);
void sha256_sw_final(sha256_sw_t *c, uint8_t out[32]);
void sha256_sw(const uint8_t *data, size_t len, uint8_t out[32]);

// Compress one 512-bit block given as 16 big-endian message words.
void sha256_sw_compress_words(uint32_t state[8], const uint32_t w[16]);

// Bitcoin double SHA-256 over an 80-byte header. Writes the 32-byte digest
// in internal (big-endian) order.
void sha256_sw_dsha80(const uint8_t hdr[80], uint8_t out[32]);

#endif // SHA256_SW_H
