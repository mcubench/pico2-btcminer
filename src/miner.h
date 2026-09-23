// RP2350 hardware SHA-256 engine driver, specialised for Bitcoin double-SHA256.
#ifndef MINER_H
#define MINER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// How the 512-bit blocks are pushed into the engine.
typedef enum {
    FEED_CPU_FAST = 0, // wait for WDATA_RDY only where the datasheet requires it
    FEED_CPU_SAFE = 1, // poll WDATA_RDY before every single word (SDK-style)
    FEED_DMA      = 2, // DMA feeds the first hash, paced by DREQ_SHA256
    FEED_COUNT    = 3
} feed_mode_t;

extern const char *const feed_mode_name[FEED_COUNT];

// Fastest feed mode that passed validation. Set by the self test in main.c.
extern feed_mode_t best_mode;

// A prepared work item: the 80-byte header expanded into the 32 big-endian
// message words of the two blocks the first SHA-256 consumes. Word 19 is the
// nonce and is the only thing that changes while searching.
typedef struct {
    uint32_t blk[32];
} btc_work_t;

#define WORK_NONCE_WORD 19

void miner_hw_init(void);

// Expand an 80-byte serialised block header into a work item.
void btc_work_init(btc_work_t *w, const uint8_t hdr[80]);

// Hash one nonce. Leaves the eight final state words in the engine's SUM
// registers and returns state word 7 -- the fast-reject word, which must be
// zero for a hash with 32 or more leading zero bits.
uint32_t miner_hash_nonce_fast(btc_work_t *w, uint32_t nonce);
uint32_t miner_hash_nonce_safe(btc_work_t *w, uint32_t nonce);
uint32_t miner_hash_nonce_dma(btc_work_t *w, uint32_t nonce);
uint32_t miner_hash_nonce(btc_work_t *w, uint32_t nonce, feed_mode_t mode);

// Read the eight state words left behind by the last hash.
void miner_read_state(uint32_t st[8]);

// General purpose hardware SHA-256 over an arbitrary byte string.
void hw_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

// Raw streaming interface: caller supplies already-padded big-endian message
// words, one 512-bit block at a time. Lets us hash huge inputs without
// buffering them.
void hw_feed_raw_start(void);
void hw_feed_raw_block(const uint32_t w[16]);
void hw_feed_raw_finish(uint8_t out[32]);

// True if the engine flagged "data written while not ready" since the last clear.
bool miner_hw_error(void);
void miner_hw_error_clear(void);

// ---- Bitcoin numeric helpers ---------------------------------------------

// Convert the eight final state words into 32-bit limbs of the 256-bit value
// Bitcoin compares against the target. limb[7] is the most significant.
void btc_hash_limbs(const uint32_t st[8], uint32_t limbs[8]);

// Expand a compact "bits" difficulty encoding into limb form.
void btc_target_from_bits(uint32_t bits, uint32_t target[8]);

// True if 'bits' is a well formed compact difficulty encoding.
bool btc_bits_valid(uint32_t bits);

bool btc_limbs_le(const uint32_t a[8], const uint32_t b[8]);
int  btc_leading_zero_bits(const uint32_t limbs[8]);

// 64 hex chars, big-endian display order (the byte-reversed digest).
void btc_hash_to_display(const uint32_t st[8], char out[65]);

// Serialise the digest in internal order (what SHA-256 actually produced).
void btc_state_to_digest(const uint32_t st[8], uint8_t out[32]);

#endif // MINER_H
