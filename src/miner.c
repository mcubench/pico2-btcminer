#include "miner.h"

#include <string.h>
#include "pico/stdlib.h"
#include "hardware/sha256.h"
#include "hardware/structs/sha256.h"
#include "hardware/dma.h"

// ---------------------------------------------------------------------------
// Engine notes (RP2350 datasheet, SHA-256 section)
//
//  * The core hashes one 512-bit block at a time. It does NOT do padding and it
//    does NOT let you load an initial state -- START always reloads the
//    standard SHA-256 IV. That second point is why this miner cannot use the
//    usual "midstate" trick: block 0 of the header has to be re-hashed for
//    every nonce, so a Bitcoin hash costs 3 compressions here instead of 2.
//
//  * BSWAP converts little-endian bus words into big-endian internal words.
//    We keep BSWAP off and hand the engine big-endian message words directly,
//    which lets the header be byte-swapped once per work item instead of once
//    per nonce.
//
//  * "After writing 16 words, WDATA_RDY will go low for 57 cycles whilst the
//    core completes its digest." So within a block all 16 words may be written
//    back to back; a ready check is only needed between blocks. That is what
//    FEED_CPU_FAST relies on, and what FEED_CPU_SAFE deliberately does not.
// ---------------------------------------------------------------------------

#define CSR_START_CPU (SHA256_CSR_START_BITS)
#define CSR_START_DMA (SHA256_CSR_START_BITS | \
                       (SHA256_CSR_DMA_SIZE_VALUE_32BIT << SHA256_CSR_DMA_SIZE_LSB))

const char *const feed_mode_name[FEED_COUNT] = {
    "CPU (fast)", "CPU (safe)", "DMA"
};

static int dma_chan = -1;

void miner_hw_init(void) {
    sha256_err_not_ready_clear();
    sha256_set_bswap(false);
    if (dma_chan < 0) {
        dma_chan = dma_claim_unused_channel(true);
        dma_channel_config c = dma_channel_get_default_config((uint)dma_chan);
        channel_config_set_transfer_data_size(&c, DMA_SIZE_32);
        channel_config_set_read_increment(&c, true);
        channel_config_set_write_increment(&c, false);
        channel_config_set_dreq(&c, DREQ_SHA256);
        dma_channel_configure((uint)dma_chan, &c,
                              (void *)&sha256_hw->wdata, NULL, 32, false);
    }
}

bool miner_hw_error(void)      { return sha256_err_not_ready(); }
void miner_hw_error_clear(void) { sha256_err_not_ready_clear(); }

static inline uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void btc_work_init(btc_work_t *w, const uint8_t hdr[80]) {
    // blk[0..15]  = message words for header bytes 0..63   (first block)
    // blk[16..19] = message words for header bytes 64..79  (second block)
    // blk[19] is the nonce and is rewritten for every candidate.
    for (int i = 0; i < 20; i++) w->blk[i] = be32(hdr + 4 * i);
    // Padding for a 640-bit message.
    w->blk[20] = 0x80000000u;
    for (int i = 21; i < 31; i++) w->blk[i] = 0;
    w->blk[31] = 640u;
}

// --- block feeders ---------------------------------------------------------

static inline void feed16_fast(const uint32_t *p) {
    io_wo_32 *wd = &sha256_hw->wdata;
    *wd = p[0];  *wd = p[1];  *wd = p[2];  *wd = p[3];
    *wd = p[4];  *wd = p[5];  *wd = p[6];  *wd = p[7];
    *wd = p[8];  *wd = p[9];  *wd = p[10]; *wd = p[11];
    *wd = p[12]; *wd = p[13]; *wd = p[14]; *wd = p[15];
}

static inline void feed16_safe(const uint32_t *p) {
    for (int i = 0; i < 16; i++) {
        while (!(sha256_hw->csr & SHA256_CSR_WDATA_RDY_BITS)) tight_loop_contents();
        sha256_hw->wdata = p[i];
    }
}

static inline void wait_wdata_ready(void) {
    while (!(sha256_hw->csr & SHA256_CSR_WDATA_RDY_BITS)) tight_loop_contents();
}
static inline void wait_sum_valid(void) {
    while (!(sha256_hw->csr & SHA256_CSR_SUM_VLD_BITS)) tight_loop_contents();
}

// Second SHA-256: one block over the 32-byte digest of the first.
// The eight state words must already be in registers -- START clears SUM.
static inline uint32_t second_hash(uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3,
                                   uint32_t h4, uint32_t h5, uint32_t h6, uint32_t h7,
                                   uint32_t csr_start) {
    io_wo_32 *wd = &sha256_hw->wdata;
    sha256_hw->csr = csr_start;
    *wd = h0; *wd = h1; *wd = h2; *wd = h3;
    *wd = h4; *wd = h5; *wd = h6; *wd = h7;
    *wd = 0x80000000u;
    *wd = 0; *wd = 0; *wd = 0; *wd = 0; *wd = 0; *wd = 0;
    *wd = 256u; // 32 bytes * 8 bits
    wait_sum_valid();
    return sha256_hw->sum[7];
}

uint32_t __not_in_flash_func(miner_hash_nonce_fast)(btc_work_t *w, uint32_t nonce) {
    w->blk[WORK_NONCE_WORD] = __builtin_bswap32(nonce);

    sha256_hw->csr = CSR_START_CPU;
    feed16_fast(&w->blk[0]);
    wait_wdata_ready();
    feed16_fast(&w->blk[16]);
    wait_sum_valid();

    uint32_t h0 = sha256_hw->sum[0], h1 = sha256_hw->sum[1];
    uint32_t h2 = sha256_hw->sum[2], h3 = sha256_hw->sum[3];
    uint32_t h4 = sha256_hw->sum[4], h5 = sha256_hw->sum[5];
    uint32_t h6 = sha256_hw->sum[6], h7 = sha256_hw->sum[7];

    return second_hash(h0, h1, h2, h3, h4, h5, h6, h7, CSR_START_CPU);
}

uint32_t __not_in_flash_func(miner_hash_nonce_safe)(btc_work_t *w, uint32_t nonce) {
    w->blk[WORK_NONCE_WORD] = __builtin_bswap32(nonce);

    sha256_hw->csr = CSR_START_CPU;
    feed16_safe(&w->blk[0]);
    feed16_safe(&w->blk[16]);
    wait_sum_valid();

    uint32_t h[8];
    for (int i = 0; i < 8; i++) h[i] = sha256_hw->sum[i];

    uint32_t blk2[16];
    for (int i = 0; i < 8; i++) blk2[i] = h[i];
    blk2[8] = 0x80000000u;
    for (int i = 9; i < 15; i++) blk2[i] = 0;
    blk2[15] = 256u;

    sha256_hw->csr = CSR_START_CPU;
    feed16_safe(blk2);
    wait_sum_valid();
    return sha256_hw->sum[7];
}

uint32_t __not_in_flash_func(miner_hash_nonce_dma)(btc_work_t *w, uint32_t nonce) {
    w->blk[WORK_NONCE_WORD] = __builtin_bswap32(nonce);

    // START must precede the transfer: the core requests 16 transfers at a
    // time and paces the channel through DREQ_SHA256, so one 32-word transfer
    // covers both header blocks with no CPU involvement in between.
    sha256_hw->csr = CSR_START_DMA;
    dma_channel_set_trans_count((uint)dma_chan, 32, false);
    dma_channel_set_read_addr((uint)dma_chan, w->blk, true);
    dma_channel_wait_for_finish_blocking((uint)dma_chan);
    wait_sum_valid();

    uint32_t h0 = sha256_hw->sum[0], h1 = sha256_hw->sum[1];
    uint32_t h2 = sha256_hw->sum[2], h3 = sha256_hw->sum[3];
    uint32_t h4 = sha256_hw->sum[4], h5 = sha256_hw->sum[5];
    uint32_t h6 = sha256_hw->sum[6], h7 = sha256_hw->sum[7];

    return second_hash(h0, h1, h2, h3, h4, h5, h6, h7, CSR_START_DMA);
}

uint32_t miner_hash_nonce(btc_work_t *w, uint32_t nonce, feed_mode_t mode) {
    switch (mode) {
        case FEED_CPU_SAFE: return miner_hash_nonce_safe(w, nonce);
        case FEED_DMA:      return miner_hash_nonce_dma(w, nonce);
        default:            return miner_hash_nonce_fast(w, nonce);
    }
}

void miner_read_state(uint32_t st[8]) {
    for (int i = 0; i < 8; i++) st[i] = sha256_hw->sum[i];
}

// --- raw streaming interface -----------------------------------------------

void hw_feed_raw_start(void) {
    sha256_hw->csr = CSR_START_CPU;
}

void hw_feed_raw_block(const uint32_t w[16]) {
    wait_wdata_ready();
    feed16_fast(w);
}

void hw_feed_raw_finish(uint8_t out[32]) {
    wait_sum_valid();
    for (int i = 0; i < 8; i++) {
        uint32_t v = sha256_hw->sum[i];
        out[4 * i + 0] = (uint8_t)(v >> 24);
        out[4 * i + 1] = (uint8_t)(v >> 16);
        out[4 * i + 2] = (uint8_t)(v >> 8);
        out[4 * i + 3] = (uint8_t)(v);
    }
}

// --- general purpose hardware SHA-256 --------------------------------------

void hw_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t w[16];
    size_t off = 0;

    sha256_hw->csr = CSR_START_CPU;

    while (len - off >= 64) {
        for (int i = 0; i < 16; i++) w[i] = be32(data + off + 4 * i);
        feed16_safe(w);
        off += 64;
    }

    uint8_t tail[128];
    size_t tl = len - off;
    memcpy(tail, data + off, tl);
    tail[tl] = 0x80u;
    size_t padlen = (tl <= 55) ? 64u : 128u;
    memset(tail + tl + 1, 0, padlen - tl - 1);
    uint64_t bits = (uint64_t)len * 8u;
    for (int i = 0; i < 8; i++) tail[padlen - 1 - i] = (uint8_t)(bits >> (8 * i));

    for (size_t b = 0; b < padlen; b += 64) {
        for (int i = 0; i < 16; i++) w[i] = be32(tail + b + 4 * i);
        feed16_safe(w);
    }

    wait_sum_valid();
    for (int i = 0; i < 8; i++) {
        uint32_t v = sha256_hw->sum[i];
        out[4 * i + 0] = (uint8_t)(v >> 24);
        out[4 * i + 1] = (uint8_t)(v >> 16);
        out[4 * i + 2] = (uint8_t)(v >> 8);
        out[4 * i + 3] = (uint8_t)(v);
    }
}

// --- Bitcoin numeric helpers ----------------------------------------------

void btc_hash_limbs(const uint32_t st[8], uint32_t limbs[8]) {
    // Bitcoin reads the digest as a little-endian 256-bit integer, so the most
    // significant limb comes from the last state word, byte-reversed.
    for (int i = 0; i < 8; i++) limbs[i] = __builtin_bswap32(st[i]);
}

void btc_target_from_bits(uint32_t bits, uint32_t target[8]) {
    uint8_t t[32];
    memset(t, 0, sizeof(t));
    uint32_t exp = bits >> 24;
    uint32_t mant = bits & 0x007fffffu;
    // target = mant * 256^(exp-3), laid out big-endian in t[0..31]
    if (exp <= 3) {
        mant >>= 8 * (3 - exp);
        t[31] = (uint8_t)(mant);
        t[30] = (uint8_t)(mant >> 8);
        t[29] = (uint8_t)(mant >> 16);
    } else if (exp <= 32) {
        int msb = 32 - (int)exp; // index of the mantissa's top byte
        if (msb >= 0 && msb + 2 < 32) {
            t[msb + 0] = (uint8_t)(mant >> 16);
            t[msb + 1] = (uint8_t)(mant >> 8);
            t[msb + 2] = (uint8_t)(mant);
        }
    } else {
        // Not a valid compact encoding. Leave the target at zero so nothing
        // can pass -- an all-ones fallback would report bogus solutions.
        memset(t, 0x00, sizeof(t));
    }
    for (int i = 0; i < 8; i++)
        target[7 - i] = ((uint32_t)t[4 * i] << 24) | ((uint32_t)t[4 * i + 1] << 16) |
                        ((uint32_t)t[4 * i + 2] << 8) | (uint32_t)t[4 * i + 3];
}

bool btc_bits_valid(uint32_t bits) {
    uint32_t exp = bits >> 24;
    uint32_t mant = bits & 0x007fffffu;
    return mant != 0 && exp >= 3 && exp <= 32;
}

bool btc_limbs_le(const uint32_t a[8], const uint32_t b[8]) {
    for (int i = 7; i >= 0; i--) {
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return true;
}

int btc_leading_zero_bits(const uint32_t limbs[8]) {
    int n = 0;
    for (int i = 7; i >= 0; i--) {
        if (limbs[i] == 0) { n += 32; continue; }
        n += __builtin_clz(limbs[i]);
        break;
    }
    return n;
}

void btc_state_to_digest(const uint32_t st[8], uint8_t out[32]) {
    for (int i = 0; i < 8; i++) {
        out[4 * i + 0] = (uint8_t)(st[i] >> 24);
        out[4 * i + 1] = (uint8_t)(st[i] >> 16);
        out[4 * i + 2] = (uint8_t)(st[i] >> 8);
        out[4 * i + 3] = (uint8_t)(st[i]);
    }
}

void btc_hash_to_display(const uint32_t st[8], char out[65]) {
    static const char hex[] = "0123456789abcdef";
    uint8_t d[32];
    btc_state_to_digest(st, d);
    for (int j = 0; j < 32; j++) {
        uint8_t b = d[31 - j];
        out[2 * j] = hex[b >> 4];
        out[2 * j + 1] = hex[b & 0xf];
    }
    out[64] = '\0';
}
