// Cycle-inaccurate but behaviourally faithful model of the RP2350 SHA-256
// accelerator, so the real miner.c can be exercised on a host.
//
// Semantics modelled (from the RP2350 datasheet register docs and the
// pico-sdk driver):
//   * START reloads the standard SHA-256 IV and clears the word counter.
//   * WDATA takes 16 words per 512-bit block; the block is compressed on the
//     16th word.
//   * BSWAP converts little-endian bus words into big-endian message words.
//     With BSWAP clear, the word written IS the message word.
//   * SUM0..SUM7 read back the numeric state words H0..H7.
//   * Writing WDATA when not ready sets ERR_WDATA_NOT_RDY.

#include "hardware/sha256.h"
#include "hardware/dma.h"
#include <string.h>
#include <stdio.h>

sha256_hw_t sha256_hw_obj;

static const uint32_t IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};
static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u,
};

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static uint32_t state[8];
static uint32_t buf[16];
static int      wcount = 0;
static bool     sum_valid = true;
static bool     bswap = true;   // reset value is 1
static bool     err = false;

// Instrumentation: how many blocks the engine has compressed.
unsigned long emul_block_count = 0;

static void compress(void) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = buf[i];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3];
    uint32_t e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
    emul_block_count++;
}

void sha_emul_csr_write(uint32_t v) {
    bswap = (v & SHA256_CSR_BSWAP_BITS) != 0;
    if (v & SHA256_CSR_ERR_WDATA_NOT_RDY_BITS) err = false; // write-1-to-clear
    if (v & SHA256_CSR_START_BITS) {
        memcpy(state, IV, sizeof(IV));
        wcount = 0;
        sum_valid = true;
    }
}

uint32_t sha_emul_csr_read(void) {
    uint32_t v = SHA256_CSR_WDATA_RDY_BITS;          // model is never busy
    if (sum_valid) v |= SHA256_CSR_SUM_VLD_BITS;
    if (err)       v |= SHA256_CSR_ERR_WDATA_NOT_RDY_BITS;
    if (bswap)     v |= SHA256_CSR_BSWAP_BITS;
    return v;
}

void sha_emul_wdata(uint32_t v) {
    uint32_t m = bswap ? __builtin_bswap32(v) : v;
    sum_valid = false;
    buf[wcount++] = m;
    if (wcount == 16) { compress(); wcount = 0; sum_valid = true; }
}

uint32_t sha_emul_sum(int i) { return state[i]; }
void sha_emul_set_bswap(bool b) { bswap = b; }
void sha_emul_err_clear(void)   { err = false; }
bool sha_emul_err(void)         { return err; }

RegRO::operator uint32_t() const {
    int i = (int)(this - &sha256_hw_obj.sum[0]);
    return sha_emul_sum(i);
}

// --- DMA model -------------------------------------------------------------
static uint32_t dma_count = 0;

int dma_claim_unused_channel(bool) { return 0; }
dma_channel_config dma_channel_get_default_config(uint) { dma_channel_config c{0}; return c; }
void channel_config_set_transfer_data_size(dma_channel_config *, enum_dma_transfer_size) {}
void channel_config_set_read_increment(dma_channel_config *, bool) {}
void channel_config_set_write_increment(dma_channel_config *, bool) {}
void channel_config_set_dreq(dma_channel_config *, uint) {}
void dma_channel_configure(uint, const dma_channel_config *, volatile void *,
                           const volatile void *r, uint count, bool trigger) {
    dma_count = count;
    if (trigger && r) {
        const uint32_t *p = (const uint32_t *)r;
        for (uint32_t i = 0; i < dma_count; i++) sha_emul_wdata(p[i]);
    }
}
void dma_channel_set_trans_count(uint, uint32_t count, bool) { dma_count = count; }
void dma_channel_set_read_addr(uint, const volatile void *addr, bool trigger) {
    if (trigger) {
        const uint32_t *p = (const uint32_t *)addr;
        for (uint32_t i = 0; i < dma_count; i++) sha_emul_wdata(p[i]);
    }
}
void dma_channel_wait_for_finish_blocking(uint) {}
