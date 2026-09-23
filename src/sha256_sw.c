#include "sha256_sw.h"
#include <string.h>

#ifdef PICO_ON_DEVICE
#include "pico.h"
#else
#define __not_in_flash_func(x) x
#endif

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static const uint32_t IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define S1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define s0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define s1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

void __not_in_flash_func(sha256_sw_compress_words)(uint32_t state[8], const uint32_t in[16]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = in[i];
    for (int i = 16; i < 64; i++)
        w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + S1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = S0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void compress_bytes(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[16];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
    sha256_sw_compress_words(state, w);
}

void sha256_sw_init(sha256_sw_t *c) {
    memcpy(c->state, IV, sizeof(IV));
    c->bitlen = 0;
    c->buflen = 0;
}

void sha256_sw_update(sha256_sw_t *c, const uint8_t *data, size_t len) {
    c->bitlen += (uint64_t)len * 8u;
    while (len) {
        uint32_t take = 64u - c->buflen;
        if (take > len) take = (uint32_t)len;
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        len -= take;
        if (c->buflen == 64u) {
            compress_bytes(c->state, c->buf);
            c->buflen = 0;
        }
    }
}

void sha256_sw_final(sha256_sw_t *c, uint8_t out[32]) {
    uint64_t bits = c->bitlen;
    c->buf[c->buflen++] = 0x80u;
    if (c->buflen > 56u) {
        memset(c->buf + c->buflen, 0, 64u - c->buflen);
        compress_bytes(c->state, c->buf);
        c->buflen = 0;
    }
    memset(c->buf + c->buflen, 0, 56u - c->buflen);
    for (int i = 0; i < 8; i++) c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    compress_bytes(c->state, c->buf);
    for (int i = 0; i < 8; i++) {
        out[4 * i + 0] = (uint8_t)(c->state[i] >> 24);
        out[4 * i + 1] = (uint8_t)(c->state[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->state[i] >> 8);
        out[4 * i + 3] = (uint8_t)(c->state[i]);
    }
}

void sha256_sw(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_sw_t c;
    sha256_sw_init(&c);
    sha256_sw_update(&c, data, len);
    sha256_sw_final(&c, out);
}

void __not_in_flash_func(sha256_sw_dsha80)(const uint8_t hdr[80], uint8_t out[32]) {
    uint32_t st[8], w[16];

    // --- first SHA-256 over the 80-byte header (2 blocks) ---
    memcpy(st, IV, sizeof(IV));
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)hdr[4 * i] << 24) | ((uint32_t)hdr[4 * i + 1] << 16) |
               ((uint32_t)hdr[4 * i + 2] << 8) | (uint32_t)hdr[4 * i + 3];
    sha256_sw_compress_words(st, w);

    for (int i = 0; i < 4; i++) {
        const uint8_t *p = hdr + 64 + 4 * i;
        w[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    w[4] = 0x80000000u;
    for (int i = 5; i < 15; i++) w[i] = 0;
    w[15] = 640u; // 80 bytes * 8 bits
    sha256_sw_compress_words(st, w);

    // --- second SHA-256 over the 32-byte digest (1 block) ---
    uint32_t st2[8];
    memcpy(st2, IV, sizeof(IV));
    for (int i = 0; i < 8; i++) w[i] = st[i];
    w[8] = 0x80000000u;
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 256u; // 32 bytes * 8 bits
    sha256_sw_compress_words(st2, w);

    for (int i = 0; i < 8; i++) {
        out[4 * i + 0] = (uint8_t)(st2[i] >> 24);
        out[4 * i + 1] = (uint8_t)(st2[i] >> 16);
        out[4 * i + 2] = (uint8_t)(st2[i] >> 8);
        out[4 * i + 3] = (uint8_t)(st2[i]);
    }
}
