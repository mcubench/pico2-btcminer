// Runs the real miner.c / sha256_sw.c against the emulated SHA-256 peripheral.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "miner.h"
#include "sha256_sw.h"
#include "vectors.h"

extern unsigned long emul_block_count;

static int fails = 0;
static int checks = 0;

static void check(bool ok, const char *what) {
    checks++;
    if (!ok) { fails++; printf("  FAIL: %s\n", what); }
}

static void hexstr(const uint8_t *b, int n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i] = h[b[i]>>4]; out[2*i+1] = h[b[i]&0xf]; }
    out[2*n] = 0;
}

int main(void) {
    miner_hw_init();
    printf("=== host verification of miner.c against emulated SHA-256 engine ===\n\n");

    // ---- generic SHA-256 over arbitrary lengths ----
    printf("[1] hardware-path SHA-256 vs stored NIST digests\n");
    for (int i = 0; i < N_SHA_KATS; i++) {
        uint8_t got[32], sw[32];
        hw_sha256(sha_kats[i].msg, sha_kats[i].len, got);
        sha256_sw(sha_kats[i].msg, sha_kats[i].len, sw);
        bool a = memcmp(got, sha_kats[i].digest, 32) == 0;
        bool b = memcmp(sw,  sha_kats[i].digest, 32) == 0;
        if (!a || !b) printf("    %-26s hw=%s sw=%s\n", sha_kats[i].name,
                             a?"ok":"BAD", b?"ok":"BAD");
        check(a, sha_kats[i].name);
        check(b, "software path");
    }
    printf("    %d vectors, hw and sw paths\n", N_SHA_KATS);

    // ---- streaming: one million 'a' ----
    printf("[2] streaming path, one million 'a'\n");
    {
        uint32_t blk[16], pad[16], i;
        for (i = 0; i < 16; i++) blk[i] = 0x61616161u;
        pad[0] = 0x80000000u;
        for (i = 1; i < 15; i++) pad[i] = 0;
        pad[15] = 8000000u;
        uint8_t out[32];
        hw_feed_raw_start();
        for (i = 0; i < 15625; i++) hw_feed_raw_block(blk);
        hw_feed_raw_block(pad);
        hw_feed_raw_finish(out);
        check(memcmp(out, kat_million_a, 32) == 0, "one million 'a'");
    }

    // ---- Bitcoin headers, every feed mode ----
    printf("[3] Bitcoin double-SHA256 headers, all feed modes\n");
    for (int i = 0; i < N_BTC_KATS; i++) {
        const btc_kat_t *k = &btc_kats[i];
        char want[65];
        hexstr(k->hash_disp, 32, want);

        for (int m = 0; m < FEED_COUNT; m++) {
            btc_work_t w;
            btc_work_init(&w, k->hdr);
            unsigned long before = emul_block_count;
            miner_hash_nonce(&w, k->nonce, (feed_mode_t)m);
            unsigned long used = emul_block_count - before;
            uint32_t st[8]; miner_read_state(st);
            char disp[65]; btc_hash_to_display(st, disp);
            bool ok = strcmp(disp, want) == 0;
            if (!ok) printf("    %-22s %-10s got %s\n                              want %s\n",
                            k->name, feed_mode_name[m], disp, want);
            check(ok, k->name);
            check(used == 3, "3 compressions per bitcoin hash");
        }
        // software must agree too
        uint8_t swd[32], swdisp[32];
        sha256_sw_dsha80(k->hdr, swd);
        for (int j = 0; j < 32; j++) swdisp[j] = swd[31-j];
        check(memcmp(swdisp, k->hash_disp, 32) == 0, "software dsha80");
        printf("    %-26s %s\n", k->name, want);
    }

    // ---- target maths ----
    printf("[4] compact-bits target expansion and comparison\n");
    {
        struct { uint32_t bits; const char *hex; } tv[] = {
            { 0x1d00ffffu, "00000000ffff0000000000000000000000000000000000000000000000000000" },
            { 0x1a44b9f2u, "00000000000000000044b9f20000000000000000000000000000000000000000" },
        };
        // note: second string is built below from first principles instead
        uint32_t t[8];
        btc_target_from_bits(0x1d00ffffu, t);
        check(t[7] == 0x00000000u && t[6] == 0xffff0000u, "bits 1d00ffff -> target limbs");
        btc_target_from_bits(0x1a44b9f2u, t);
        check(t[7] == 0x00000000u && t[6] == 0x000044b9u && t[5] == 0xf2000000u,
              "bits 1a44b9f2 -> target limbs");
        (void)tv;
    }

    // every real block must satisfy its own stated target
    for (int i = 0; i < 3; i++) {
        const btc_kat_t *k = &btc_kats[i];
        btc_work_t w; btc_work_init(&w, k->hdr);
        miner_hash_nonce(&w, k->nonce, FEED_CPU_FAST);
        uint32_t st[8], limbs[8], target[8];
        miner_read_state(st);
        btc_hash_limbs(st, limbs);
        btc_target_from_bits(k->bits, target);
        bool meets = btc_limbs_le(limbs, target);
        int lz = btc_leading_zero_bits(limbs);
        printf("    %-26s zeros=%2d meets target=%s\n", k->name, lz, meets ? "yes" : "NO");
        check(meets, "real block meets its own target");
        check(lz >= 32, "real block has >=32 leading zero bits");
    }

    // a nonce one off from the real one must NOT meet the target
    {
        const btc_kat_t *k = &btc_kats[0];
        btc_work_t w; btc_work_init(&w, k->hdr);
        miner_hash_nonce(&w, k->nonce - 1, FEED_CPU_FAST);
        uint32_t st[8], limbs[8], target[8];
        miner_read_state(st); btc_hash_limbs(st, limbs);
        btc_target_from_bits(k->bits, target);
        check(!btc_limbs_le(limbs, target), "wrong nonce rejected");
    }

    // ---- fast-reject word must agree with the full comparison ----
    printf("[5] fast-reject word consistency (20000 nonces)\n");
    {
        btc_work_t w; btc_work_init(&w, btc_kats[0].hdr);
        int mism = 0;
        for (uint32_t n = 0; n < 20000; n++) {
            uint32_t h7 = miner_hash_nonce(&w, n, FEED_CPU_FAST);
            uint32_t st[8], limbs[8];
            miner_read_state(st);
            btc_hash_limbs(st, limbs);
            if (limbs[7] != __builtin_bswap32(h7)) mism++;
        }
        check(mism == 0, "returned word equals most significant limb");
    }

    // ---- fuzz: all three modes vs software ----
    printf("[6] randomised cross-check, 3000 headers x 3 modes vs software\n");
    {
        uint32_t s = 0xdeadbeefu;
        int bad = 0;
        for (int i = 0; i < 3000; i++) {
            uint8_t hdr[80];
            for (int j = 0; j < 80; j++) {
                s ^= s << 13; s ^= s >> 17; s ^= s << 5;
                hdr[j] = (uint8_t)s;
            }
            uint8_t swd[32];
            sha256_sw_dsha80(hdr, swd);
            uint32_t nonce = (uint32_t)hdr[76] | ((uint32_t)hdr[77]<<8) |
                             ((uint32_t)hdr[78]<<16) | ((uint32_t)hdr[79]<<24);
            for (int m = 0; m < FEED_COUNT; m++) {
                btc_work_t w; btc_work_init(&w, hdr);
                miner_hash_nonce(&w, nonce, (feed_mode_t)m);
                uint32_t st[8]; uint8_t hwd[32];
                miner_read_state(st);
                btc_state_to_digest(st, hwd);
                if (memcmp(swd, hwd, 32) != 0) bad++;
            }
        }
        check(bad == 0, "fuzz hw vs sw");
        printf("    %s\n", bad ? "MISMATCHES" : "all 9000 comparisons identical");
    }

    // ---- nonce plumbing: changing the nonce must change the hash the same
    //      way a freshly serialised header does ----
    printf("[7] nonce injection matches full header re-serialisation\n");
    {
        uint8_t hdr[80];
        memcpy(hdr, btc_kats[2].hdr, 80);
        int bad = 0;
        for (uint32_t n = 1000; n < 1200; n++) {
            hdr[76]=(uint8_t)n; hdr[77]=(uint8_t)(n>>8);
            hdr[78]=(uint8_t)(n>>16); hdr[79]=(uint8_t)(n>>24);
            uint8_t swd[32];
            sha256_sw_dsha80(hdr, swd);
            btc_work_t w; btc_work_init(&w, btc_kats[2].hdr);
            miner_hash_nonce(&w, n, FEED_DMA);
            uint32_t st[8]; uint8_t hwd[32];
            miner_read_state(st); btc_state_to_digest(st, hwd);
            if (memcmp(swd, hwd, 32)) bad++;
        }
        check(bad == 0, "nonce word injection");
    }

    printf("\n=== %d checks, %d failures ===\n", checks, fails);
    return fails ? 1 : 0;
}
