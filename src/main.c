// ---------------------------------------------------------------------------
// Bitcoin double-SHA256 miner for the Raspberry Pi Pico 2 (RP2350),
// driving the on-chip SHA-256 hardware accelerator.
//
//   * validates the engine against NIST SHA-256 vectors and against three real
//     Bitcoin block headers before it will mine anything
//   * benchmarks hardware vs software, and CPU-fed vs DMA-fed
//   * re-mines real historical blocks to prove it is doing genuine work
//   * mines continuously against a target you choose
// ---------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "hardware/clocks.h"
#include "hardware/vreg.h"
#include "hardware/adc.h"
#include "pico/multicore.h"
#include "hardware/structs/sysinfo.h"

#include "miner.h"
#include "sha256_sw.h"
#include "vectors.h"
#include "protocol.h"
#include "led.h"

// Settle time after a clk_sys transition, before core 1 may be launched.
#ifndef CLOCK_SETTLE_MS
#define CLOCK_SETTLE_MS 25
#endif
// Extra pause between the clock being confirmed and core 1 being launched.
#ifndef C1_LAUNCH_SETTLE_MS
#define C1_LAUNCH_SETTLE_MS 10
#endif

#define VERSION "5.8"

#if defined(__riscv)
  #define ARCH_NAME  "RISC-V Hazard3"
  #define ARCH_SHORT "H3"
#else
  #define ARCH_NAME  "Arm Cortex-M33"
  #define ARCH_SHORT "M33"
#endif

static bool set_clock_quiet(uint32_t khz);   // defined below, used by mine_loop

static bool mode_ok[FEED_COUNT];
feed_mode_t best_mode = FEED_CPU_FAST;   // declared in miner.h
static double last_rate[FEED_COUNT];

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

static void hexline(const uint8_t *b, int n) {
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
}

static void print_rate(double hs) {
    // A marginal clock can corrupt a computation into NaN or Inf, and the
    // soft-float formatter will then spin for a very long time emitting
    // digits -- indistinguishable from a hang. Reject those first.
    if (hs != hs || hs < 0.0 || hs > 1e12) { printf("INVALID"); return; }
    if (hs >= 1e6) printf("%.3f MH/s", hs / 1e6);
    else if (hs >= 1e3) printf("%.1f kH/s", hs / 1e3);
    else printf("%.0f H/s", hs);
}

static double difficulty_from_bits(uint32_t bits) {
    uint32_t exp = bits >> 24;
    uint32_t mant = bits & 0x007fffffu;
    if (!mant) return 0.0;
    // ldexp() without pulling in libm: scale by powers of two directly.
    double d = 65535.0 / (double)mant;
    int e = 232 - 8 * (int)exp;
    while (e > 0) { d *= 2.0; e--; }
    while (e < 0) { d *= 0.5; e++; }
    return d;
}

static void print_duration(double sec) {
    if (sec < 1.0)          printf("%.0f ms", sec * 1e3);
    else if (sec < 90.0)    printf("%.1f s", sec);
    else if (sec < 5400.0)  printf("%.1f min", sec / 60.0);
    else if (sec < 172800.0) printf("%.1f hours", sec / 3600.0);
    else if (sec < 3.15e9)  printf("%.1f days", sec / 86400.0);
    else                    printf("%.3g years", sec / 3.15576e7);
}

// Die temperature.
//
// The temperature channel depends on the package, not on the build config:
//   QFN-60 / RP2350A: user inputs 0-3 (GPIO26-29), temperature on 4
//   QFN-80 / RP2350B: user inputs 0-7 (GPIO40-47), temperature on 8
// SYSINFO_PACKAGE_SEL reports which die this actually is, so read it at
// runtime rather than trusting a compile-time guess. ADC_TEMPERATURE_CHANNEL_NUM
// is unreliable here: it derives from NUM_ADC_CHANNELS, selected by
// "#if PICO_RP2350A" inside platform_defs.h, which includes nothing and so may
// be evaluated before the board header defines that macro.
static uint temp_channel(void) {
    return (sysinfo_hw->package_sel & SYSINFO_PACKAGE_SEL_BITS) ? 8u : 4u;
}
#define TEMP_ADC_CHANNEL temp_channel()

// Conversion from the SDK's adc.h: T = 27 - (V - 0.706)/0.001721. The sensor
// is uncalibrated, so treat absolute values as approximate -- the trend under
// load is what matters.
static uint16_t last_adc_raw = 0;

static float read_temp_c(void) {
    adc_select_input(TEMP_ADC_CHANNEL);
    uint32_t sum = 0;
    for (int i = 0; i < 16; i++) sum += adc_read();
    last_adc_raw = (uint16_t)(sum / 16u);
    if (adc_hw->cs & ADC_CS_ERR_BITS) { last_adc_raw = 0xFFFF; return -999.0f; }
    float v = (float)last_adc_raw * 3.3f / 4096.0f;
    return 27.0f - (v - 0.706f) / 0.001721f;
}

// Never print a nonsense temperature: if the reading is outside anything
// physically plausible, say so instead.
static void temp_str(char *buf, size_t n) {
    float t = read_temp_c();
    if (t > -40.0f && t < 150.0f) snprintf(buf, n, "%.0f C", (double)t);
    // Show the raw code when the reading is impossible: 0 or 4095 means the
    // mux input is not driven, anything else means the maths is wrong.
    else snprintf(buf, n, "n/a[adc%u]", (unsigned)last_adc_raw);
}

// A single known-answer check against block 125552, cheap enough to run
// inside the mining loop. This is what catches a marginal overclock: bad
// timing produces wrong hashes, not crashes.
static bool verify_vector(void) {
    const btc_kat_t *k = &btc_kats[2];
    btc_work_t w;
    btc_work_init(&w, k->hdr);
    miner_hash_nonce(&w, k->nonce, best_mode);
    uint32_t st[8];
    miner_read_state(st);
    uint8_t d[32];
    btc_state_to_digest(st, d);
    for (int j = 0; j < 32; j++) if (d[j] != k->hash_disp[31 - j]) return false;
    return !miner_hw_error();
}

// Silent version of the vector checks, for the automatic clock search.
static bool quick_validate(void) {
    miner_hw_error_clear();
    for (int i = 0; i < N_BTC_KATS; i++) {
        const btc_kat_t *k = &btc_kats[i];
        uint8_t sw[32];
        sha256_sw_dsha80(k->hdr, sw);
        for (int m = 0; m < FEED_COUNT; m++) {
            if (!mode_ok[m]) continue;
            btc_work_t w;
            btc_work_init(&w, k->hdr);
            miner_hash_nonce(&w, k->nonce, (feed_mode_t)m);
            uint32_t st[8];
            uint8_t hw[32];
            miner_read_state(st);
            btc_state_to_digest(st, hw);
            if (memcmp(sw, hw, 32) != 0) return false;
        }
    }
    return !miner_hw_error();
}

// ---------------------------------------------------------------------------
// Core 1: software miner.
//
// The SHA-256 engine cannot be shared -- there is one instance, one state, and
// START reloads the IV, so a second core issuing START mid-hash would destroy
// core 0's work. Core 1 therefore runs the pure-software path, which touches
// no peripheral at all, over a disjoint nonce range.
//
// Core 1 never prints: stdio locking across cores is a good way to deadlock.
// It publishes counters and a share mailbox; core 0 does all the reporting.
// ---------------------------------------------------------------------------

static bool dual_core = true;               // toggled with 'd'; on by default

static volatile bool     c1_run = false;    // core 0 -> core 1: mine
static volatile uint32_t c1_chunks = 0;     // core 1 -> core 0: units of 100 hashes
static volatile uint32_t c1_nonce_start = 0;
static volatile uint8_t  c1_hdr[80];
static volatile uint32_t c1_target[8];
static volatile bool     c1_share = false;
static volatile bool     c1_alive = false;   // core 1 -> core 0: entry running
static volatile uint32_t c1_share_nonce = 0;

// Bitcoin reads the digest as a little-endian 256-bit integer, so each limb is
// simply a little-endian read of four digest bytes.
static inline void digest_limbs(const uint8_t d[32], uint32_t limbs[8]) {
    for (int i = 0; i < 8; i++)
        limbs[i] = (uint32_t)d[4*i] | ((uint32_t)d[4*i+1] << 8) |
                   ((uint32_t)d[4*i+2] << 16) | ((uint32_t)d[4*i+3] << 24);
}

static void core1_entry(void) {
    c1_alive = true;
    // Launched with c1_run already true, so there is no handshake to miss.
    // Returns when told to stop, which halts core 1 -- no idle spinning and no
    // reliance on __wfe/__sev (which on RISC-V is Hazard3 block/unblock).
    uint8_t  hdr[80];
    uint32_t tgt[8];
    for (int i = 0; i < 80; i++) hdr[i] = c1_hdr[i];
    for (int i = 0; i < 8; i++)  tgt[i] = c1_target[i];
    uint32_t nonce = c1_nonce_start;

    while (c1_run) {
        for (int i = 0; i < 100; i++) {
            hdr[76] = (uint8_t)nonce;         hdr[77] = (uint8_t)(nonce >> 8);
            hdr[78] = (uint8_t)(nonce >> 16); hdr[79] = (uint8_t)(nonce >> 24);
            uint8_t d[32];
            sha256_sw_dsha80(hdr, d);
            uint32_t limb7 = (uint32_t)d[28] | ((uint32_t)d[29] << 8) |
                             ((uint32_t)d[30] << 16) | ((uint32_t)d[31] << 24);
            if (limb7 <= tgt[7]) {
                uint32_t limbs[8];
                digest_limbs(d, limbs);
                if (btc_limbs_le(limbs, tgt) && !c1_share) {
                    c1_share_nonce = nonce;
                    c1_share = true;
                }
            }
            nonce++;
        }
        c1_chunks++;   // units of 100 hashes; 32-bit, atomic on both cores
    }
    c1_alive = false;   // tell core 0 it is safe to reset us
}

// Returns false if core 1 never started. A late launch must not be reported as
// a genuine (terrible) hash rate -- at marginal clocks the inter-core handshake
// itself becomes unreliable, which is worth surfacing rather than averaging in.
static bool c1_start(const uint8_t hdr[80], const uint32_t target[8], uint32_t nonce_base) {
    c1_run = false;
    multicore_reset_core1();
    for (int i = 0; i < 80; i++) c1_hdr[i] = hdr[i];
    for (int i = 0; i < 8; i++)  c1_target[i] = target[i];
    c1_nonce_start = nonce_base;
    c1_share = false;
    c1_chunks = 0;
    // The clock transition has completed and been verified by now; give the
    // rails a further moment before the FIFO handshake, which is the first
    // thing to fail when the core is near its limit.
    sleep_ms(C1_LAUNCH_SETTLE_MS);
    for (int attempt = 0; attempt < 2; attempt++) {
        c1_run = true;                   // set BEFORE launch
        c1_alive = false;
        multicore_launch_core1(core1_entry);
        // Caller starts timing as soon as this returns, so core 1 must already
        // be executing or the measurement window is wrong.
        uint64_t t = time_us_64();
        while (!c1_alive && time_us_64() - t < 300000ull) tight_loop_contents();
        if (c1_alive) return true;
        c1_run = false;
        multicore_reset_core1();
        sleep_ms(2);
    }
    return false;
}

// Bring core 1 to a full stop and hold it in reset. Setting c1_run alone is
// not enough: the worker only tests it between 100-hash blocks, so the core can
// still be executing when the caller proceeds. Retuning clk_sys underneath a
// running core 1 is exactly the condition that makes the inter-core FIFO the
// first thing to fail at the overclocked edge.
static void c1_quiesce(void) {
    c1_run = false;
    uint64_t t = time_us_64();
    while (c1_alive && time_us_64() - t < 200000ull) tight_loop_contents();
    multicore_reset_core1();
}

static void c1_stop(void) {
    c1_run = false;
    // Wait for core 1 to leave its loop rather than guessing at a delay. The
    // inner block is 100 software hashes -- ~2 ms at 480 MHz but ~7 ms at
    // 150 MHz -- so a fixed sleep reset the core mid-execution and left the
    // inter-core FIFO in a state that made the next launch unreliable.
    uint64_t t = time_us_64();
    while (c1_alive && time_us_64() - t < 200000ull) tight_loop_contents();
    multicore_reset_core1();
    sleep_ms(1);
}

// ---------------------------------------------------------------------------
// self test
// ---------------------------------------------------------------------------

static bool test_generic_sha256(void) {
    bool ok = true;
    printf("\n  NIST / RFC SHA-256 vectors (hardware engine, arbitrary lengths)\n");
    for (int i = 0; i < N_SHA_KATS; i++) {
        uint8_t got[32], sw[32];
        hw_sha256(sha_kats[i].msg, sha_kats[i].len, got);
        sha256_sw(sha_kats[i].msg, sha_kats[i].len, sw);
        bool a = memcmp(got, sha_kats[i].digest, 32) == 0;
        bool b = memcmp(sw, sha_kats[i].digest, 32) == 0;
        printf("    [%s] %-24s len=%-7u", a && b ? "PASS" : "FAIL",
               sha_kats[i].name, (unsigned)sha_kats[i].len);
        if (a && b) {
            printf(" ");
            hexline(got, 8);
            printf("...\n");
        } else {
            printf("\n           hw="); hexline(got, 32);
            printf("\n           sw="); hexline(sw, 32);
            printf("\n           ex="); hexline(sha_kats[i].digest, 32);
            printf("\n");
            ok = false;
        }
    }

    // One million 'a': exactly 15625 blocks plus a padding block. Fed straight
    // into the engine so we never need a megabyte of RAM.
    {
        uint32_t blk[16], pad[16];
        for (int i = 0; i < 16; i++) blk[i] = 0x61616161u; // "aaaa"
        pad[0] = 0x80000000u;
        for (int i = 1; i < 15; i++) pad[i] = 0;
        pad[15] = 8000000u; // 1e6 bytes * 8
        uint8_t out[32];

        miner_hw_error_clear();
        hw_feed_raw_start();
        for (int i = 0; i < 15625; i++) hw_feed_raw_block(blk);
        hw_feed_raw_block(pad);
        hw_feed_raw_finish(out);

        bool a = memcmp(out, kat_million_a, 32) == 0;
        printf("    [%s] %-24s len=%-7u ", a ? "PASS" : "FAIL", "one million 'a'", 1000000u);
        hexline(out, 8);
        printf("...\n");
        if (!a) ok = false;
    }
    return ok;
}

static bool test_bitcoin_vectors(void) {
    bool ok = true;
    printf("\n  Bitcoin block headers -- double SHA-256, all three feed modes\n");

    for (int m = 0; m < FEED_COUNT; m++) mode_ok[m] = true;

    for (int i = 0; i < N_BTC_KATS; i++) {
        const btc_kat_t *k = &btc_kats[i];
        btc_work_t w;
        uint8_t swd[32], swdisp[32];

        sha256_sw_dsha80(k->hdr, swd);
        for (int j = 0; j < 32; j++) swdisp[j] = swd[31 - j];
        bool sw_ok = memcmp(swdisp, k->hash_disp, 32) == 0;

        printf("    %-26s", k->name);
        for (int m = 0; m < FEED_COUNT; m++) {
            btc_work_init(&w, k->hdr);
            miner_hw_error_clear();
            miner_hash_nonce(&w, k->nonce, (feed_mode_t)m);
            uint32_t st[8];
            miner_read_state(st);
            char disp[65];
            btc_hash_to_display(st, disp);

            char want[65];
            for (int j = 0; j < 32; j++) {
                static const char hex[] = "0123456789abcdef";
                want[2 * j] = hex[k->hash_disp[j] >> 4];
                want[2 * j + 1] = hex[k->hash_disp[j] & 0xf];
            }
            want[64] = 0;

            bool good = (strcmp(disp, want) == 0) && !miner_hw_error();
            if (!good) { mode_ok[m] = false; ok = false; }
            printf(" %s:%s", feed_mode_name[m], good ? "ok" : "BAD");
        }
        printf(" sw:%s\n", sw_ok ? "ok" : "BAD");
        if (!sw_ok) ok = false;

        // Show the hash, and confirm it really satisfies the block's own target.
        btc_work_init(&w, k->hdr);
        miner_hash_nonce(&w, k->nonce, FEED_CPU_FAST);
        uint32_t st[8], limbs[8], target[8];
        miner_read_state(st);
        btc_hash_limbs(st, limbs);
        btc_target_from_bits(k->bits, target);
        char disp[65];
        btc_hash_to_display(st, disp);
        printf("        %s\n", disp);
        if (!btc_bits_valid(k->bits)) {
            printf("        random test header -- hash correctness only, its "
                   "'bits' field is not a\n        valid difficulty encoding\n");
        } else {
            bool meets = btc_limbs_le(limbs, target);
            printf("        nonce %10u  bits %08x  difficulty %.2f  "
                   "leading zero bits %d  meets target: %s\n",
                   (unsigned)k->nonce, (unsigned)k->bits,
                   difficulty_from_bits(k->bits),
                   btc_leading_zero_bits(limbs), meets ? "YES" : "no");
        }
    }
    return ok;
}

// Random-ish headers, hardware vs software, to catch anything the fixed
// vectors would miss.
static bool test_fuzz(int n) {
    printf("\n  Randomised cross-check, hardware vs software (%d headers)\n", n);
    uint32_t s = 0x1234567u;
    int bad = 0;
    for (int i = 0; i < n; i++) {
        uint8_t hdr[80];
        for (int j = 0; j < 80; j++) {
            s ^= s << 13; s ^= s >> 17; s ^= s << 5;
            hdr[j] = (uint8_t)s;
        }
        uint8_t swd[32], hwd[32];
        sha256_sw_dsha80(hdr, swd);

        btc_work_t w;
        btc_work_init(&w, hdr);
        uint32_t nonce = ((uint32_t)hdr[76]) | ((uint32_t)hdr[77] << 8) |
                         ((uint32_t)hdr[78] << 16) | ((uint32_t)hdr[79] << 24);
        feed_mode_t m = (feed_mode_t)(i % FEED_COUNT);
        miner_hash_nonce(&w, nonce, m);
        uint32_t st[8];
        miner_read_state(st);
        btc_state_to_digest(st, hwd);
        if (memcmp(swd, hwd, 32) != 0) { bad++; mode_ok[m] = false; }
    }
    printf("    [%s] %d/%d matched\n", bad ? "FAIL" : "PASS", n - bad, n);
    return bad == 0;
}

static bool run_selftest(bool verbose) {
    if (!verbose) {
        // Quiet boot path: run every check, print only the verdict. The full
        // report is ~45 lines, and dumping that into a CDC endpoint Windows is
        // still binding is the most likely cause of enumeration failures.
        miner_hw_error_clear();
        bool qa = true;
        for (int i = 0; i < N_SHA_KATS; i++) {
            uint8_t got[32];
            hw_sha256(sha_kats[i].msg, sha_kats[i].len, got);
            if (memcmp(got, sha_kats[i].digest, 32)) qa = false;
        }
        for (int m = 0; m < FEED_COUNT; m++) mode_ok[m] = true;
        bool qb = true;
        for (int i = 0; i < N_BTC_KATS; i++) {
            const btc_kat_t *k = &btc_kats[i];
            uint8_t sw[32];
            sha256_sw_dsha80(k->hdr, sw);
            for (int m = 0; m < FEED_COUNT; m++) {
                btc_work_t w;
                btc_work_init(&w, k->hdr);
                miner_hash_nonce(&w, k->nonce, (feed_mode_t)m);
                uint32_t st[8]; uint8_t hw[32];
                miner_read_state(st);
                btc_state_to_digest(st, hw);
                if (memcmp(sw, hw, 32)) { mode_ok[m] = false; qb = false; }
            }
        }
        best_mode = FEED_COUNT;
        for (int m = 0; m < FEED_COUNT; m++)
            if (mode_ok[m] && best_mode == FEED_COUNT) best_mode = (feed_mode_t)m;
        if (best_mode == FEED_COUNT) best_mode = FEED_CPU_SAFE;
        printf(" Self test: %s (%d SHA vectors, %d block headers, all feed modes)\n",
               (qa && qb) ? "PASSED" : "*** FAILED -- press t for detail ***",
               N_SHA_KATS, N_BTC_KATS);
        return qa && qb;
    }
    printf("\n=== SELF TEST ===  v%s, %s\n", VERSION, ARCH_NAME);
    miner_hw_error_clear();
    bool a = test_generic_sha256();
    bool b = test_bitcoin_vectors();
    bool c = test_fuzz(512);

    printf("\n  Feed modes usable:");
    best_mode = FEED_COUNT;
    for (int m = 0; m < FEED_COUNT; m++) {
        printf(" %s=%s", feed_mode_name[m], mode_ok[m] ? "yes" : "NO");
        if (mode_ok[m] && best_mode == FEED_COUNT) best_mode = (feed_mode_t)m;
    }
    if (best_mode == FEED_COUNT) best_mode = FEED_CPU_SAFE;
    printf("\n");

    bool all = a && b && c;
    printf("\n  RESULT: %s\n", all ? "ALL TESTS PASSED" : "*** FAILURES -- see above ***");
    return all;
}

// ---------------------------------------------------------------------------
// benchmark
// ---------------------------------------------------------------------------

static double bench_mode(feed_mode_t m, uint32_t iters) {
    btc_work_t w;
    btc_work_init(&w, btc_kats[0].hdr);
    // warm up
    for (uint32_t i = 0; i < 1000; i++) miner_hash_nonce(&w, i, m);
    uint64_t t0 = time_us_64();
    uint32_t acc = 0;
    for (uint32_t i = 0; i < iters; i++) acc += miner_hash_nonce(&w, i, m);
    uint64_t t1 = time_us_64();
    (void)acc;
    double sec = (double)(t1 - t0) / 1e6;
    return (double)iters / sec;
}

static double bench_software(uint32_t iters) {
    uint8_t hdr[80], out[32];
    memcpy(hdr, btc_kats[0].hdr, 80);
    uint64_t t0 = time_us_64();
    for (uint32_t i = 0; i < iters; i++) {
        hdr[76] = (uint8_t)i; hdr[77] = (uint8_t)(i >> 8);
        hdr[78] = (uint8_t)(i >> 16); hdr[79] = (uint8_t)(i >> 24);
        sha256_sw_dsha80(hdr, out);
    }
    uint64_t t1 = time_us_64();
    return (double)iters / ((double)(t1 - t0) / 1e6);
}

static void run_benchmark(void) {
    uint32_t f = clock_get_hz(clk_sys);
    printf("\n=== BENCHMARK ===  v%s, %s, clk_sys = %u.%01u MHz\n", VERSION, ARCH_NAME,
           (unsigned)(f / 1000000u), (unsigned)((f / 100000u) % 10u));
    printf("  One Bitcoin hash = 3 SHA-256 compressions on this chip.\n");
    printf("  (The engine reloads the IV on every START, so there is no way to\n");
    printf("   cache a midstate for header block 0 -- it is 3 blocks, not 2.)\n\n");

    printf("  %-12s %14s %14s %14s\n", "mode", "hashes/s", "cycles/hash", "cycles/block");
    double best = 0;
    for (int m = 0; m < FEED_COUNT; m++) {
        if (!mode_ok[m]) { printf("  %-12s %14s\n", feed_mode_name[m], "(failed test)"); continue; }
        double hs = bench_mode((feed_mode_t)m, 200000);
        last_rate[m] = hs;
        double cph = (double)f / hs;
        printf("  %-12s %14.0f %14.1f %14.1f\n", feed_mode_name[m], hs, cph, cph / 3.0);
        if (hs > best) { best = hs; best_mode = (feed_mode_t)m; }
    }

    double sw = bench_software(20000);
    printf("  %-12s %14.0f %14.1f %14.1f\n", "software", sw, (double)f / sw, (double)f / sw / 3.0);

    if (best <= 0.0) {
        printf("\n  No feed mode passed the self test -- the hardware engine is not\n");
        printf("  usable, so there is nothing to compare against. Run 't' for detail.\n");
        return;
    }

    printf("\n  Hardware speedup over software: %.1fx\n", best / sw);
    printf("  Engine floor is 57 cycles/block -> %.0f H/s at this clock.\n",
           (double)f / (3.0 * 57.0));
    printf("  Achieved %.0f%% of that ceiling.\n", 100.0 * best / ((double)f / 171.0));

    if (dual_core) {
        uint32_t all_ones[8];
        for (int i = 0; i < 8; i++) all_ones[i] = 0xffffffffu;  // count, never "win"
        bool started = c1_start(btc_kats[0].hdr, all_ones, 0x80000000u);
        uint64_t t0 = time_us_64();
        double hw_with = bench_mode(best_mode, 200000);
        uint32_t chunks = c1_chunks;
        double window = (double)(time_us_64() - t0) / 1e6;
        c1_stop();
        double sw1 = (double)chunks * 100.0 / window;

        printf("\n  Dual core (core 1 running the software miner):\n");
        printf("    %-24s %10.0f H/s\n", "hardware alone", best);
        printf("    %-24s %10.0f H/s  (%+.1f%% from contention)\n",
               "hardware + core 1", hw_with, 100.0 * (hw_with - best) / best);
        printf("    %-24s %10.0f H/s\n", "core 1 software", sw1);
        printf("    %-24s %10.0f H/s  (%+.1f%% overall)\n", "combined",
               hw_with + sw1, 100.0 * (hw_with + sw1 - best) / best);
        if (!started)
            printf("    *** core 1 failed to launch -- the clock is marginal. ***\n");
        else if (chunks == 0)
            printf("    *** core 1 produced NO hashes -- it never ran. ***\n");
        else if (hw_with + sw1 < best)
            printf("    Net loss -- core 1 costs more in contention than it adds.\n");
    }

    printf("\n  Fastest mode: %s at ", feed_mode_name[best_mode]);
    print_rate(best);
    printf("\n\n  Expected time to solve one block at:\n");
    struct { const char *what; uint32_t bits; } d[] = {
        { "difficulty 1 (2009, block 0)", 0x1d00ffffu },
        { "difficulty 244k (2011, block 125552)", 0x1a44b9f2u },
    };
    for (unsigned i = 0; i < sizeof(d) / sizeof(d[0]); i++) {
        double diff = difficulty_from_bits(d[i].bits);
        printf("    %-38s ", d[i].what);
        print_duration(diff * 4294967296.0 / best);
        printf("\n");
    }
    printf("\n  For scale: modern Bitcoin difficulty is above 1e14, which puts a\n");
    printf("  solo block far beyond the age of the universe. This is a hardware\n");
    printf("  demo and a SHA-256 benchmark, not a way to earn anything.\n");
}

// ---------------------------------------------------------------------------
// re-mine a real block
// ---------------------------------------------------------------------------

static void remine(int idx, uint32_t window) {
    const btc_kat_t *k = &btc_kats[idx];
    btc_work_t w;
    btc_work_init(&w, k->hdr);

    uint32_t target[8];
    btc_target_from_bits(k->bits, target);
    uint32_t t7 = target[7];

    uint32_t start = k->nonce - window;
    printf("\n=== RE-MINING %s ===\n", k->name);
    printf("  Everything in the header is fixed except the nonce. Searching\n");
    printf("  forward from %u for a nonce whose hash beats the block's own\n", (unsigned)start);
    printf("  target (bits %08x, difficulty %.2f).\n",
           (unsigned)k->bits, difficulty_from_bits(k->bits));
    printf("  The answer the network found in %s was %u.\n\n",
           idx == 0 ? "2009" : "its day", (unsigned)k->nonce);

    uint64_t t0 = time_us_64();
    uint32_t nonce = start;
    uint32_t tried = 0;
    bool found = false;
    uint32_t found_nonce = 0;
    uint32_t st[8];

    while (tried <= window + 16) {
        uint32_t h7 = miner_hash_nonce(&w, nonce, best_mode);
        tried++;
        if (__builtin_bswap32(h7) <= t7) {
            uint32_t s[8], limbs[8];
            miner_read_state(s);
            btc_hash_limbs(s, limbs);
            if (btc_limbs_le(limbs, target)) {
                found = true; found_nonce = nonce;
                memcpy(st, s, sizeof(st));
                break;
            }
        }
        nonce++;
    }
    uint64_t t1 = time_us_64();
    double sec = (double)(t1 - t0) / 1e6;

    if (found) {
        char disp[65];
        btc_hash_to_display(st, disp);
        printf("  SOLVED after %u hashes in %.3f s (", (unsigned)tried, sec);
        print_rate((double)tried / sec);
        printf(")\n");
        printf("  nonce %u  %s\n", (unsigned)found_nonce, found_nonce == k->nonce ? "(matches the real block)" : "(!! different nonce !!)");
        printf("  hash  %s\n", disp);
        char want[65];
        static const char hex[] = "0123456789abcdef";
        for (int j = 0; j < 32; j++) {
            want[2 * j] = hex[k->hash_disp[j] >> 4];
            want[2 * j + 1] = hex[k->hash_disp[j] & 0xf];
        }
        want[64] = 0;
        printf("  real  %s  -> %s\n", want, strcmp(want, disp) == 0 ? "IDENTICAL" : "MISMATCH");
    } else {
        printf("  not found in %u hashes (%.3f s)\n", (unsigned)tried, sec);
    }
}

// ---------------------------------------------------------------------------
// continuous mining
// ---------------------------------------------------------------------------

static void mine_loop(int zero_bits) {
    btc_work_t w;
    uint8_t hdr[80];
    // A synthetic header: real structure, arbitrary contents. Chained onto the
    // genesis hash so it at least looks like a plausible block.
    memcpy(hdr, btc_kats[0].hdr, 80);
    hdr[0] = 0x00; hdr[1] = 0x00; hdr[2] = 0x00; hdr[3] = 0x20; // version 0x20000000
    btc_work_init(&w, hdr);

    uint32_t target[8];
    memset(target, 0, sizeof(target));
    // target = 2^(256 - zero_bits) - 1
    int rem = 256 - zero_bits;
    for (int i = 0; i < 8; i++) {
        int lo = i * 32;
        if (rem >= lo + 32) target[i] = 0xffffffffu;
        else if (rem > lo) target[i] = (uint32_t)((1ull << (rem - lo)) - 1ull);
        else target[i] = 0;
    }
    uint32_t t7 = target[7];

    printf("\n=== MINING ===  target: %d leading zero bits", zero_bits);
    printf("  (1 share per 2^%d hashes)\n", zero_bits);
    printf("  Mode %s. Press any key to stop.\n", feed_mode_name[best_mode]);
    printf("  BOOT clk_sys=%u MHz arch=%s\n",
           (unsigned)(clock_get_hz(clk_sys) / 1000000u), ARCH_NAME);
    stdio_flush();

    // Core 1 is launched last, deliberately. The clock transition has already
    // completed and been verified, and this telemetry has already been emitted,
    // so the inter-core FIFO handshake never races an unsettled clock or
    // competes with the USB stack draining the boot output. The handshake is
    // the first thing to fail at the overclocked edge, so giving it the
    // quietest possible moment is what buys headroom.
    if (dual_core) {
        // core 0 takes the bottom half of the nonce space, core 1 the top
        if (c1_start(hdr, target, 0x80000000u))
            printf("  core 1 software worker running (top half of nonce space)\n\n");
        else
            printf("  WARNING: core 1 failed to launch; mining on core 0 only.\n\n");
    } else {
        printf("\n");
    }

    uint64_t t0 = time_us_64(), tlast = t0;
    uint64_t total = 0, since = 0;
    uint32_t shares = 0;
    uint32_t nonce = 0;
    uint32_t best_limb7 = 0xffffffffu;
    int best_zeros = 0;
    char best_hash[65] = "";
    uint32_t extranonce = 0;

    const uint32_t CHUNK = 20000;
    for (;;) {
        for (uint32_t i = 0; i < CHUNK; i++) {
            uint32_t h7 = miner_hash_nonce(&w, nonce, best_mode);
            uint32_t limb7 = __builtin_bswap32(h7);
            if (limb7 <= t7) {
                uint32_t s[8], limbs[8];
                miner_read_state(s);
                btc_hash_limbs(s, limbs);
                if (btc_limbs_le(limbs, target)) {
                    char disp[65];
                    btc_hash_to_display(s, disp);
                    shares++;
                    led_activity();
                    printf("  SHARE #%u  nonce=%10u  zeros=%2d  %s\n",
                           (unsigned)shares, (unsigned)nonce,
                           btc_leading_zero_bits(limbs), disp);
                }
            }
            if (limb7 < best_limb7) {
                uint32_t s[8], limbs[8];
                miner_read_state(s);
                btc_hash_limbs(s, limbs);
                best_limb7 = limb7;
                best_zeros = btc_leading_zero_bits(limbs);
                btc_hash_to_display(s, best_hash);
            }
            if (++nonce == 0) {
                // nonce space exhausted -- roll the extra nonce, as a real
                // miner rolls the coinbase, and keep going
                extranonce++;
                w.blk[9] = extranonce;
            }
        }
        led_service();
        total += CHUNK;
        since += CHUNK;

        if (dual_core) {
            uint32_t ch = c1_chunks;
            total += (uint64_t)ch * 100ull;
            since += (uint64_t)ch * 100ull;
            c1_chunks = 0;
            if (c1_share) {
                shares++;
                printf("  SHARE #%u  nonce=%10u  (core 1, software)\n",
                       (unsigned)shares, (unsigned)c1_share_nonce);
                c1_share = false;
            }
        }

        // Catch a marginal overclock that has started producing wrong hashes.
        if (!verify_vector()) {
            { char tb[16]; temp_str(tb, sizeof(tb));
              printf("\n  *** HASH CORRUPTION DETECTED (die %s) ***\n", tb); }
            printf("  The engine stopped reproducing a known block hash. The clock\n");
            printf("  is too high for this die at this temperature. Dropping to 150 MHz.\n");
            set_clock_quiet(150000);
            break;
        }

        uint64_t now = time_us_64();
        if (now - tlast >= 2000000ull) {
            double inst = (double)since / ((double)(now - tlast) / 1e6);
            double avg = (double)total / ((double)(now - t0) / 1e6);
            printf("  %8.1f s | ", (double)(now - t0) / 1e6);
            print_rate(inst);
            printf(" now, ");
            print_rate(avg);
            printf(" avg | %llu hashes | %u shares | best %d zero bits\n",
                   (unsigned long long)total, (unsigned)shares, best_zeros);
            tlast = now; since = 0;
        }

        int c = getchar_timeout_us(0);
        if (c != PICO_ERROR_TIMEOUT) break;
    }

    if (dual_core) c1_stop();
    double sec = (double)(time_us_64() - t0) / 1e6;
    printf("\n  Stopped. %llu hashes in %.1f s = ", (unsigned long long)total, sec);
    print_rate((double)total / sec);
    printf("\n  %u shares. Best hash seen (%d leading zero bits):\n  %s\n",
           (unsigned)shares, best_zeros, best_hash);
}

// ---------------------------------------------------------------------------
// btcminer-mcu protocol mode
// ---------------------------------------------------------------------------

static int dev_get_byte(void *ctx, uint32_t timeout_us) {
    (void)ctx;
    int c = getchar_timeout_us(timeout_us);
    return (c == PICO_ERROR_TIMEOUT) ? -1 : c;
}

static void dev_put_bytes(void *ctx, const uint8_t *b, size_t n) {
    (void)ctx;
    // One call, not one per byte: stdio_usb_out_chars() takes a mutex, runs
    // tud_task() and flushes each time it is entered. It already flushes, so
    // no stdio_flush() is needed either.
    stdio_put_string((const char *)b, (int)n, false, false);
}

static void enter_protocol_mode(void) {
    // From here the port carries binary frames only -- nothing else may print.
    // CRLF translation would corrupt any nonce byte equal to 0x0A.
    stdio_set_translate_crlf(&stdio_usb, false);
#if !PICO_NO_UART_STDIO
    stdio_set_translate_crlf(&stdio_uart, false);
#endif
    static const proto_io_t io = {
        .get_byte = dev_get_byte, .put_bytes = dev_put_bytes, .ctx = NULL
    };
    proto_run(&io);   // never returns
}

// ---------------------------------------------------------------------------
// clock control
// ---------------------------------------------------------------------------

// Hard ceiling. Going past 1.30 V needs vreg_disable_voltage_limit(), which
// the SDK itself describes as beyond the safe range of operation. Not offered.
#define MAX_KHZ 606000u   // hard PLL ceiling off a 12 MHz crystal

// Every step here has an exact PLL solution off the 12 MHz crystal.
// 350 MHz deliberately absent: 350*2 = 700 is below the 750 MHz VCO minimum
// and 350*3 = 1050 is not a multiple of 12, so no solution exists and
// set_sys_clock_khz would simply refuse.
// The PLL grid above 400 MHz is 4 MHz (VCO must be a multiple of 12 MHz and
// postdiv is 3), so these are the finest steps available through the edge.
// Full 4 MHz PLL grid from 440 up -- that is as fine as the hardware allows
// (VCO must be a multiple of 12 MHz with postdiv 3).
static const uint32_t clock_steps[] = {
    150000, 200000, 250000, 300000, 400000, 420000,
    440000, 444000, 448000, 452000, 456000, 460000,
    464000, 468000, 472000, 476000, 480000, 484000,
    488000, 492000, 496000, 500000, 504000, 508000,
    512000, 516000, 520000, 524000, 528000, 532000,
    534000, 540000, 546000, 552000, 558000, 564000,
    570000, 576000, 582000, 588000, 594000, 600000,
    606000
};
// 0 = no direct key; reachable via the sweep or the 'c' custom entry.
static const char clock_keys[] = {
    'q', 'w', 'e', 'r', 'u', 'i',
    'o',   0,   0,   0,   0, 'j',
      0,   0,   0,   0, 'k',   0,
      0,   0,   0, 'l',   0,   0,
      0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,
      0
};
static const char clock_digits[] = {
    '1', '2', '3', '4', '5', '6',
    '7',   0,   0,   0,   0, '8',
      0,   0,   0,   0, '9',   0,
      0,   0,   0, '0',   0,   0,
      0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,
      0
};
#define N_CLOCK_STEPS (sizeof(clock_steps) / sizeof(clock_steps[0]))

// Opt-in for core voltages past VREG_VOLTAGE_MAX (1.30 V). Off by default and
// requires an explicit confirmation, because this is the point where the risk
// stops being "it might crash" and starts being "it ages the silicon".
static bool ext_voltage = false;

// Upper bound for the sweep. Set with 'x'. Lets you explore a range without
// the final step disconnecting the device and wedging the host USB port.
static uint32_t sweep_top_khz = MAX_KHZ;

static enum vreg_voltage voltage_for(uint32_t khz) {
    if (khz <= 150000) return VREG_VOLTAGE_1_10;   // stock
    if (khz <= 200000) return VREG_VOLTAGE_1_15;
    if (khz <= 300000) return VREG_VOLTAGE_1_20;
    if (khz <= 400000) return VREG_VOLTAGE_1_30;   // SDK maximum
    if (!ext_voltage)  return VREG_VOLTAGE_1_30;
    if (khz <= 460000) return VREG_VOLTAGE_1_35;                     // ext only
    if (khz <= 500000) return VREG_VOLTAGE_1_40;
    return VREG_VOLTAGE_1_50;
}

// Manual override, 0 = follow the table. Lets you raise voltage BEFORE
// attempting a clock, which is the only thing that helps against a hang --
// a hang cannot trigger the sweep's after-the-fact retry.
static enum vreg_voltage manual_vreg = (enum vreg_voltage)0;

static enum vreg_voltage next_voltage(enum vreg_voltage v) {
    // Encodings 1.10 .. 1.60 are consecutive, so stepping is just +1.
    // Note there is no 1.45 V: the ladder is 1.35, 1.40, 1.50, 1.60.
    return (v >= VREG_VOLTAGE_1_60) ? v : (enum vreg_voltage)((int)v + 1);
}

static const char *voltage_label(enum vreg_voltage v) {
    switch (v) {
        case VREG_VOLTAGE_1_10: return "1.10";
        case VREG_VOLTAGE_1_15: return "1.15";
        case VREG_VOLTAGE_1_20: return "1.20";
        case VREG_VOLTAGE_1_25: return "1.25";
        case VREG_VOLTAGE_1_30: return "1.30";
        case VREG_VOLTAGE_1_35: return "1.35";
        case VREG_VOLTAGE_1_40: return "1.40";
        case VREG_VOLTAGE_1_50: return "1.50";
        case VREG_VOLTAGE_1_60: return "1.60";
        default:                return "?";
    }
}

static enum vreg_voltage cur_vreg = VREG_VOLTAGE_1_10;

static bool set_clock_v(uint32_t khz, enum vreg_voltage want) {
    if (khz > MAX_KHZ) return false;
    c1_quiesce();     // never retune the clock underneath a running core 1
    if (want > VREG_VOLTAGE_MAX) vreg_disable_voltage_limit();
    if (want > cur_vreg) { vreg_set_voltage(want); cur_vreg = want; sleep_ms(20); }
    bool ok = set_sys_clock_khz(khz, false);
    // Let the PLL and the regulator settle before anything else runs, and
    // confirm the transition actually landed. Core 1 is only launched after
    // this returns, so its handshake never races an unsettled clock.
    sleep_ms(CLOCK_SETTLE_MS);
    if (ok && clock_get_hz(clk_sys) != (uint32_t)khz * 1000u) ok = false;
    // Keep the peripheral clock on the USB PLL rather than letting it follow
    // clk_sys. At 500 MHz a clk_sys-derived clk_peri is far outside what the
    // UART is specified for; this decouples the console from the overclock.
    clock_configure(clk_peri, 0, CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_USB,
                    48 * MHZ, 48 * MHZ);
    setup_default_uart();
    if (ok && want < cur_vreg) { vreg_set_voltage(want); cur_vreg = want; sleep_ms(5); }
    return ok;
}

static enum vreg_voltage effective_voltage(uint32_t khz) {
    enum vreg_voltage v = voltage_for(khz);
    if (manual_vreg && manual_vreg > v) v = manual_vreg;
    enum vreg_voltage cap = ext_voltage ? VREG_VOLTAGE_1_60 : VREG_VOLTAGE_MAX;
    if (v > cap) v = cap;
    return v;
}

static bool set_clock_quiet(uint32_t khz) {
    return set_clock_v(khz, effective_voltage(khz));
}

// Sustained validation. Timing margin shrinks as the die warms, so a clock
// that passes cold can start corrupting minutes later -- this keeps checking.
static bool stress(int seconds, bool verbose) {
    btc_work_t w;
    btc_work_init(&w, btc_kats[0].hdr);
    uint64_t t0 = time_us_64(), tlast = t0;
    uint64_t hashes = 0, checks = 0;
    uint32_t nonce = 0;
    bool ok = true;
    while ((int)((time_us_64() - t0) / 1000000ull) < seconds) {
        for (uint32_t i = 0; i < 50000; i++) miner_hash_nonce(&w, nonce++, best_mode);
        hashes += 50000;
        checks++;
        if (!verify_vector()) { ok = false; break; }
        uint64_t now = time_us_64();
        if (verbose && now - tlast >= 2000000ull) {
            char tb[16]; temp_str(tb, sizeof(tb));
            printf("    %4.0f s  %8s  %llu hashes, %llu checks, all good\n",
                   (double)(now - t0) / 1e6, tb,
                   (unsigned long long)hashes, (unsigned long long)checks);
            tlast = now;
        }
    }
    if (verbose) {
        char tb[16]; temp_str(tb, sizeof(tb));
        double secs = (double)(time_us_64() - t0) / 1e6;
        if (ok) printf("    STABLE: %llu hashes in %.1f s (%.0f H/s), %llu known-answer\n"
                       "    checks, 0 errors, %s\n",
                       (unsigned long long)hashes, secs, (double)hashes / secs,
                       (unsigned long long)checks, tb);
        else    printf("    *** CORRUPTION after %llu hashes (%s) -- clock too high ***\n",
                       (unsigned long long)hashes, tb);
    }
    return ok;
}

static void set_clock(uint32_t khz) {
    if (!set_clock_quiet(khz)) {
        // The PLL needs VCO = fbdiv * 12 MHz within 750..1600 MHz, divided by
        // postdiv1*postdiv2. Most frequencies have no exact solution, so say
        // which nearby ones do rather than just refusing.
        printf("\n  %u MHz has no exact PLL solution off the 12 MHz crystal.\n",
               (unsigned)(khz / 1000));
        uint vco, p1, p2;
        uint32_t lo = 0, hi = 0;
        for (uint32_t d = 1000; d <= 24000 && !(lo && hi); d += 1000) {
            if (!lo && khz > d && check_sys_clock_khz(khz - d, &vco, &p1, &p2)) lo = khz - d;
            if (!hi && khz + d <= MAX_KHZ && check_sys_clock_khz(khz + d, &vco, &p1, &p2)) hi = khz + d;
        }
        printf("  Nearest available: ");
        if (lo) printf("%u MHz", (unsigned)(lo / 1000));
        if (lo && hi) printf(" or ");
        if (hi) printf("%u MHz", (unsigned)(hi / 1000));
        if (!lo && !hi) printf("(none within 24 MHz)");
        printf(". Unchanged.\n");
        return;
    }
    char tb[16]; temp_str(tb, sizeof(tb));
    printf("\n  clk_sys now %u kHz at %s V (die %s).\n",
           (unsigned)(clock_get_hz(clk_sys) / 1000),
           voltage_label(voltage_for(khz)), tb);
    run_selftest(false);
    run_benchmark();
}

// Step up until something breaks, benchmarking every step that passes, then
// settle one step below the first failure and report the whole sweep.
static void auto_max_clock(void) {
    static double rate[N_CLOCK_STEPS][FEED_COUNT];
    static double swrate[N_CLOCK_STEPS];
    static bool   passed[N_CLOCK_STEPS];
    static char   temps[N_CLOCK_STEPS][16];
    static enum vreg_voltage used_v[N_CLOCK_STEPS];
    static double c1rate[N_CLOCK_STEPS];
    static double hwdual[N_CLOCK_STEPS];

    memset(rate, 0, sizeof(rate));
    memset(swrate, 0, sizeof(swrate));
    memset(passed, 0, sizeof(passed));
    memset(c1rate, 0, sizeof(c1rate));
    memset(hwdual, 0, sizeof(hwdual));

    printf("\n=== AUTO CLOCK SWEEP ===  v%s, %s, core1 %s\n",
           VERSION, ARCH_NAME, dual_core ? "ON" : "off");
    stdio_flush();
    printf("  At each step: set clock, validate all vectors, soak under load with\n");
    printf("  continuous known-answer checks (4 s low, 8 s from 420, 15 s from 460),\n");
    printf("  then benchmark every feed mode.\n");
    printf("  Stops at the first failure and settles one step below. If the chip\n");
    printf("  hangs instead, power cycle -- nothing is persisted, so it comes\n");
    printf("  back at 150 MHz.\n\n");

    // Start from wherever the clock already is. A hang costs a power cycle, so
    // after recovering you can set the last known-good step and press 'a' to
    // resume from there rather than re-walking everything below it.
    unsigned start = 0;
    uint32_t now_khz = clock_get_hz(clk_sys) / 1000;
    for (unsigned i = 0; i < N_CLOCK_STEPS; i++)
        if (clock_steps[i] <= now_khz) start = i;
    uint32_t good = (start > 0) ? clock_steps[start - 1] : 150000;
    if (start > 0)
        printf("  Resuming from %u MHz (set a lower clock first for a full sweep).\n\n",
               (unsigned)(clock_steps[start] / 1000));

    if (manual_vreg)
        printf("  Manual voltage floor %s V is in force -- it applies at EVERY step,\n"
               "  including low clocks that do not need it. Press - to lower it.\n\n",
               voltage_label(manual_vreg));
    if (sweep_top_khz < MAX_KHZ)
        printf("  Ceiling set: will not go above %u MHz.\n\n",
               (unsigned)(sweep_top_khz / 1000));

    for (unsigned i = start; i < N_CLOCK_STEPS; i++) {
        uint32_t khz = clock_steps[i];
        if (khz > sweep_top_khz) {
            printf("  Stopping at the %u MHz ceiling.\n", (unsigned)(sweep_top_khz / 1000));
            break;
        }
        printf("  %3u MHz @ %s V: ", (unsigned)(khz / 1000),
               voltage_label(effective_voltage(khz)));
        stdio_flush();   // partial line: push it out before the risky part

        enum vreg_voltage v = effective_voltage(khz);
        enum vreg_voltage vmax = ext_voltage ? VREG_VOLTAGE_1_60 : VREG_VOLTAGE_MAX;
        bool step_ok = false, no_pll = false;
        for (;;) {
            if (!set_clock_v(khz, v)) { no_pll = true; break; }
            // 500 MHz once passed a 4 s stress and the whole benchmark before
            // hanging, so the top of the range gets a much longer soak.
            int soak = (khz >= 460000) ? 15 : (khz >= 420000) ? 8 : 4;
            if (quick_validate() && stress(soak, false)) { step_ok = true; break; }
            if (v >= vmax) break;
            v = next_voltage(v);
            printf("marginal, retrying @ %s V... ", voltage_label(v));
            stdio_flush();
        }
        if (no_pll)   { printf("no PLL solution, skipping\n"); continue; }
        if (khz > 440000 && !ext_voltage)
            printf("(1.30 V cap -- press V for more headroom) ");
        if (!step_ok) { printf("FAILED (up to %s V)\n", voltage_label(v)); break; }
        used_v[i] = v;

        // same measurements the 'b' command makes, just fewer iterations so the
        // sweep does not take all day
        for (int m = 0; m < FEED_COUNT; m++)
            if (mode_ok[m]) rate[i][m] = bench_mode((feed_mode_t)m, 100000);
        swrate[i] = bench_software(10000);

        // Dual-core is measured HERE, not in run_benchmark() -- the sweep
        // never calls that, which is why 'd' appeared to do nothing under 'a'.
        if (dual_core) {
            feed_mode_t bm = FEED_CPU_FAST;
            double bst = 0;
            for (int m = 0; m < FEED_COUNT; m++)
                if (rate[i][m] > bst) { bst = rate[i][m]; bm = (feed_mode_t)m; }
            uint32_t all1[8];
            for (int k = 0; k < 8; k++) all1[k] = 0xffffffffu;
            c1_start(btc_kats[0].hdr, all1, 0x80000000u);
            uint64_t td = time_us_64();
            hwdual[i] = bench_mode(bm, 300000);   // long enough that core 1
                                                  // is not quantisation-limited
            uint32_t ch = c1_chunks;
            double win = (double)(time_us_64() - td) / 1e6;
            c1_stop();
            c1rate[i] = (double)ch * 100.0 / win;
        }
        temp_str(temps[i], sizeof(temps[i]));
        passed[i] = true;
        good = khz;

        double best = 0;
        for (int m = 0; m < FEED_COUNT; m++) if (rate[i][m] > best) best = rate[i][m];
        // At the top of the range the device can drop off the USB bus mid-line,
        // losing the result that was just measured. Measure hot, report cool.
        bool dropped = false;
        if (khz > 440000) {
            set_clock_v(400000, voltage_for(400000));
            dropped = true;
        }

        printf("stable @ %s V, %s, best ", voltage_label(used_v[i]), temps[i]);
        print_rate(best);
        stdio_flush();
        if (dual_core) {
            // Printed inline, not just in the summary: a hang at a later step
            // would otherwise take the whole table with it.
            printf(" | core1 ");
            print_rate(c1rate[i] < 0 ? 0.0 : c1rate[i]);
            printf(", combined ");
            double comb = hwdual[i] + (c1rate[i] < 0 ? 0.0 : c1rate[i]);
            print_rate(comb);
            if (best > 0) printf(" (%+.1f%%)", 100.0 * (comb - best) / best);
            if (c1rate[i] < 0)       printf("  [CORE 1 LAUNCH FAILED -- clock marginal]");
            else if (c1rate[i] == 0)  printf("  [CORE 1 DID NOT RUN]");
        }
        printf("\n");
        (void)dropped;   // next step sets its own clock; summary restores it
    }

    // Summary is long; print it from a clock USB can survive, then settle.
    set_clock_quiet(good > 440000 ? 400000u : good);

    // ---- sweep summary ----
    printf("\n  %-6s %-5s %10s %10s %10s %9s %9s %7s\n",
           "MHz", "V", "DMA", "CPU fast", "CPU safe", "software", "cyc/hash", "vs 150");
    double base = 0;
    for (unsigned i = 0; i < N_CLOCK_STEPS; i++) {
        if (!passed[i]) continue;
        double best = 0;
        for (int m = 0; m < FEED_COUNT; m++) if (rate[i][m] > best) best = rate[i][m];
        if (base == 0) base = best;
        printf("  %-6u %-5s %10.0f %10.0f %10.0f %9.0f %9.1f %6.2fx\n",
               (unsigned)(clock_steps[i] / 1000), voltage_label(used_v[i]),
               rate[i][FEED_DMA], rate[i][FEED_CPU_FAST], rate[i][FEED_CPU_SAFE],
               swrate[i], (double)clock_steps[i] * 1000.0 / best,
               base > 0 ? best / base : 0.0);
    }
    if (dual_core) {
        printf("\n  Dual core, core 1 running the software miner:\n");
        printf("  %-6s %11s %11s %9s %11s %8s\n",
               "MHz", "hw alone", "hw+core1", "core1", "combined", "delta");
        for (unsigned i = 0; i < N_CLOCK_STEPS; i++) {
            if (!passed[i]) continue;
            double alone = 0;
            for (int m = 0; m < FEED_COUNT; m++) if (rate[i][m] > alone) alone = rate[i][m];
            double comb = hwdual[i] + (c1rate[i] < 0 ? 0.0 : c1rate[i]);
            printf("  %-6u %11.0f %11.0f %9.0f %11.0f %7.1f%%\n",
                   (unsigned)(clock_steps[i] / 1000), alone, hwdual[i], c1rate[i],
                   comb, 100.0 * (comb - alone) / alone);
        }
        bool any = false;
        for (unsigned i = 0; i < N_CLOCK_STEPS; i++) if (passed[i] && c1rate[i] > 0) any = true;
        if (!any) printf("  *** core 1 produced NO hashes at any step -- it never ran. ***\n");
    }

    set_clock_quiet(good);
    printf("\n  Highest clock that passed: %u MHz. Settled there.\n",
           (unsigned)(good / 1000));
    printf("  If cyc/hash stays flat across the sweep, the bottleneck scales with\n");
    printf("  clk_sys as expected; a rising figure means something else is limiting.\n");
    if (!ext_voltage)
        printf("  Stopped at 1.30 V. Press V to allow 1.35/1.40 V and sweep again.\n");

    run_benchmark();
}

// ---------------------------------------------------------------------------

static void menu(void) {
    printf("\n---------------------------------------------------------------\n");
    printf(" t  self test          b  benchmark\n");
    printf(" g  re-mine block 0 (genesis)   h  re-mine block 125552\n");
    printf(" m  mine (24 zero bits)         M  mine (28 zero bits)\n");
    printf(" s  stability stress test (30 s, validates continuously)\n");
    printf(" a  auto clock sweep: validate + stress + benchmark at every step\n");
    printf(" 1/q 150  2/w 200  3/e 250  4/r 300 MHz\n");
    printf(" 5/u 400  6/i 420  7/o 440  8/j 460  9/k 480  0/l 500 MHz\n");
    printf("     4 MHz grid 440-500 via 'c' or the sweep\n");
    printf(" c  set any clock by typing MHz   d  core 1 software miner (%s)\n",
           dual_core ? "ON" : "off");
    printf(" x  sweep ceiling (now %u MHz) -- stops 'a' before the cliff\n",
           (unsigned)(sweep_top_khz / 1000));
    printf(" +/- raise / lower core voltage one step (apply before clocking up)\n");
    printf(" T  ADC diagnostic    p  btcminer-mcu protocol mode\n");
    printf(" V  allow core voltage above 1.30 V (%s).  Core now at %s V\n",
           ext_voltage ? "ON, up to 1.60 V" : "off", voltage_label(cur_vreg));
    printf(" ?  this menu\n");
    printf("---------------------------------------------------------------\n");
    char tb[16]; temp_str(tb, sizeof(tb));
    printf("[v%s %s %u MHz %s V %s] > ", VERSION, ARCH_SHORT,
           (unsigned)(clock_get_hz(clk_sys) / 1000000u),
           voltage_label(cur_vreg), tb);
}

// Delay before stdio_init_all(), which is where tusb_init() asserts the D+
// pull-up and the device appears on the bus. After a UF2 flash the bootrom's
// mass-storage device has only just disappeared from this port; attaching
// again while the host is still tearing it down is a good way to get a failed
// descriptor request. This gap makes it a clean fresh attach instead.
#ifndef BOOT_USB_SETTLE_MS
#define BOOT_USB_SETTLE_MS 500
#endif

// Dedicated mining build (-DPROTOCOL_DEFAULT=1): clock and core voltage applied
// at boot with no prompt. Both overridable from CMake.
#ifndef PROTOCOL_CLOCK_KHZ
#define PROTOCOL_CLOCK_KHZ 528000u
#endif
#ifndef PROTOCOL_VREG
#define PROTOCOL_VREG VREG_VOLTAGE_1_50
#endif

int main(void) {
    sleep_ms(BOOT_USB_SETTLE_MS);
    stdio_init_all();

    // Give a USB host a moment to enumerate, but never block forever.
    for (int i = 0; i < 500 && !stdio_usb_connected(); i++) sleep_ms(10);
    sleep_ms(700);   // let the host finish binding before any bulk output

    // Defensive only: measurement showed clk_adc already enabled at boot on
    // this silicon, so this is not a fix for anything -- it just pins the
    // source to a known 48 MHz.
    clock_configure(clk_adc, 0, CLOCKS_CLK_ADC_CTRL_AUXSRC_VALUE_CLKSRC_PLL_USB,
                    48 * MHZ, 48 * MHZ);
    led_init();
    led_boot_flash();
    adc_init();
    adc_set_temp_sensor_enabled(true);
    hw_set_bits(&adc_hw->cs, ADC_CS_ERR_STICKY_BITS);   // clear any latched error
    miner_hw_init();

    printf("\n\n");
    printf("===============================================================\n");
    printf(" Pico 2 / RP2350 Bitcoin miner v%s\n", VERSION);
    printf(" Core: %s   (USB attach delayed %u ms after reset)\n",
           ARCH_NAME, (unsigned)BOOT_USB_SETTLE_MS);
    {
        bool qfn80 = (sysinfo_hw->package_sel & SYSINFO_PACKAGE_SEL_BITS) != 0;
        printf(" Package: %s, temperature sensor on ADC channel %u\n",
               qfn80 ? "QFN-80 / RP2350B" : "QFN-60 / RP2350A",
               (unsigned)(qfn80 ? 8 : 4));
#ifdef PICO_RP2350A
        if (qfn80 && PICO_RP2350A)
            printf(" NOTE: built for RP2350A but this die is RP2350B. Harmless for\n"
                   "       mining, but GPIO/ADC pin maps in the board header are wrong.\n");
#endif
    }
    printf(" Hardware SHA-256 accelerator @ 0x400f8000\n");
    printf("===============================================================\n");
    printf(" clk_sys %u kHz\n", (unsigned)(clock_get_hz(clk_sys) / 1000));

#if PROTOCOL_DEFAULT
#if PROTOCOL_STOCK
    // Stock mining build: boot clock and voltage, nothing touched. Safe to leave
    // running indefinitely; roughly a third of the overclocked rate.
    printf(" MINING BUILD (stock): %u MHz, no overclock, no voltage change.\n",
           (unsigned)(clock_get_hz(clk_sys) / 1000000u));
#else
    // Overclocked mining build: apply it before the self test, so the engine is
    // validated at the clock it will actually mine at. No prompt -- that is the
    // point of this build.
    ext_voltage = true;                     // allow past VREG_VOLTAGE_MAX
    manual_vreg = PROTOCOL_VREG;            // held across clock changes
    bool clocked = set_clock_quiet(PROTOCOL_CLOCK_KHZ);
    printf(" MINING BUILD (overclocked): %u MHz at %s V, applied without"
           " confirmation.\n",
           (unsigned)(clock_get_hz(clk_sys) / 1000000u), voltage_label(cur_vreg));
    if (!clocked)
        printf(" WARNING: %u kHz has no PLL solution; still at %u MHz.\n",
               (unsigned)PROTOCOL_CLOCK_KHZ,
               (unsigned)(clock_get_hz(clk_sys) / 1000000u));
#endif
#endif

    bool boot_ok = run_selftest(false);

#if PROTOCOL_DEFAULT
    if (!boot_ok) {
        // Never mine on an engine that cannot reproduce a known block hash.
#if PROTOCOL_STOCK
        printf(" *** Self test FAILED at stock clock -- not mining. ***\n");
        menu();
        goto interactive;
#else
        printf(" *** Self test FAILED at %u MHz -- falling back to stock. ***\n",
               (unsigned)(clock_get_hz(clk_sys) / 1000000u));
        manual_vreg = (enum vreg_voltage)0;
        ext_voltage = false;
        set_clock_quiet(150000);
        if (!run_selftest(false)) {
            printf(" *** Self test FAILS AT STOCK TOO -- not mining. ***\n");
            menu();
            goto interactive;
        }
#endif
    }
    printf(" Entering btcminer-mcu protocol mode at %u MHz, %s V.\n",
           (unsigned)(clock_get_hz(clk_sys) / 1000000u), voltage_label(cur_vreg));
    stdio_flush();
    sleep_ms(50);
    enter_protocol_mode();
interactive:;
#else
    (void)boot_ok;
#endif
    printf(" Press b for the benchmark, t for the full self test.\n");
    printf(" Core 1 software miner is ON by default (d toggles it).\n");
    menu();

    for (;;) {
        int c = getchar_timeout_us(100000);
        if (c == PICO_ERROR_TIMEOUT) continue;

        // NUL and CR/LF are line noise from the host, never menu keys.
        if (c == 0 || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;

        // Terminals in application-keypad mode send ESC O <x> for the numeric
        // keypad instead of a plain digit. Consume the sequence and say so.
        if (c == 0x1b) {
            int a = getchar_timeout_us(20000);
            int b = getchar_timeout_us(20000);
            printf("\n  escape sequence (ESC %c %c) -- your terminal is in\n",
                   a > 0x20 ? a : '?', b > 0x20 ? b : '?');
            printf("  application-keypad mode. Use the top-row digits, or the\n");
            printf("  letter aliases q/w/e/r for the clock settings.\n");
            menu();
            continue;
        }

        printf("%c\n", c);

        bool handled = false;
        for (unsigned i = 0; i < N_CLOCK_STEPS; i++) {
            if (c == clock_keys[i] || c == clock_digits[i]) {
                set_clock(clock_steps[i]);
                handled = true;
                break;
            }
        }
        if (handled) { menu(); continue; }

        switch (c) {
            case 't': run_selftest(true); break;
            case 'b': run_benchmark(); break;
            case 'g': remine(0, 200000); break;
            case 'h': remine(2, 200000); break;
            case 's':
                printf("\n=== STRESS TEST ===  v%s, %s, %u MHz at %s V\n", VERSION, ARCH_NAME,
                       (unsigned)(clock_get_hz(clk_sys) / 1000000), voltage_label(cur_vreg));
                stress(30, true);
                break;
            case 'a': auto_max_clock(); break;
            case 'p':
                printf("\n  Entering btcminer-mcu protocol mode. The port now carries\n");
                printf("  binary work frames only; reset the board to get this menu back.\n");
                printf("  80-byte frames mine on the accelerator; 48-byte midstate frames\n");
                printf("  are answered in software (auto-detection probe only).\n\n");
                stdio_flush();
                sleep_ms(50);
                enter_protocol_mode();
                break;
            case 'd':
                dual_core = !dual_core;
                c1_run = false;
                multicore_reset_core1();   // core 1 is launched per measurement
                printf("\n  Core 1 software miner %s.\n", dual_core ? "ENABLED" : "disabled");
                if (dual_core) {
                    printf("  The SHA engine cannot be shared, so core 1 runs the software\n");
                    printf("  path over the top half of the nonce space. Expect single-digit\n");
                    printf("  percent. Run 'b' to see the contention cost measured directly,\n");
                    printf("  and re-check stability -- two busy cores run hotter.\n");
                }
                break;
            case 'x': {
                printf("\n  Sweep ceiling in MHz (0 = no limit): ");
                uint32_t mhz = 0;
                int digits = 0;
                for (;;) {
                    int ch = getchar_timeout_us(15000000);
                    if (ch == PICO_ERROR_TIMEOUT) break;
                    if (ch >= '0' && ch <= '9' && digits < 4) {
                        mhz = mhz * 10u + (uint32_t)(ch - '0');
                        digits++;
                        printf("%c", ch);
                    } else break;
                }
                printf("\n");
                if (!digits) { printf("  cancelled\n"); break; }
                sweep_top_khz = mhz ? mhz * 1000u : MAX_KHZ;
                if (sweep_top_khz > MAX_KHZ) sweep_top_khz = MAX_KHZ;
                printf("  Sweep will stop at %u MHz.\n", (unsigned)(sweep_top_khz / 1000));
                break;
            }
            case 'c': {
                printf("\n  Clock in MHz (Enter to apply, anything else cancels): ");
                uint32_t mhz = 0;
                int digits = 0;
                for (;;) {
                    int ch = getchar_timeout_us(15000000);
                    if (ch == PICO_ERROR_TIMEOUT) break;
                    if (ch >= '0' && ch <= '9' && digits < 4) {
                        mhz = mhz * 10u + (uint32_t)(ch - '0');
                        digits++;
                        printf("%c", ch);
                    } else break;
                }
                printf("\n");
                if (!digits) { printf("  cancelled\n"); break; }
                if (mhz < 50 || mhz > MAX_KHZ / 1000) {
                    printf("  out of range (50 - %u MHz)\n", (unsigned)(MAX_KHZ / 1000));
                    break;
                }
                set_clock(mhz * 1000);
                break;
            }
            case '+': case '=': {
                enum vreg_voltage cap = ext_voltage ? VREG_VOLTAGE_1_60 : VREG_VOLTAGE_MAX;
                if (cur_vreg >= cap) {
                    printf("\n  Already at %s V%s.\n", voltage_label(cur_vreg),
                           ext_voltage ? " (firmware maximum)" : " -- press V to go higher");
                } else {
                    enum vreg_voltage v = next_voltage(cur_vreg);
                    if (v > VREG_VOLTAGE_MAX) vreg_disable_voltage_limit();
                    vreg_set_voltage(v);
                    cur_vreg = v;
                    manual_vreg = v;
                    sleep_ms(20);
                    printf("\n  Core voltage now %s V (held across clock changes).\n",
                           voltage_label(v));
                    if (v >= VREG_VOLTAGE_1_50)
                        printf("  *** %s V will degrade the die. Cool it and keep runs short. ***\n",
                               voltage_label(v));
                    printf("  Raise this BEFORE selecting a higher clock -- a hang cannot\n");
                    printf("  be caught after the fact.\n");
                }
                break;
            }
            case '-': case '_': {
                if (cur_vreg <= VREG_VOLTAGE_1_10) {
                    printf("\n  Already at 1.10 V (stock).\n");
                } else {
                    enum vreg_voltage v = (enum vreg_voltage)((int)cur_vreg - 1);
                    vreg_set_voltage(v);
                    cur_vreg = v;
                    manual_vreg = (v <= VREG_VOLTAGE_1_10) ? (enum vreg_voltage)0 : v;
                    sleep_ms(20);
                    printf("\n  Core voltage now %s V.\n", voltage_label(v));
                }
                break;
            }
            case 'T': {
                printf("\n=== ADC DIAGNOSTIC ===\n");
                printf("  package    = %s -> temp channel %u\n",
                       (sysinfo_hw->package_sel & SYSINFO_PACKAGE_SEL_BITS)
                           ? "QFN-80 / RP2350B" : "QFN-60 / RP2350A",
                       (unsigned)TEMP_ADC_CHANNEL);
                printf("  clk_adc    = %u Hz  (0 means the generator is off)\n",
                       (unsigned)clock_get_hz(clk_adc));
                printf("  adc_hw->cs = 0x%08x  (EN=%u READY=%u TS_EN=%u AINSEL=%u "
                       "ERR=%u ERR_STICKY=%u)\n",
                       (unsigned)adc_hw->cs,
                       (unsigned)((adc_hw->cs & ADC_CS_EN_BITS) ? 1 : 0),
                       (unsigned)((adc_hw->cs & ADC_CS_READY_BITS) ? 1 : 0),
                       (unsigned)((adc_hw->cs & ADC_CS_TS_EN_BITS) ? 1 : 0),
                       (unsigned)((adc_hw->cs & ADC_CS_AINSEL_BITS) >> ADC_CS_AINSEL_LSB),
                       (unsigned)((adc_hw->cs & ADC_CS_ERR_BITS) ? 1 : 0),
                       (unsigned)((adc_hw->cs & ADC_CS_ERR_STICKY_BITS) ? 1 : 0));
                printf("  adc_hw->div = 0x%08x\n", (unsigned)adc_hw->div);

                // Proper control: adc_gpio_init disables the digital input
                // buffer and pulls. Reading GPIO26-29 WITHOUT it is invalid --
                // RP2350 pads with a pull-down can latch high, which rails the
                // input regardless of whether the ADC works.
                adc_gpio_init(26);
                sleep_ms(2);
                hw_set_bits(&adc_hw->cs, ADC_CS_ERR_STICKY_BITS);
                adc_select_input(0);
                sleep_ms(2);
                uint16_t r0 = adc_read();
                bool e0 = (adc_hw->cs & ADC_CS_ERR_BITS) != 0;
                printf("    ch0 via adc_gpio_init(26): raw=%4u  %.3f V  ERR=%u\n",
                       (unsigned)r0, (double)r0 * 3.3 / 4096.0, (unsigned)e0);

                hw_set_bits(&adc_hw->cs, ADC_CS_ERR_STICKY_BITS);
                adc_set_temp_sensor_enabled(true);
                sleep_ms(10);                    // let the sensor bias settle
                adc_select_input(TEMP_ADC_CHANNEL);
                sleep_ms(2);
                uint16_t r4 = adc_read();
                bool e4 = (adc_hw->cs & ADC_CS_ERR_BITS) != 0;
                printf("    ch4 temp sensor, settled:  raw=%4u  %.3f V  ERR=%u\n",
                       (unsigned)r4, (double)r4 * 3.3 / 4096.0, (unsigned)e4);

                printf("\n  Reading: ch0 sensible and ERR=0 means the ADC works and\n");
                printf("  only the temperature path is bad. Both railing with ERR=1\n");
                printf("  means the ADC block itself is not converting on this board.\n");
                break;
            }
            case 'm': mine_loop(24); break;
            case 'M': mine_loop(28); break;
            case 'V': {
                if (ext_voltage) {
                    ext_voltage = false;
                    set_clock_quiet(150000);
                    printf("\n  Extended voltage OFF. Dropped to 150 MHz at 1.10 V.\n");
                    break;
                }
                printf("\n  This unlocks 1.35, 1.40, 1.50 and 1.60 V (there is no 1.45).\n");
                printf("  1.50 V is 36%% over the 1.10 V nominal, 1.60 V is 45%%. At 1.60 V\n");
                printf("  expect permanent degradation, possibly within minutes of load.\n");
                printf("  1.30 V is VREG_VOLTAGE_MAX; the SDK calls anything above it\n");
                printf("  \"beyond the safe range of operation\". It will not fail suddenly,\n");
                printf("  but it does accelerate ageing of the die. Your call, your board.\n");
                printf("  Press Y to confirm, anything else to cancel: ");
                int y = getchar_timeout_us(10000000);
                printf("\n");
                if (y == 'Y') {
                    ext_voltage = true;
                    printf("  Extended voltage ON. Re-select a clock to apply it.\n");
                    printf("  Run 's' afterwards -- a 30 s stress at temperature is the\n");
                    printf("  only thing that tells you whether it is actually stable.\n");
                } else {
                    printf("  Cancelled, staying at 1.30 V maximum.\n");
                }
                break;
            }
            case '?': break;
            default:
                printf("  unknown key: byte 0x%02x", (unsigned)(c & 0xff));
                if (c >= 0x20 && c < 0x7f) printf(" ('%c')", c);
                printf("\n");
                break;
        }
        menu();
    }
}
