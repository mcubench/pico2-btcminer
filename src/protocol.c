// btcminer-mcu wire protocol.
//
// Work in  : 80 raw little-endian block header bytes  (has_midstate_support = False)
//            or 48 bytes midstate work                (has_midstate_support = True)
// Shares out: 4 bytes per share, nonce big-endian, streamed continuously until
//            new work arrives.
//
// The 80-byte path is the one that matters: it feeds btc_work_init() directly
// and runs at full accelerator speed. The 48-byte path exists only so the
// device can answer btcminer-mcu's auto-detection probe -- RP2350's engine
// cannot load a midstate, so it is software-only and ~9x slower.
//
// I/O is abstracted so this exact code runs both on the device (USB CDC) and
// in the host test harness (pty).

#include "protocol.h"
#include "miner.h"
#include "sha256_sw.h"
#include "led.h"
#include <string.h>

// btcminer-mcu fixes the device-side share target at 0x0000FFFF..FF
// (see mining_device.py / the project README): 16 leading zero bits.
#define SHARE_LIMB7 0x0000FFFFu

#define CHUNK 2000u          // hashes between checks for new work (~2 ms at 1 MH/s)

static inline uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void emit_nonce(const proto_io_t *io, uint32_t nonce) {
    uint8_t b[4] = { (uint8_t)(nonce >> 24), (uint8_t)(nonce >> 16),
                     (uint8_t)(nonce >> 8),  (uint8_t)nonce };
    io->put_bytes(io->ctx, b, 4);      // big-endian, matches struct.pack(">L", n)
    // NB: put_bytes must write all four in ONE call. stdio_usb_out_chars()
    // takes a mutex, runs tud_task() and flushes on every call, so four
    // per-byte writes plus an explicit flush is five traversals of the USB
    // stack per share where one is enough.
}

// Collect one work frame. The host writes the whole frame in one burst, so
// after 48 bytes we probe briefly for 32 more to tell an 80-byte header from a
// 48-byte midstate unit.
static size_t read_frame(const proto_io_t *io, uint8_t *buf, int *pending) {
    size_t n = 0;
    if (*pending >= 0) { buf[n++] = (uint8_t)*pending; *pending = -1; }

    while (n < 48) {
        // Short timeout so the heartbeat keeps ticking while idle waiting for
        // work, and so a pulse is never left on for a whole second.
        int c = io->get_byte(io->ctx, 100000);
        led_service();
        if (c < 0) { if (n) n = 0; continue; }   // partial frame timed out, resync
        buf[n++] = (uint8_t)c;
    }
    while (n < 80) {
        int c = io->get_byte(io->ctx, 50000);
        if (c < 0) return 48;                    // no more data: midstate unit
        buf[n++] = (uint8_t)c;
    }
    return 80;
}

// Full 80-byte header: hardware path, full speed.
static void mine_header(const proto_io_t *io, const uint8_t hdr[80], int *pending) {
    btc_work_t w;
    btc_work_init(&w, hdr);

    uint32_t target[8];
    for (int i = 0; i < 7; i++) target[i] = 0xffffffffu;
    target[7] = SHARE_LIMB7;

    uint32_t nonce = rd_le32(hdr + 76);          // start nonce, little-endian field

    // Resolve the feed mode once. miner_hash_nonce() switches on it per call,
    // which is a compare and branch on every single hash.
    uint32_t (*hash_one)(btc_work_t *, uint32_t);
    switch (best_mode) {
        case FEED_CPU_SAFE: hash_one = miner_hash_nonce_safe; break;
        case FEED_DMA:      hash_one = miner_hash_nonce_dma;  break;
        default:            hash_one = miner_hash_nonce_fast; break;
    }

    // Bound the search by a precomputed end instead of a second counter
    // incremented and tested on every hash.
    uint32_t remaining = 0xffffffffu;

    while (remaining) {
        uint32_t batch = remaining < CHUNK ? remaining : CHUNK;
        remaining -= batch;
        while (batch--) {
            uint32_t h7 = hash_one(&w, nonce);
            // Equivalent to bswap32(h7) <= 0x0000FFFF, without the byte swap:
            // the top 16 bits of the display hash are the low 16 bits of the
            // raw SUM word, and byte order cannot change whether they are zero.
            if ((h7 & 0xffffu) == 0) {
                uint32_t st[8], limbs[8];
                miner_read_state(st);
                btc_hash_limbs(st, limbs);
                if (btc_limbs_le(limbs, target)) emit_nonce(io, nonce);
            }
            nonce++;
        }
        led_service();
        int c = io->get_byte(io->ctx, 0);
        if (c >= 0) { *pending = c; return; }     // new work preempts
    }
}

// 48-byte midstate unit: software only. RP2350 cannot load a SHA-256 state,
// so the first compression cannot use the accelerator.
static void mine_midstate(const proto_io_t *io, const uint8_t f[48], int *pending) {
    static const uint32_t IV[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };

    uint32_t st0[8], w[16];
    for (int i = 0; i < 8; i++) st0[i] = rd_le32(f + 4 * i);
    for (int i = 0; i < 3; i++) w[i] = rd_le32(f + 32 + 4 * i);
    w[4] = 0x80000000u;
    for (int i = 5; i < 15; i++) w[i] = 0;
    w[15] = 640u;                                // 80 byte message

    uint32_t nonce = rd_be32(f + 44);            // start nonce, big-endian in the frame
    uint32_t done  = 0;

    for (;;) {
        for (uint32_t i = 0; i < 200u; i++) {
            uint32_t st[8], w2[16], st2[8];
            memcpy(st, st0, sizeof(st));
            w[3] = __builtin_bswap32(nonce);
            sha256_sw_compress_words(st, w);

            for (int k = 0; k < 8; k++) w2[k] = st[k];
            w2[8] = 0x80000000u;
            for (int k = 9; k < 15; k++) w2[k] = 0;
            w2[15] = 256u;
            memcpy(st2, IV, sizeof(st2));
            sha256_sw_compress_words(st2, w2);

            if ((st2[7] & 0xffffu) == 0) {          // see mine_header
                uint32_t limbs[8], target[8];
                btc_hash_limbs(st2, limbs);
                for (int k = 0; k < 7; k++) target[k] = 0xffffffffu;
                target[7] = SHARE_LIMB7;
                if (btc_limbs_le(limbs, target)) emit_nonce(io, nonce);
            }
            nonce++;
            if (++done == 0xffffffffu) return;
        }
        led_service();
        int c = io->get_byte(io->ctx, 0);
        if (c >= 0) { *pending = c; return; }
    }
}

void proto_run(const proto_io_t *io) {
    uint8_t frame[80];
    int pending = -1;
    for (;;) {
        size_t n = read_frame(io, frame, &pending);
        // New work means the host accepted a block and moved on -- the closest
        // thing the device can observe to "a block was found".
        led_activity();
        if (n == 80)      mine_header(io, frame, &pending);
        else if (n == 48) mine_midstate(io, frame, &pending);
    }
}
