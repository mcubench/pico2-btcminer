// btcminer-mcu wire protocol. See protocol.c for the format.
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

// I/O abstraction: the same protocol code runs on the device over USB CDC and
// in the host test harness over a pty.
typedef struct {
    int  (*get_byte)(void *ctx, uint32_t timeout_us);  // 0..255, or <0 on timeout
    void (*put_bytes)(void *ctx, const uint8_t *b, size_t n);
    void *ctx;
} proto_io_t;

// Serve work frames forever.
void proto_run(const proto_io_t *io);

#endif
