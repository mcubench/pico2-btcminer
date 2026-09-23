// Runs the real protocol.c on a host, backed by a tty (pty slave), with the
// SHA-256 peripheral emulated. Lets btcminer-mcu's own Python drive the actual
// firmware protocol code.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <poll.h>
#include "protocol.h"
#include "miner.h"

feed_mode_t best_mode = FEED_DMA;      // normally set by the device self test

static int g_fd = -1;

static int host_get_byte(void *, uint32_t timeout_us) {
    struct pollfd p = { g_fd, POLLIN, 0 };
    int ms = (timeout_us == 0) ? 0 : (int)((timeout_us + 999) / 1000);
    if (poll(&p, 1, ms) <= 0) return -1;
    uint8_t b;
    ssize_t n = read(g_fd, &b, 1);
    if (n != 1) return -1;
    return b;
}
static void host_put_bytes(void *, const uint8_t *b, size_t n) {
    ssize_t r = write(g_fd, b, n); (void)r;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: proto_host <tty>\n"); return 1; }
    g_fd = open(argv[1], O_RDWR | O_NOCTTY);
    if (g_fd < 0) { perror("open"); return 1; }

    struct termios t;
    tcgetattr(g_fd, &t);
    cfmakeraw(&t);                      // no echo, no CR/LF translation
    tcsetattr(g_fd, TCSANOW, &t);

    miner_hw_init();
    proto_io_t io = { host_get_byte, host_put_bytes, nullptr };
    proto_run(&io);
    return 0;
}
