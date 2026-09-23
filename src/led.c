// LED status, non-blocking.
//
// The mining loop must never sleep, so pulses are started and then ended by
// led_service() on a later pass. Called from the chunk loop, that gives a few
// milliseconds of resolution at full hash rate.
//
// Two distinguishable signals:
//   heartbeat  short flash every 5 s -- the firmware is alive
//   activity   longer flash when new work arrives -- real mining progress
//
// Activity is deliberately rate limited. The device cannot tell which share is
// a valid block (the host decides that), and at a 16-bit share target it finds
// ~16 shares/second, so an unlimited blink would look like a solid LED.

#include "led.h"
#include "pico/stdlib.h"

#ifdef PICO_DEFAULT_LED_PIN

#define LED_PIN            PICO_DEFAULT_LED_PIN
#define HEARTBEAT_EVERY_US 5000000ull
#define HEARTBEAT_MS       40u
#define ACTIVITY_MS        90u
#define ACTIVITY_MIN_GAP_US 250000ull   // keep blinks visually distinct

static bool     led_on = false;
static uint64_t off_at_us = 0;
static uint64_t last_beat_us = 0;
static uint64_t last_activity_us = 0;

void led_init(void) {
    gpio_init(LED_PIN);
    gpio_set_dir(LED_PIN, GPIO_OUT);
    gpio_put(LED_PIN, 0);
    last_beat_us = time_us_64();
}

static void pulse(uint32_t ms) {
    gpio_put(LED_PIN, 1);
    led_on = true;
    off_at_us = time_us_64() + (uint64_t)ms * 1000ull;
}

void led_activity(void) {
    uint64_t now = time_us_64();
    if (now - last_activity_us < ACTIVITY_MIN_GAP_US) return;
    last_activity_us = now;
    pulse(ACTIVITY_MS);
}

void led_service(void) {
    uint64_t now = time_us_64();
    if (led_on && now >= off_at_us) {
        gpio_put(LED_PIN, 0);
        led_on = false;
    }
    if (!led_on && now - last_beat_us >= HEARTBEAT_EVERY_US) {
        last_beat_us = now;
        pulse(HEARTBEAT_MS);
    }
}

void led_boot_flash(void) {
    for (int i = 0; i < 3; i++) {
        gpio_put(LED_PIN, 1); sleep_ms(60);
        gpio_put(LED_PIN, 0); sleep_ms(60);
    }
}

#else   // board has no LED

void led_init(void)       {}
void led_activity(void)   {}
void led_service(void)    {}
void led_boot_flash(void) {}

#endif
