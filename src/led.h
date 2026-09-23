// Non-blocking LED status. See led.c for the signalling scheme.
#ifndef LED_H
#define LED_H

void led_init(void);        // configure the pin
void led_boot_flash(void);  // three quick flashes at start-up (blocking, once)
void led_activity(void);    // new work arrived; rate limited to stay visible
void led_service(void);     // call often: ends pulses, emits the 5 s heartbeat

#endif
