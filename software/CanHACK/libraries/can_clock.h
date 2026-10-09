#pragma once
#include <furi.h>
#include <furi_hal.h>
#include <stm32wbxx.h>

typedef struct {
    uint32_t tick;
    uint32_t start_fraction;
    uint64_t elapsed_ticks;
    uint64_t last_us;
} CanClock;

// Unlike DWT, SysTick keeps counting in shallow WFI sleep. Insomnia prevents
// deep/tickless sleep from suspending SysTick while this clock is in use.
static inline uint32_t can_clock_sample(uint32_t* tick) {
    uint32_t before, after, value, period;
    do {
        before = furi_get_tick();
        period = SysTick->LOAD + 1;
        value = SysTick->VAL;
        after = furi_get_tick();
    } while(before != after);
    *tick = before;
    return (uint32_t)((uint64_t)(period - 1 - value) * 1000 / period);
}

static inline CanClock can_clock_start(void) {
    furi_hal_power_insomnia_enter();
    CanClock clock = {0};
    clock.start_fraction = can_clock_sample(&clock.tick);
    return clock;
}

static inline void can_clock_stop(CanClock* clock) {
    (void)clock;
    furi_hal_power_insomnia_exit();
}

// Sample at least once per RTOS tick wrap (~49 days). Clamp the tiny window
// where SysTick has reloaded but its interrupt has not updated the RTOS tick.
static inline uint64_t can_clock_us(CanClock* clock) {
    uint32_t tick;
    uint32_t fraction = can_clock_sample(&tick);
    clock->elapsed_ticks += (uint32_t)(tick - clock->tick);
    clock->tick = tick;
    uint64_t current = clock->elapsed_ticks * 1000 + fraction;
    if(current >= clock->start_fraction) {
        current -= clock->start_fraction;
        if(current > clock->last_us) clock->last_us = current;
    }
    return clock->last_us;
}

static inline bool can_wait_until(CanClock* clock, uint64_t deadline_us) {
    for(;;) {
        if(furi_thread_flags_get() & (1U << 1)) return false;
        uint64_t now = can_clock_us(clock);
        if(now >= deadline_us) return true;
        uint64_t left = deadline_us - now;
        if(left > 2000) furi_delay_ms(left > 10000 ? 10 : (uint32_t)((left - 1000) / 1000));
        else furi_delay_us(left > 100 ? 100 : (uint32_t)left);
    }
}
