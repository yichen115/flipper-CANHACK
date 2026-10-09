#pragma once
#include "can_types.h"
#include <stdbool.h>
#include <stddef.h>

// Existing integer millisecond field is preserved. Optional :U000..999 adds us.
int can_trace_format(char* out, size_t capacity, const CANFRAME* frame, uint64_t time_us);
bool can_trace_parse(const char* line, CANFRAME* frame, uint64_t* time_us);

typedef struct {
    bool started;
    uint64_t previous_us;
    uint64_t deadline_us;
} CanReplaySchedule;

// First record starts now; Fast caps only gaps exceeding 20 ms.
bool can_replay_schedule(CanReplaySchedule* schedule, uint64_t timestamp_us,
                         uint64_t now_us, bool fast, uint64_t* deadline_us, bool* capped);
// Skip missed periodic slots instead of issuing a catch-up burst.
uint64_t can_periodic_next(uint64_t deadline_us, uint64_t period_us, uint64_t now_us);
uint32_t can_scaled_count(uint8_t value, uint8_t exponent);
