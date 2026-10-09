#include "can_trace.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>

int can_trace_format(char* out, size_t capacity, const CANFRAME* frame, uint64_t time_us) {
    if(!out || !frame || !capacity || frame->data_length > 8 || frame->canId > 0x1FFFFFFF) return -1;
    int pos = snprintf(out, capacity, "r:%u:%llu:%0*lX:%u:",
        frame->ext ? 1U : 0U, (unsigned long long)(time_us / 1000),
        frame->ext ? 8 : 3, (unsigned long)frame->canId, frame->data_length);
    if(pos < 0 || (size_t)pos >= capacity) return -1;
    for(uint8_t i = 0; i < frame->data_length; i++) {
        int n = snprintf(out + pos, capacity - pos, "%s%02X", i ? " " : "", frame->buffer[i]);
        if(n < 0 || (size_t)n >= capacity - pos) return -1;
        pos += n;
    }
    int n = snprintf(out + pos, capacity - pos, "%s:U%03u\n", frame->req ? ":Q1" : "", (unsigned)(time_us % 1000));
    if(n < 0 || (size_t)n >= capacity - pos) return -1;
    return pos + n;
}

static int nibble(char ch) {
    if(ch >= '0' && ch <= '9') return ch - '0';
    if(ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    if(ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

static bool decimal(const char** cursor, uint64_t limit, uint64_t* result) {
    const char* p = *cursor;
    if(*p < '0' || *p > '9') return false;
    uint64_t value = 0;
    do {
        uint64_t digit = *p++ - '0';
        if(digit > limit || value > (limit - digit) / 10) return false;
        value = value * 10 + digit;
    } while(*p >= '0' && *p <= '9');
    *result = value;
    *cursor = p;
    return true;
}

bool can_trace_parse(const char* line, CANFRAME* frame, uint64_t* time_us) {
    if(!line || !frame || !time_us) return false;
    const char* p = line;
    while(*p == ' ' || *p == '\t') p++;
    if(!strchr("rRtT", *p) || !*p) return false;
    p++;
    if(*p++ != ':') return false;
    if(*p != '0' && *p != '1') return false;
    CANFRAME parsed = {.ext = *p++ - '0'};
    if(*p++ != ':') return false;
    uint64_t milliseconds = 0, length = 0;
    if(!decimal(&p, UINT64_MAX / 1000, &milliseconds) || *p++ != ':') return false;
    uint32_t id = 0;
    uint8_t digits = 0;
    int digit;
    while((digit = nibble(*p)) >= 0) {
        if(++digits > 8) return false;
        id = (id << 4) | digit;
        p++;
    }
    if(!digits || id > 0x1FFFFFFF || *p++ != ':') return false;
    if(!decimal(&p, 8, &length) || *p++ != ':') return false;
    parsed.canId = id;
    parsed.ext |= id > 0x7FF;
    parsed.data_length = (uint8_t)length;
    for(size_t i = 0; i < length; i++) {
        while(*p == ' ' || *p == '\t') p++;
        int hi = nibble(*p);
        if(hi < 0) return false;
        p++;
        int lo = nibble(*p);
        if(lo < 0) return false;
        p++;
        parsed.buffer[i] = (hi << 4) | lo;
    }
    bool has_us = false, has_rtr = false;
    uint64_t fraction = 0;
    while(*p == ' ' || *p == '\t') p++;
    while(*p == ':') {
        p++;
        if((*p == 'Q' || *p == 'q') && !has_rtr) {
            p++;
            if(*p++ != '1') return false;
            parsed.req = 1;
            has_rtr = true;
        } else if((*p == 'U' || *p == 'u') && !has_us) {
            p++;
            if(!decimal(&p, 999, &fraction)) return false;
            has_us = true;
        } else return false;
        while(*p == ' ' || *p == '\t') p++;
    }
    while(*p == '\r' || *p == '\n') p++;
    if(*p || milliseconds * 1000 > UINT64_MAX - fraction) return false;
    *frame = parsed;
    *time_us = milliseconds * 1000 + fraction;
    return true;
}

bool can_replay_schedule(CanReplaySchedule* s, uint64_t timestamp, uint64_t now,
                         bool fast, uint64_t* deadline, bool* capped) {
    *capped = false;
    if(!s->started) {
        s->started = true;
        s->deadline_us = now;
    } else {
        if(timestamp < s->previous_us) return false;
        uint64_t gap = timestamp - s->previous_us;
        if(fast && gap > 20000) { gap = 20000; *capped = true; }
        if(s->deadline_us > UINT64_MAX - gap) return false;
        s->deadline_us += gap;
    }
    s->previous_us = timestamp;
    *deadline = s->deadline_us;
    return true;
}

uint64_t can_periodic_next(uint64_t deadline, uint64_t period, uint64_t now) {
    if(!period) period = 1;
    uint64_t slots = now >= deadline ? (now - deadline) / period + 1 : 1;
    return deadline + slots * period;
}

uint32_t can_scaled_count(uint8_t value, uint8_t exponent) {
    uint32_t result = value;
    while(exponent--) {
        if(result > UINT32_MAX / 10) return UINT32_MAX;
        result *= 10;
    }
    return result;
}
