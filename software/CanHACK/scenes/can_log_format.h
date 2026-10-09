#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* CANFRAME must already be defined.
 * r:<ext 0/1>:<time ms>:<id hex>:<dlc>:<bytes>[:Q1]
 *
 * The optional Q1 suffix keeps remote-request frames lossless while leaving
 * the original format byte-for-byte compatible for ordinary data frames.
 * Returns the byte count to write, including the newline, or -1.
 */
static inline int can_log_format_line(
    char* out,
    size_t out_len,
    const CANFRAME* frame,
    uint32_t time_ms) {
    uint8_t dlc = frame->data_length;
    if(dlc > 8) dlc = 8;

    int pos = snprintf(
        out,
        out_len,
        "r:%u:%lu:%0*lX:%u:",
        frame->ext ? 1U : 0U,
        (unsigned long)time_ms,
        frame->ext ? 8 : 3,
        (unsigned long)frame->canId,
        dlc);
    if(pos < 0 || (size_t)pos >= out_len) return -1;

    for(uint8_t i = 0; i < dlc; i++) {
        int wrote = snprintf(
            out + pos,
            out_len - (size_t)pos,
            "%s%02X",
            i ? " " : "",
            frame->buffer[i]);
        if(wrote < 0 || (size_t)pos + (size_t)wrote >= out_len) return -1;
        pos += wrote;
    }

    if(frame->req) {
        int wrote = snprintf(out + pos, out_len - (size_t)pos, ":Q1");
        if(wrote < 0 || (size_t)pos + (size_t)wrote >= out_len) return -1;
        pos += wrote;
    }
    if((size_t)pos + 1 >= out_len) return -1;
    out[pos++] = '\n';
    out[pos] = '\0';
    return pos;
}
