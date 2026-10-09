#pragma once

#include <furi.h>

typedef struct {
    uint32_t* timestamp;
    bool* extended;
    FuriString* dir;
    FuriString* can_id;
    char* len;
    FuriString* dlc;
} FrameCAN;

FrameCAN* frame_can_alloc(void);

void frame_can_free(FrameCAN* frame);
