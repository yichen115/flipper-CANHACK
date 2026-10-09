#pragma once
#include <stdint.h>

typedef struct {
    uint32_t canId;
    uint8_t ext;
    uint8_t req;
    uint8_t data_length;
    uint8_t buffer[8];
} CANFRAME;
