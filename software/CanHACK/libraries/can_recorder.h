#pragma once
#include <furi.h>
#include <storage/storage.h>
#include "can_types.h"

#define CAN_RECORD_QUEUE_SIZE 256U
typedef struct CanRecorder CanRecorder;
typedef struct {
    // Complete records in successful storage writes. Check failed for sync errors.
    uint32_t written;
    uint32_t dropped;
    bool failed;
} CanRecorderStats;

CanRecorder* can_recorder_open(Storage* storage, const char* path);
// Never waits for disk or queue space. Only the producer may enqueue.
bool can_recorder_put(CanRecorder* recorder, const CANFRAME* frame, uint64_t time_us);
CanRecorderStats can_recorder_stats(CanRecorder* recorder);
// Stop the producer first. Drains accepted frames and flushes the final block.
CanRecorderStats can_recorder_close(CanRecorder* recorder);
