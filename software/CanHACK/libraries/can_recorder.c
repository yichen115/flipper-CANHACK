#include "can_recorder.h"
#include "can_trace.h"
#include <stdlib.h>
#include <string.h>

#define WRITER_STOP (1U << 1)
#define DISK_BLOCK 2048U
typedef struct {
    CANFRAME frame;
    uint64_t time_us;
} Record;

struct CanRecorder {
    File* file;
    FuriMessageQueue* queue;
    FuriThread* writer;
    FuriMutex* mutex;
    CanRecorderStats stats;
    char* buffer;
};

static bool flush(CanRecorder* r, size_t* used, uint32_t* pending, uint32_t* written) {
    if(!*used) return true;
    bool ok = storage_file_write(r->file, r->buffer, *used) == *used;
    if(ok) *written += *pending;
    *pending = 0;
    *used = 0;
    return ok;
}

static int32_t writer_thread(void* context) {
    CanRecorder* r = context;
    size_t used = 0;
    uint32_t last_flush = furi_get_tick();
    bool stop = false;
    bool failed = false;
    uint32_t written = 0, pending = 0;
    for(;;) {
        if(furi_thread_flags_get() & WRITER_STOP) stop = true;
        Record record;
        FuriStatus status = furi_message_queue_get(r->queue, &record, stop ? 0 : 20);
        if(status == FuriStatusOk) {
            if(!failed) {
                char line[128];
                int length = can_trace_format(line, sizeof(line), &record.frame, record.time_us);
                if(length < 0) failed = true;
                else {
                    if(used + length > DISK_BLOCK) failed = !flush(r, &used, &pending, &written);
                    if(!failed) {
                        memcpy(r->buffer + used, line, length);
                        used += length;
                        pending++;
                    }
                }
            }
        } else if(stop) break;
        if(!failed && used && furi_get_tick() - last_flush >= 200) {
            failed = !flush(r, &used, &pending, &written);
            last_flush = furi_get_tick();
        }
        furi_mutex_acquire(r->mutex, FuriWaitForever);
        r->stats.written = written;
        r->stats.failed = failed;
        furi_mutex_release(r->mutex);
    }
    if(!failed) failed = !flush(r, &used, &pending, &written);
    if(!storage_file_sync(r->file)) failed = true;
    storage_file_close(r->file);
    furi_mutex_acquire(r->mutex, FuriWaitForever);
    r->stats.written = written;
    r->stats.failed = failed;
    furi_mutex_release(r->mutex);
    return 0;
}

CanRecorder* can_recorder_open(Storage* storage, const char* path) {
    CanRecorder* r = calloc(1, sizeof(*r));
    if(!r) return NULL;
    r->file = storage_file_alloc(storage);
    if(!storage_file_open(r->file, path, FSAM_WRITE, FSOM_CREATE_NEW)) {
        storage_file_free(r->file);
        free(r);
        return NULL;
    }
    r->buffer = malloc(DISK_BLOCK);
    if(!r->buffer) {
        storage_file_close(r->file);
        storage_file_free(r->file);
        free(r);
        return NULL;
    }
    r->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    r->queue = furi_message_queue_alloc(CAN_RECORD_QUEUE_SIZE, sizeof(Record));
    r->writer = furi_thread_alloc_ex("CanLogWriter", 3072, writer_thread, r);
    furi_thread_start(r->writer);
    return r;
}

bool can_recorder_put(CanRecorder* r, const CANFRAME* frame, uint64_t time_us) {
    Record record = {.frame = *frame, .time_us = time_us};
    bool accepted = furi_message_queue_put(r->queue, &record, 0) == FuriStatusOk;
    if(!accepted) {
        furi_mutex_acquire(r->mutex, FuriWaitForever);
        r->stats.dropped++;
        furi_mutex_release(r->mutex);
    }
    return accepted;
}

CanRecorderStats can_recorder_stats(CanRecorder* r) {
    furi_mutex_acquire(r->mutex, FuriWaitForever);
    CanRecorderStats stats = r->stats;
    furi_mutex_release(r->mutex);
    return stats;
}

CanRecorderStats can_recorder_close(CanRecorder* r) {
    FuriThreadId id = furi_thread_get_id(r->writer);
    if(id) furi_thread_flags_set(id, WRITER_STOP);
    furi_thread_join(r->writer);
    CanRecorderStats stats = can_recorder_stats(r);
    furi_thread_free(r->writer);
    furi_message_queue_free(r->queue);
    furi_mutex_free(r->mutex);
    storage_file_free(r->file);
    free(r->buffer);
    free(r);
    return stats;
}
