#include "../app_user.h"
#include "../libraries/can_trace.h"
#include "../libraries/can_clock.h"
#include "../libraries/can_recorder.h"

#include <stdio.h>
#include <string.h>

#ifndef LOG_PATH_SIZE
#define LOG_PATH_SIZE 256
#endif
#define CAPTURE_STACK           4096
#define REPLAY_STACK            4096
#define LOG_LINE_MAX            160

typedef struct {
    FuriMutex* mutex;
    uint32_t frames;
    uint32_t elapsed_ms;
    uint32_t last_id;
    uint32_t rx_overrun;
    uint32_t tx_error;
    uint32_t gap_capped;
    uint32_t queue_dropped;
    uint32_t late_frames;
    uint32_t invalid_lines;
    uint8_t last_dlc;
    uint8_t last_data[8];
    uint8_t last_ext;
    uint8_t fail;
    bool finished;
    char file_label[64];
} TraceState;

static TraceState trace;
static bool trace_error_view = false;
static uint8_t replay_timing = 0;
static uint8_t replay_loop = 0;

static const char* replay_timing_text[] = {"Real", "Fast"};
static const char* replay_loop_text[] = {"Off", "On"};

typedef enum {
    ReplayEventChooseLog,
} ReplayEvent;

static void trace_reset(void) {
    if(trace.mutex) {
        furi_mutex_free(trace.mutex);
        trace.mutex = NULL;
    }
    memset(&trace, 0, sizeof(trace));
    trace.mutex = furi_mutex_alloc(FuriMutexTypeNormal);
}

static void trace_clear(void) {
    if(trace.mutex) {
        furi_mutex_free(trace.mutex);
        trace.mutex = NULL;
    }
}

static void trace_note_frame(const CANFRAME* frame, uint32_t elapsed, bool tx_fail) {
    uint8_t dlc = frame->data_length;
    if(dlc > 8) dlc = 8;
    furi_mutex_acquire(trace.mutex, FuriWaitForever);
    trace.frames++;
    trace.elapsed_ms = elapsed;
    trace.last_id = frame->canId;
    trace.last_ext = frame->ext;
    trace.last_dlc = dlc;
    memset(trace.last_data, 0, sizeof(trace.last_data));
    memcpy(trace.last_data, frame->buffer, dlc);
    if(tx_fail) trace.tx_error++;
    furi_mutex_release(trace.mutex);
}

static void trace_note_overrun(uint8_t count) {
    furi_mutex_acquire(trace.mutex, FuriWaitForever);
    trace.rx_overrun += count;
    furi_mutex_release(trace.mutex);
}

static void trace_finish(uint8_t fail) {
    furi_mutex_acquire(trace.mutex, FuriWaitForever);
    trace.fail = fail;
    trace.finished = true;
    furi_mutex_release(trace.mutex);
}

static bool worker_stopped(void) {
    return (furi_thread_flags_get() & THREAD_SNIFFER_STOP) != 0;
}

static void trace_set_label(const char* path) {
    const char* base = strrchr(path, '/');
    base = base ? base + 1 : path;
    furi_mutex_acquire(trace.mutex, FuriWaitForever);
    snprintf(trace.file_label, sizeof(trace.file_label), "%s", base);
    furi_mutex_release(trace.mutex);
}

static bool resolve_capture_path(Storage* storage, char* out, size_t out_len) {
    for(uint16_t index = 0; index < 1000; index++) {
        int wrote = snprintf(out, out_len, "%s/Capture_%u.log", PATHLOGS, index);
        if(wrote < 0 || (size_t)wrote >= out_len) return false;
        if(!storage_file_exists(storage, out)) return true;
    }
    return false;
}
typedef struct {
    File* file;
    uint8_t buf[256];
    size_t len;
    size_t pos;
    bool eof;
    bool failed;
} LineReader;

static int reader_get(LineReader* reader) {
    if(reader->pos >= reader->len) {
        if(reader->eof) return -1;
        if(worker_stopped()) { reader->eof = true; return -1; }
        reader->len = storage_file_read(reader->file, reader->buf, sizeof(reader->buf));
        reader->pos = 0;
        if(reader->len == 0) {
            reader->failed = storage_file_get_error(reader->file) != FSE_OK;
            reader->eof = true;
            return -1;
        }
    }
    return reader->buf[reader->pos++];
}

static bool reader_line(LineReader* reader, char* out, size_t out_len) {
    size_t n = 0;
    bool any = false;
    for(;;) {
        int ch = reader_get(reader);
        if(ch < 0) {
            out[n] = '\0';
            return any;
        }
        any = true;
        if(ch == '\n') {
            out[n] = '\0';
            return true;
        }
        if(ch == '\r') continue;
        if(n + 1 < out_len) {
            out[n++] = (char)ch;
            continue;
        }
        int extra = 0;
        do {
            extra = reader_get(reader);
        } while(extra >= 0 && extra != '\n');
        out[0] = '\0';
        return false;
    }
}

static bool send_with_retry(MCP2515* mcp, CANFRAME* frame) {
    for(uint8_t attempt = 0; attempt < 3 && !worker_stopped(); attempt++) {
        ERROR_CAN status = send_can_frame(mcp, frame);
        if(status == ERROR_OK) return true;
        // Only a busy buffer proves no request was submitted. Timeouts/SPI
        // errors may have reached the bus, so never duplicate them by retrying.
        if(status != ERROR_ALLTXBUSY) return false;
        furi_delay_ms(1);
    }
    return false;
}

static void stop_join(App* app) {
    if(!app->thread) return;
    FuriThreadId id = furi_thread_get_id(app->thread);
    if(id) furi_thread_flags_set(id, THREAD_SNIFFER_STOP);
    furi_thread_join(app->thread);
    furi_thread_free(app->thread);
    app->thread = NULL;
}
static int32_t capture_worker(void* context) {
    App* app = context;
    MCP2515* mcp = app->mcp_can;
    char path[LOG_PATH_SIZE];
    if(!resolve_capture_path(app->storage, path, sizeof(path))) { trace_finish(2); return 0; }
    trace_set_label(path);
    CanRecorder* recorder = can_recorder_open(app->storage, path);
    if(!recorder) { trace_finish(2); return 0; }
    mcp->mode = MCP_NORMAL;
    if(mcp2515_init(mcp) != ERROR_OK) {
        deinit_mcp2515(mcp);
        can_recorder_close(recorder);
        trace_finish(1);
        return 0;
    }
    CanClock clock = can_clock_start();
    uint32_t last_poll = furi_get_tick();
    uint32_t burst = 0;
    uint8_t failure = 0;
    while(!worker_stopped()) {
        CANFRAME frame;
        ERROR_CAN status = read_can_message(mcp, &frame);
        uint64_t rel = can_clock_us(&clock);
        if(status == ERROR_OK) {
            can_recorder_put(recorder, &frame, rel);
            trace_note_frame(&frame, rel / 1000, false);
            if((++burst & 15U) == 0) furi_thread_yield();
        } else if(status == ERROR_NOMSG) {
            furi_delay_us(100);
        } else { failure = 4; break; }
        uint32_t now = furi_get_tick();
        if(now - last_poll >= 100) {
            uint8_t errors = get_error(mcp);
            trace_note_overrun(!!(errors & MCP_EFLG_RX0OVR) + !!(errors & MCP_EFLG_RX1OVR));
            CanRecorderStats stats = can_recorder_stats(recorder);
            furi_mutex_acquire(trace.mutex, FuriWaitForever);
            trace.queue_dropped = stats.dropped;
            trace.elapsed_ms = rel / 1000;
            furi_mutex_release(trace.mutex);
            if(stats.failed) { failure = 3; break; }
            last_poll = now;
        }
    }
    can_clock_stop(&clock);
    deinit_mcp2515(mcp); // Stop RX before draining the writer queue.
    CanRecorderStats stats = can_recorder_close(recorder);
    furi_mutex_acquire(trace.mutex, FuriWaitForever);
    trace.queue_dropped = stats.dropped;
    furi_mutex_release(trace.mutex);
    trace_finish(stats.failed ? 3 : failure);
    return 0;
}

static int32_t replay_worker(void* context) {
    App* app = context;
    const char* path = furi_string_get_cstr(app->path);
    trace_set_label(path);

    MCP2515* mcp = app->mcp_can;
    mcp->mode = MCP_NORMAL;
    if(mcp2515_init(mcp) != ERROR_OK) {
        deinit_mcp2515(mcp);
        trace_finish(1);
        return 0;
    }

    File* file = storage_file_alloc(app->storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(file);
        deinit_mcp2515(mcp);
        trace_finish(2);
        return 0;
    }

    CanClock clock = can_clock_start();
    bool again = true;
    uint8_t replay_failed = 0;
    while(again && !worker_stopped()) {
        again = false;
        if(!storage_file_seek(file, 0, true)) {
            replay_failed = 2;
            break;
        }
        LineReader reader;
        memset(&reader, 0, sizeof(reader));
        reader.file = file;
        CanReplaySchedule schedule = {0};
        uint32_t pass_frames = 0;
        char line[LOG_LINE_MAX];

        while(!worker_stopped()) {
            can_clock_us(&clock);
            bool got = reader_line(&reader, line, sizeof(line));
            if(reader.failed) { replay_failed = 2; break; }
            if(!got) {
                if(reader.eof) {
                    if(reader.failed) replay_failed = 2;
                    break;
                }
                furi_mutex_acquire(trace.mutex, FuriWaitForever);
                trace.invalid_lines++;
                furi_mutex_release(trace.mutex);
                continue;
            }
            CANFRAME frame;
            uint64_t ts = 0;
            if(!can_trace_parse(line, &frame, &ts)) {
                if(line[0] && line[0] != '#') {
                    furi_mutex_acquire(trace.mutex, FuriWaitForever);
                    trace.invalid_lines++;
                    furi_mutex_release(trace.mutex);
                }
                continue;
            }
            uint64_t deadline = 0;
            bool capped = false;
            if(!can_replay_schedule(&schedule, ts, can_clock_us(&clock), replay_timing, &deadline, &capped)) {
                // A decreasing timestamp is ambiguous: skip instead of bursting.
                furi_mutex_acquire(trace.mutex, FuriWaitForever);
                trace.invalid_lines++;
                furi_mutex_release(trace.mutex);
                continue;
            }
            if(!can_wait_until(&clock, deadline)) break;
            if(can_clock_us(&clock) > deadline + 1000) {
                furi_mutex_acquire(trace.mutex, FuriWaitForever);
                trace.late_frames++;
                furi_mutex_release(trace.mutex);
            }

            bool sent = send_with_retry(mcp, &frame);
            if(capped) {
                furi_mutex_acquire(trace.mutex, FuriWaitForever);
                trace.gap_capped++;
                furi_mutex_release(trace.mutex);
            }
            trace_note_frame(&frame, can_clock_us(&clock) / 1000, !sent);
            pass_frames++;
            if(!sent && !worker_stopped()) { replay_failed = 5; break; }
        }

        if(replay_loop && !replay_failed && !worker_stopped() && pass_frames) again = true;
    }

    can_clock_stop(&clock);
    storage_file_close(file);
    storage_file_free(file);
    deinit_mcp2515(mcp);
    trace_finish(replay_failed);
    return 0;
}
static void format_clock(char* out, size_t n, uint32_t ms) {
    uint32_t total = ms / 1000U;
    snprintf(out, n, "%02lu:%02lu", (unsigned long)(total / 60U), (unsigned long)(total % 60U));
}

static void refresh_trace_text(App* app, bool capturing) {
    TraceState snap;
    furi_mutex_acquire(trace.mutex, FuriWaitForever);
    snap = trace;
    furi_mutex_release(trace.mutex);

    char clock[16];
    format_clock(clock, sizeof(clock), snap.elapsed_ms);

    char idbuf[12] = "--";
    char hex[40] = "--";
    if(snap.frames > 0) {
        if(snap.last_ext) snprintf(idbuf, sizeof(idbuf), "%08lX", (unsigned long)snap.last_id);
        else snprintf(idbuf, sizeof(idbuf), "%03lX", (unsigned long)snap.last_id);
        char top[16] = {0};
        char bot[16] = {0};
        size_t top_n = 0;
        size_t bot_n = 0;
        uint8_t count = snap.last_dlc;
        if(count > 8) count = 8;
        for(uint8_t i = 0; i < count; i++) {
            char* dest = i < 4 ? top : bot;
            size_t cap = 16;
            size_t* used = i < 4 ? &top_n : &bot_n;
            int wrote = snprintf(dest + *used, cap - *used, "%s%02X", *used ? " " : "", snap.last_data[i]);
            if(wrote < 0) break;
            *used += (size_t)wrote;
        }
        snprintf(hex, sizeof(hex), "%s%s%s", top, bot[0] ? "\n" : "", bot);
    }
    const char* name = snap.file_label[0] ? snap.file_label : "...";
    if(capturing) {
        const char* state = "REC";
        if(snap.finished) {
            state = snap.fail == 2 ? "FILE" : snap.fail == 3 ? "WRITE" : snap.fail ? "RX FAIL" : "SAVED";
        }
        furi_string_printf(
            app->text,
            "CAPTURE %s %s\nn=%lu hw=%lu q=%lu\n%s\n%s L%u\n%s\nBACK saves",
            state,
            clock,
            (unsigned long)snap.frames,
            (unsigned long)snap.rx_overrun,
            (unsigned long)snap.queue_dropped,
            name,
            idbuf,
            snap.last_dlc,
            hex);
    } else {
        const char* state = snap.finished ? (snap.fail ? "FAIL" : "DONE") : "RUN";
        furi_string_printf(
            app->text,
            "REPLAY %s %s\n%s %s\nn=%lu err=%lu late=%lu bad=%lu\n%s L%u\n%s\nBACK stops",
            state,
            replay_timing ? "FAST" : "REAL",
            replay_loop ? "LOOP" : "ONCE",
            name,
            (unsigned long)snap.frames,
            (unsigned long)snap.tx_error,
            (unsigned long)snap.late_frames,
            (unsigned long)snap.invalid_lines,
            idbuf,
            snap.last_dlc,
            hex);
    }
    text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
}

static bool trace_tick(App* app, bool capturing) {
    if(!trace.mutex) return false;
    uint8_t fail = 0;
    furi_mutex_acquire(trace.mutex, FuriWaitForever);
    fail = trace.fail;
    furi_mutex_release(trace.mutex);
    if(fail == 1 && !trace_error_view) {
        trace_error_view = true;
        draw_device_no_connected(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewWidget);
        return true;
    }
    if(!trace_error_view) refresh_trace_text(app, capturing);
    return true;
}

static void show_text(App* app, const char* text) {
    text_box_reset(app->textBox);
    text_box_set_font(app->textBox, TextBoxFontText);
    furi_string_set(app->text, text);
    text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
}

void app_scene_capture_on_enter(void* context) {
    App* app = context;
    trace_error_view = false;
    trace_reset();
    app->thread = furi_thread_alloc_ex("CanCapture", CAPTURE_STACK, capture_worker, app);
    furi_thread_start(app->thread);
    show_text(app, "CAPTURE\nStarting...");
}

bool app_scene_capture_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    if(event.type == SceneManagerEventTypeTick) return trace_tick(app, true);
    return false;
}

void app_scene_capture_on_exit(void* context) {
    App* app = context;
    stop_join(app);
    trace_clear();
    text_box_reset(app->textBox);
    widget_reset(app->widget);
}

static void replay_timing_changed(VariableItem* item) {
    replay_timing = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, replay_timing_text[replay_timing]);
}

static void replay_loop_changed(VariableItem* item) {
    replay_loop = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, replay_loop_text[replay_loop]);
}

static void replay_enter_callback(void* context, uint32_t index) {
    App* app = context;
    if(index != 2) return;

    // The item callback holds the view model lock. Open dialogs only after
    // returning to the dispatcher's event loop, where that lock is released.
    view_dispatcher_send_custom_event(app->view_dispatcher, ReplayEventChooseLog);
}

static void replay_choose_log(App* app) {
    DialogsFileBrowserOptions options;
    dialog_file_browser_set_basic_options(&options, ".log", NULL);
    options.base_path = PATHLOGS;

    FuriString* start = furi_string_alloc_set(PATHLOGS);
    bool selected = dialog_file_browser_show(app->dialogs, app->path, start, &options);
    furi_string_free(start);
    if(selected) scene_manager_next_scene(app->scene_manager, app_scene_replay_run_option);
}

void app_scene_replay_on_enter(void* context) {
    App* app = context;
    VariableItem* item;
    variable_item_list_reset(app->varList);

    item = variable_item_list_add(app->varList, "Timing", 2, replay_timing_changed, app);
    variable_item_set_current_value_index(item, replay_timing);
    variable_item_set_current_value_text(item, replay_timing_text[replay_timing]);

    item = variable_item_list_add(app->varList, "Loop", 2, replay_loop_changed, app);
    variable_item_set_current_value_index(item, replay_loop);
    variable_item_set_current_value_text(item, replay_loop_text[replay_loop]);

    variable_item_list_add(app->varList, "Choose log", 0, NULL, app);
    variable_item_list_set_enter_callback(app->varList, replay_enter_callback, app);
    variable_item_list_set_selected_item(app->varList, 2);
    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

bool app_scene_replay_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    if(event.type == SceneManagerEventTypeCustom && event.event == ReplayEventChooseLog) {
        replay_choose_log(app);
        return true;
    }
    return false;
}

void app_scene_replay_on_exit(void* context) {
    App* app = context;
    variable_item_list_reset(app->varList);
}

void app_scene_replay_run_on_enter(void* context) {
    App* app = context;
    trace_error_view = false;
    app->thread = NULL;
    if(furi_string_empty(app->path)) {
        show_text(app, "REPLAY\nNo file");
        return;
    }
    trace_reset();
    app->thread = furi_thread_alloc_ex("CanReplay", REPLAY_STACK, replay_worker, app);
    furi_thread_start(app->thread);
    show_text(app, "REPLAY\nStarting...");
}

bool app_scene_replay_run_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    if(!app->thread) return false;
    if(event.type == SceneManagerEventTypeTick) return trace_tick(app, false);
    return false;
}

void app_scene_replay_run_on_exit(void* context) {
    App* app = context;
    stop_join(app);
    trace_clear();
    text_box_reset(app->textBox);
    widget_reset(app->widget);
}
