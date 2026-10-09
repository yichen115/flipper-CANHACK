#include "../app_user.h"
#include "../libraries/can_clock.h"
#include "../libraries/can_recorder.h"
void sniffing_callback(void* context, uint32_t index);

// Only the CAN worker configures filters and writes the frame cache. The
// dispatcher renders snapshots and requests mode changes under this mutex.
static struct {
    FuriMutex* mutex;
    bool active;
    bool detail;
    bool init_failed;
    bool rx_failed;
    bool log_failed;
    uint8_t count;
    uint8_t selected;
    uint8_t displayed;
    uint32_t received;
    uint32_t hardware_overruns;
    uint32_t queue_dropped;
    uint32_t current_drops;
    uint32_t address_limit;
} sniff;

static bool log_path(App* app, bool address, uint32_t id) {
    for(uint16_t index = 0; index < 1000; index++) {
        int n;
        if(address) n = snprintf(app->log_file_path, LOG_PATH_SIZE, "%s/L_0x%lX_%u.log", PATHLOGS, id, index);
        else n = snprintf(app->log_file_path, LOG_PATH_SIZE, "%s/Log_%u.log", PATHLOGS, index);
        if(n < 0 || n >= LOG_PATH_SIZE) return false;
        if(!storage_file_exists(app->storage, app->log_file_path)) return true;
    }
    return false;
}

static void sniff_stop(App* app) {
    if(!sniff.active) return;
    if(app->thread) {
        FuriThreadId id = furi_thread_get_id(app->thread);
        if(id) furi_thread_flags_set(id, THREAD_SNIFFER_STOP);
        furi_thread_join(app->thread);
        furi_thread_free(app->thread);
        app->thread = NULL;
    }
    furi_mutex_free(sniff.mutex);
    memset(&sniff, 0, sizeof(sniff));
}

static void sniff_render(App* app, bool detail) {
    furi_mutex_acquire(sniff.mutex, FuriWaitForever);
    uint8_t count = sniff.count;
    uint8_t selected = sniff.selected;
    bool failed = sniff.init_failed || sniff.rx_failed;
    bool log_failed = sniff.log_failed;
    uint32_t received = sniff.received, overrun = sniff.hardware_overruns, dropped = sniff.queue_dropped + sniff.current_drops;
    uint32_t limited = sniff.address_limit;
    CANFRAME frame = {0};
    uint32_t interval = 0;
    if(selected < count) { frame = app->frameArray[selected]; interval = app->times[selected]; }
    furi_mutex_release(sniff.mutex);
    if(failed) {
        text_box_set_text(app->textBox, "CAN receive failed\nBACK: return");
        view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
        return;
    }
    if(detail) {
        furi_string_printf(app->text, "%s %03lX DLC %u%s\n", frame.ext ? "EXT" : "STD", frame.canId,
            frame.data_length, frame.req ? " RTR" : "");
        for(uint8_t i = 0; i < frame.data_length && !frame.req; i++) furi_string_cat_printf(app->text, "%02X ", frame.buffer[i]);
        furi_string_cat_printf(app->text, "\nInterval %lu ms\nRX %lu hw %lu q %lu%s\nBACK: address list",
            interval, received, overrun, dropped, log_failed ? "\nLOG FAILED" : "");
        text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
    } else {
        while(sniff.displayed < count) {
            uint8_t index = sniff.displayed++;
            furi_mutex_acquire(sniff.mutex, FuriWaitForever);
            CANFRAME item = app->frameArray[index];
            furi_mutex_release(sniff.mutex);
            char label[24];
            snprintf(label, sizeof(label), "%s %03lX", item.ext ? "EXT" : "STD", item.canId);
            submenu_add_item(app->submenu, label, index, sniffing_callback, app);
        }
        char header[64];
        snprintf(header, sizeof(header), "IDs %u RX %lu H%lu Q%lu%s%s", count, received, overrun, dropped,
            log_failed ? " LOG!" : "", limited ? " LIMIT" : "");
        submenu_set_header(app->submenu, header);
    }
}

void sniffing_callback(void* context, uint32_t index) {
    App* app = context;
    // Submenu callbacks hold its model lock; transition on the dispatcher.
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void app_scene_sniffing_on_enter(void* context) {
    App* app = context;
    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "CAN addresses...");
    if(!sniff.active) {
        memset(&sniff, 0, sizeof(sniff));
        sniff.mutex = furi_mutex_alloc(FuriMutexTypeNormal);
        sniff.active = true;
        app->num_of_devices = 0;
        memset(app->frameArray, 0, 100 * sizeof(CANFRAME));
        memset(app->current_time, 0, sizeof(app->current_time));
        app->thread = furi_thread_alloc_ex("CanSniffer", 4096, worker_sniffing, app);
        furi_thread_start(app->thread);
    }
    sniff.displayed = 0;
    view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);
    sniff_render(app, false);
}

bool app_scene_sniffing_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    if(event.type == SceneManagerEventTypeTick) { sniff_render(app, false); return true; }
    if(event.type == SceneManagerEventTypeCustom) {
        furi_mutex_acquire(sniff.mutex, FuriWaitForever);
        bool valid = event.event < sniff.count;
        if(valid) { sniff.selected = event.event; sniff.detail = true; app->sniffer_index = event.event; }
        furi_mutex_release(sniff.mutex);
        if(valid) scene_manager_next_scene(app->scene_manager, app_scene_box_sniffing);
        return valid;
    }
    return false;
}

void app_scene_sniffing_on_exit(void* context) {
    App* app = context;
    furi_mutex_acquire(sniff.mutex, FuriWaitForever);
    bool detail = sniff.detail;
    furi_mutex_release(sniff.mutex);
    if(!detail) sniff_stop(app);
    submenu_reset(app->submenu);
}

void app_scene_box_sniffing_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusStart);
    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
    sniff_render(app, true);
}

bool app_scene_box_sniffing_on_event(void* context, SceneManagerEvent event) {
    if(event.type == SceneManagerEventTypeTick) { sniff_render(context, true); return true; }
    return false;
}

void app_scene_box_sniffing_on_exit(void* context) {
    App* app = context;
    furi_mutex_acquire(sniff.mutex, FuriWaitForever);
    sniff.detail = false;
    furi_mutex_release(sniff.mutex);
    text_box_reset(app->textBox);
}

int32_t worker_sniffing(void* context) {
    App* app = context;
    MCP2515* can = app->mcp_can;
    can->mode = MCP_NORMAL;
    if(mcp2515_init(can) != ERROR_OK) {
        furi_mutex_acquire(sniff.mutex, FuriWaitForever);
        sniff.init_failed = true;
        furi_mutex_release(sniff.mutex);
        deinit_mcp2515(can);
        return 0;
    }
    CanClock clock = can_clock_start();
    CanRecorder* recorder = NULL;
    bool logging_failed = false;
    if(app->save_logs == SaveAll) {
        if(log_path(app, false, 0)) recorder = can_recorder_open(app->storage, app->log_file_path);
        logging_failed = recorder == NULL;
    }
    bool last_detail = false;
    uint8_t last_selected = 0;
    uint32_t last_poll = furi_get_tick();
    uint32_t burst = 0;
    while(!(furi_thread_flags_get() & THREAD_SNIFFER_STOP)) {
        furi_mutex_acquire(sniff.mutex, FuriWaitForever);
        bool detail = sniff.detail;
        uint8_t selected = sniff.selected;
        CANFRAME target = app->frameArray[selected];
        furi_mutex_release(sniff.mutex);
        if(detail != last_detail || selected != last_selected) {
            // Save All keeps receiving the full bus while the detail page is open.
            // Only Address uses a software selection too, avoiding filter-change gaps.
            if(app->save_logs == OnlyAddress) {
                if(recorder) {
                    CanRecorderStats stats = can_recorder_close(recorder);
                    furi_mutex_acquire(sniff.mutex, FuriWaitForever);
                    sniff.queue_dropped += stats.dropped;
                    sniff.current_drops = 0;
                    sniff.log_failed |= stats.failed;
                    furi_mutex_release(sniff.mutex);
                    recorder = NULL;
                }
                if(detail) {
                    if(log_path(app, true, target.canId)) recorder = can_recorder_open(app->storage, app->log_file_path);
                    logging_failed |= recorder == NULL;
                }
            }
            last_detail = detail;
            last_selected = selected;
        }
        CANFRAME frame;
        ERROR_CAN status = read_can_message(can, &frame);
        uint64_t elapsed = can_clock_us(&clock);
        if(status == ERROR_OK) {
            bool is_target = frame.canId == target.canId && frame.ext == target.ext;
            if(recorder && (app->save_logs == SaveAll || (detail && is_target))) can_recorder_put(recorder, &frame, elapsed);
            furi_mutex_acquire(sniff.mutex, FuriWaitForever);
            uint8_t index = 0;
            while(index < sniff.count && (frame.canId != app->frameArray[index].canId || frame.ext != app->frameArray[index].ext)) index++;
            if(index < 100) {
                if(index == sniff.count) {
                    sniff.count++;
                    app->times[index] = 0;
                } else app->times[index] = (uint32_t)(elapsed / 1000) - app->current_time[index];
                app->frameArray[index] = frame;
                app->current_time[index] = elapsed / 1000;
            } else sniff.address_limit++;
            sniff.received++;
            app->num_of_devices = sniff.count;
            furi_mutex_release(sniff.mutex);
            if((++burst & 15U) == 0) furi_thread_yield();
        } else if(status == ERROR_NOMSG) furi_delay_us(100);
        else {
            furi_mutex_acquire(sniff.mutex, FuriWaitForever);
            sniff.rx_failed = true;
            furi_mutex_release(sniff.mutex);
            break;
        }
        if(furi_get_tick() - last_poll >= 100) {
            uint8_t errors = get_error(can);
            CanRecorderStats stats = recorder ? can_recorder_stats(recorder) : (CanRecorderStats){0};
            furi_mutex_acquire(sniff.mutex, FuriWaitForever);
            sniff.hardware_overruns += !!(errors & MCP_EFLG_RX0OVR) + !!(errors & MCP_EFLG_RX1OVR);
            sniff.log_failed |= logging_failed || stats.failed;
            sniff.current_drops = stats.dropped;
            furi_mutex_release(sniff.mutex);
            last_poll = furi_get_tick();
        }
    }
    can_clock_stop(&clock);
    deinit_mcp2515(can);
    if(recorder) {
        CanRecorderStats stats = can_recorder_close(recorder);
        furi_mutex_acquire(sniff.mutex, FuriWaitForever);
        sniff.queue_dropped += stats.dropped;
        sniff.current_drops = 0;
        sniff.log_failed |= stats.failed;
        furi_mutex_release(sniff.mutex);
    }
    return 0;
}
