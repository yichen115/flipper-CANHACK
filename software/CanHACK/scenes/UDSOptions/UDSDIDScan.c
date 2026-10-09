#include "../../app_user.h"
#include <datetime/datetime.h>


typedef enum {
    DidRangeIdentification,
    DidRangeCommon,
    DidRangeOem,
    DidRangeExtended,
    DidRangeFullScan,
    DidRangeQuick,
} DidRangeItems;

static uint16_t did_scan_min = 0xF100;
static uint16_t did_scan_max = 0xF1FF;
static uint32_t did_scan_selector = 0;

static int32_t uds_did_scan_thread(void* context);

/**
 * DID Scan Menu - select scan range
 */

static void did_scan_select(void* context, uint32_t index) {
    App* app = context;
    did_scan_selector = index;

    switch(index) {
    case DidRangeQuick:
        did_scan_min = 0xF180;
        did_scan_max = 0xF1A0;
        break;
    case DidRangeIdentification:
        did_scan_min = 0xF100;
        did_scan_max = 0xF1FF;
        break;
    case DidRangeCommon:
        did_scan_min = 0xF000;
        did_scan_max = 0xF0FF;
        break;
    case DidRangeOem:
        did_scan_min = 0x0100;
        did_scan_max = 0x01FF;
        break;
    case DidRangeExtended:
        did_scan_min = 0xFD00;
        did_scan_max = 0xFEFF;
        break;
    case DidRangeFullScan:
        did_scan_min = 0x0000;
        did_scan_max = 0xFFFF;
        break;
    default:
        break;
    }

    scene_manager_next_scene(app->scene_manager, app_scene_uds_did_scan_result_option);
}

static void did_scan_menu_callback(void* context, uint32_t index) {
    App* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void app_scene_uds_did_scan_menu_on_enter(void* context) {
    App* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "DID Scanner");
    submenu_add_item(app->submenu, "Quick ID (F180-F1A0)", DidRangeQuick, did_scan_menu_callback, app);

    submenu_add_item(
        app->submenu, "ID (0xF100-F1FF)", DidRangeIdentification, did_scan_menu_callback, app);
    submenu_add_item(
        app->submenu, "Common (0xF000-F0FF)", DidRangeCommon, did_scan_menu_callback, app);
    submenu_add_item(
        app->submenu, "OEM (0x0100-01FF)", DidRangeOem, did_scan_menu_callback, app);
    submenu_add_item(
        app->submenu, "Extended (0xFD00-FEFF)", DidRangeExtended, did_scan_menu_callback, app);
    submenu_add_item(
        app->submenu, "Full (0x0000-FFFF)", DidRangeFullScan, did_scan_menu_callback, app);

    submenu_set_selected_item(app->submenu, did_scan_selector);
    view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);
}

bool app_scene_uds_did_scan_menu_on_event(void* context, SceneManagerEvent event) {
    if(event.type == SceneManagerEventTypeCustom && event.event <= DidRangeFullScan) {
        did_scan_select(context, event.event);
        return true;
    }
    return false;
}

void app_scene_uds_did_scan_menu_on_exit(void* context) {
    App* app = context;
    submenu_reset(app->submenu);
    // Stop session keepalive
    uds_stop_keepalive();
}

/**
 * DID Scan Result
 */

void app_scene_uds_did_scan_result_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusEnd);

    app->thread = furi_thread_alloc_ex("DIDScan", 4 * 1024, uds_did_scan_thread, app);
    furi_thread_start(app->thread);

    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
}

bool app_scene_uds_did_scan_result_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_did_scan_result_on_exit(void* context) {
    App* app = context;
    app_uds_stop_worker(app);
    text_box_reset(app->textBox);
}

/**
 * Thread: scan DIDs in selected range
 */
static int32_t uds_did_scan_thread(void* context) {
    App* app = context;
    UDS_SERVICE* uds = app_uds_open(app);
    if(!uds) {
        text_box_set_text(app->textBox, "CAN/session init failed");
        return 0;
    }
    // Results are streamed to storage; the on-screen history stays bounded.
    File* log = storage_file_alloc(app->storage);
    DateTime date;
    furi_hal_rtc_get_datetime(&date);
    furi_string_printf(app->path, "%s/DID_%04u%02u%02u_%02u%02u%02u_%lu.txt",
        PATHLOGS, date.year, date.month, date.day, date.hour, date.minute, date.second, furi_get_tick());
    bool log_open = storage_file_open(log, furi_string_get_cstr(app->path), FSAM_WRITE, FSOM_CREATE_NEW);
    bool log_failed = false;
    uint32_t start = furi_get_tick();
    uint32_t last_update = start - 100;
    uint32_t scanned = 0;
    uint32_t found = 0;
    uint32_t rejected = 0;
    uint32_t errors = 0;
    furi_string_reset(app->data);
    FuriString* line = furi_string_alloc();
    furi_string_printf(line, "DID %04X-%04X TX %lX RX %lX\n", did_scan_min, did_scan_max, app->uds_send_id, app->uds_received_id);
    if(log_open && storage_file_write(log, furi_string_get_cstr(line), furi_string_size(line)) != furi_string_size(line)) log_failed = true;
    uint8_t response[UDS_PAYLOAD_MAX];
    for(uint32_t did = did_scan_min; did <= did_scan_max && !uds_worker_cancelled() && !log_failed; did++) {
        uint8_t request[] = {0x22, did >> 8, did & 0xFF};
        size_t len = 0;
        uds_keepalive(uds);
        UdsStatus status = uds_request_payload(uds, request, sizeof(request), response, sizeof(response), &len);
        scanned++;
        furi_string_reset(line);
        if(status == UdsOk) {
            found++;
            furi_string_printf(line, "%04lX [%u bytes]", did, (unsigned)(len - 3));
            for(size_t i = 3; i < len; i++) furi_string_cat_printf(line, " %02X", response[i]);
            furi_string_cat_printf(line, "\nASCII: ");
            for(size_t i = 3; i < len; i++) {
                furi_string_cat_printf(line, "%c", response[i] >= 32 && response[i] <= 126 ? response[i] : '.');
            }
            furi_string_cat_printf(line, "\n");
        } else if(status == UdsNegative) {
            rejected++;
            if(response[2] != 0x31 && response[2] != 0x11 && response[2] != 0x12) {
                furi_string_printf(line, "%04lX NRC %02X %s\n", did, response[2], uds_get_nrc_name(response[2]));
            }
        } else if(status != UdsCancelled) {
            errors++;
            if(status != UdsTimeout) furi_string_printf(line, "%04lX %s\n", did, uds_status_name(status));
        }
        if(!furi_string_empty(line)) {
            if(log_open && storage_file_write(log, furi_string_get_cstr(line), furi_string_size(line)) != furi_string_size(line)) log_failed = true;
            if(furi_string_size(app->data) > 4000) furi_string_set(app->data, "Earlier results in log\n");
            furi_string_cat(app->data, line);
        }
        uint32_t now = furi_get_tick();
        if(now - last_update >= 100 || did == did_scan_max) {
            furi_string_printf(app->text,
                "DID %04lX %lu/%lu\nOK %lu NRC %lu err %lu\n%s\nBACK: cancel",
                did, scanned, (uint32_t)did_scan_max - did_scan_min + 1,
                found, rejected, errors, furi_string_get_cstr(app->data));
            text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
            last_update = now;
        }
        if(!app_uds_delay(uds, app->uds_gap_ms)) break;
    }
    furi_string_printf(line, "\n%s: scanned %lu, positive %lu, NRC %lu, errors %lu, elapsed %lu ms\n",
        uds_worker_cancelled() ? "Cancelled" : log_failed ? "Log write failed" : "Complete",
        scanned, found, rejected, errors, furi_get_tick() - start);
    if(log_open && !log_failed && storage_file_write(log, furi_string_get_cstr(line), furi_string_size(line)) != furi_string_size(line)) log_failed = true;
    if(log_open) storage_file_close(log);
    storage_file_free(log);
    furi_string_printf(app->text, "%s\n%s\n%s%s", furi_string_get_cstr(app->data), furi_string_get_cstr(line),
        log_failed ? "PARTIAL LOG: " : log_open ? "Saved: " : "Log unavailable: ", furi_string_get_cstr(app->path));
    text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
    furi_string_free(line);
    free_uds(uds);
    return 0;
}
