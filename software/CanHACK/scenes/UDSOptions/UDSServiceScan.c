#include "../../app_user.h"


static int32_t uds_service_scan_thread(void* context);

void app_scene_uds_service_scan_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusEnd);

    app->thread = furi_thread_alloc_ex("UdsSvcScan", 4 * 1024, uds_service_scan_thread, app);
    furi_thread_start(app->thread);

    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
}

bool app_scene_uds_service_scan_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_service_scan_on_exit(void* context) {
    App* app = context;
    app_uds_stop_worker(app);
    text_box_reset(app->textBox);
    uds_stop_keepalive();
}

static int32_t uds_service_scan_thread(void* context) {
    App* app = context;
    UDS_SERVICE* uds = app_uds_open(app);
    if(!uds) {
        text_box_set_text(app->textBox, "CAN/session init failed");
        return 0;
    }
    furi_string_reset(app->data);
    furi_string_set(app->text, "Service scan\n");
    uint16_t found = 0;
    uint16_t no_response = 0;
    uint32_t last_update = furi_get_tick() - 100;
    uint8_t response[UDS_PAYLOAD_MAX];
    for(uint16_t service = 0; service <= 0xFF && !uds_worker_cancelled(); service++) {
        uds_keepalive(uds);
        uint8_t request = service;
        size_t len = 0;
        UdsStatus status = uds_request_payload(uds, &request, 1, response, sizeof(response), &len);
        if(status == UdsOk || (status == UdsNegative && response[2] != 0x11)) {
            found++;
            if(furi_string_size(app->data) > 6000) furi_string_set(app->data, "Earlier results omitted\n");
            furi_string_cat_printf(app->data, "%02X %s: ", service, uds_get_service_name(service));
            if(status == UdsOk) furi_string_cat_printf(app->data, "positive\n");
            else furi_string_cat_printf(app->data, "NRC %02X %s\n", response[2], uds_get_nrc_name(response[2]));
        } else if(status != UdsNegative && status != UdsCancelled) no_response++;
        uint32_t now = furi_get_tick();
        if(now - last_update >= 100 || service == 0xFF) {
            furi_string_printf(app->text, "Service %02X / FF\nSupported/evidence %u\nNo valid response %u\n%s\nBACK: cancel",
                service, found, no_response, furi_string_get_cstr(app->data));
            text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
            last_update = now;
        }
        if(!app_uds_delay(uds, app->uds_gap_ms)) break;
    }
    furi_string_cat_printf(app->text, "\n%s", uds_worker_cancelled() ? "Cancelled" : "Scan complete");
    text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
    free_uds(uds);
    return 0;
}
