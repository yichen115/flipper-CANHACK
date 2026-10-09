#include "../../app_user.h"

static int32_t info_worker(void* context) {
    App* app = context;
    UDS_SERVICE* uds = app_uds_open(app);
    furi_string_printf(app->text, "TX %03lX RX %03lX\n", app->uds_send_id, app->uds_received_id);
    if(!uds) {
        furi_string_cat_printf(app->text, "CAN/session init failed");
    } else {
        static const uint16_t dids[] = {0xF186, 0xF189, 0xF190, 0xF187, 0xF18C, 0xF191};
        static const char* labels[] = {"Session", "SW", "VIN", "Part", "Serial", "HW"};
        uint8_t response[UDS_PAYLOAD_MAX];
        for(size_t i = 0; i < COUNT_OF(dids) && !uds_worker_cancelled(); i++) {
            uint8_t request[] = {0x22, dids[i] >> 8, dids[i] & 0xFF};
            size_t len = 0;
            UdsStatus status = uds_request_payload(uds, request, sizeof(request), response, sizeof(response), &len);
            furi_string_cat_printf(app->text, "%s %04X: ", labels[i], dids[i]);
            if(status == UdsOk) {
                bool printable = len > 3;
                for(size_t j = 3; j < len; j++) {
                    if(response[j] < 32 || response[j] > 126) printable = false;
                }
                for(size_t j = 3; j < len; j++) {
                    if(printable) furi_string_cat_printf(app->text, "%c", response[j]);
                    else furi_string_cat_printf(app->text, "%02X ", response[j]);
                }
            } else if(status == UdsNegative) {
                furi_string_cat_printf(app->text, "NRC %02X", response[2]);
            } else {
                furi_string_cat_printf(app->text, "%s", uds_status_name(status));
            }
            furi_string_cat_printf(app->text, "\n");
            text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
            if(!app_uds_delay(uds, app->uds_gap_ms)) break;
        }
        free_uds(uds);
    }
    text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
    return 0;
}

void app_scene_uds_info_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusStart);
    text_box_set_text(app->textBox, "Reading ECU...\nBACK: cancel");
    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
    app->thread = furi_thread_alloc_ex("UdsInfo", 4096, info_worker, app);
    furi_thread_start(app->thread);
}

bool app_scene_uds_info_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_info_on_exit(void* context) {
    App* app = context;
    app_uds_stop_worker(app);
    text_box_reset(app->textBox);
}
