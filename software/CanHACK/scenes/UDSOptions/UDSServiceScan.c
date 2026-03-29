#include "../../app_user.h"

#define SVC_SCAN_DELAY_MS       50  // Delay between each service probe
#define SVC_KEEPALIVE_INTERVAL  50  // Send TesterPresent every N iterations

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
    furi_thread_join(app->thread);
    furi_thread_free(app->thread);
    text_box_reset(app->textBox);
    uds_stop_keepalive();
}

static int32_t uds_service_scan_thread(void* context) {
    App* app = context;
    MCP2515* mcp = app->mcp_can;
    FuriString* text = app->text;

    furi_string_reset(text);

    UDS_SERVICE* uds = uds_service_alloc(
        app->uds_send_id, app->uds_received_id, MCP_NORMAL, mcp->clck, mcp->bitRate);

    if(!uds_init(uds)) {
        furi_string_cat_printf(text, "Device not connected\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        free_uds(uds);
        return 0;
    }

    furi_delay_ms(500);

    furi_string_cat_printf(
        text,
        "TX:0x%lX RX:0x%lX\nScanning services...\n\n",
        app->uds_send_id,
        app->uds_received_id);
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    uint8_t found_count = 0;
    uint16_t iter_count = 0;

    for(uint16_t svc_id = 0x00; svc_id <= 0xFF; svc_id++) {
        if(!furi_hal_gpio_read(&gpio_button_back)) break;

        // Inter-request delay to avoid overwhelming the ECU
        furi_delay_ms(SVC_SCAN_DELAY_MS);

        // Periodic TesterPresent to maintain session
        iter_count++;
        if(iter_count % SVC_KEEPALIVE_INTERVAL == 0) {
            uds_tester_present(uds);
            furi_delay_ms(10);
        }

        uint8_t data[1] = {(uint8_t)svc_id};
        CANFRAME frames_to_send[2] = {0};
        CANFRAME frame_to_received = {0};

        bool got_response = uds_multi_frame_request(
            uds, data, 1, frames_to_send, 1, &frame_to_received);

        if(!got_response) continue;

        bool is_supported = false;

        if(frame_to_received.buffer[1] != 0x7F) {
            is_supported = true;
        } else if(frame_to_received.buffer[3] != UDS_NRC_SERVICE_NOT_SUPPORTED) {
            is_supported = true;
        }

        if(is_supported) {
            found_count++;
            const char* name = uds_get_service_name((uint8_t)svc_id);
            if(frame_to_received.buffer[1] != 0x7F) {
                furi_string_cat_printf(
                    text, "0x%02X %s [+]\n", (uint8_t)svc_id, name);
            } else {
                uint8_t nrc = frame_to_received.buffer[3];
                furi_string_cat_printf(
                    text,
                    "0x%02X %s\n  NRC:0x%02X %s\n",
                    (uint8_t)svc_id,
                    name,
                    nrc,
                    uds_get_nrc_name(nrc));
            }
            text_box_set_text(app->textBox, furi_string_get_cstr(text));
        }
    }

    if(found_count == 0) {
        furi_string_cat_printf(text, "No services found\n");
    } else {
        furi_string_cat_printf(text, "\nFound %u service(s)\n", found_count);
    }

    furi_string_cat_printf(text, "Scan complete.");
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    free_uds(uds);
    return 0;
}
