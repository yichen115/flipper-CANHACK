#include "../../app_user.h"

#define DISCOVERY_TIMEOUT_US 15000

// Default values if not set
#define DEFAULT_SCAN_MIN 0x600
#define DEFAULT_SCAN_MAX 0x7FF

static int32_t uds_discovery_thread(void* context);

void app_scene_uds_ecu_discovery_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusEnd);

    app->thread = furi_thread_alloc_ex("UdsDisc", 4 * 1024, uds_discovery_thread, app);
    furi_thread_start(app->thread);

    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
}

bool app_scene_uds_ecu_discovery_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_ecu_discovery_on_exit(void* context) {
    App* app = context;
    furi_thread_join(app->thread);
    furi_thread_free(app->thread);
    text_box_reset(app->textBox);
}

static int32_t uds_discovery_thread(void* context) {
    App* app = context;
    FuriString* text = app->text;
    MCP2515* mcp = app->mcp_can;

    furi_string_reset(text);

    MCP2515* CAN = mcp_alloc(MCP_NORMAL, mcp->clck, mcp->bitRate);

    if(mcp2515_init(CAN) != ERROR_OK) {
        furi_string_cat_printf(text, "Device not connected\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        free_mcp2515(CAN);
        return 0;
    }

    init_mask(CAN, 0, 0);
    init_mask(CAN, 1, 0);

    // Get scan range from app settings, use defaults if not set
    uint32_t scan_min = app->ecu_discovery_start_id;
    uint32_t scan_max = app->ecu_discovery_end_id;
    
    furi_string_cat_printf(text, "Raw values: 0x%lX - 0x%lX\n", scan_min, scan_max);
    
    // If both are 0, use defaults
    if(scan_min == 0 && scan_max == 0) {
        scan_min = DEFAULT_SCAN_MIN;
        scan_max = DEFAULT_SCAN_MAX;
        furi_string_cat_printf(text, "Using defaults\n");
    }
    
    // Validate range
    if(scan_min > scan_max) {
        uint32_t temp = scan_min;
        scan_min = scan_max;
        scan_max = temp;
    }
    if(scan_min > 0x7FF) scan_min = 0x7FF;
    if(scan_max > 0x7FF) scan_max = 0x7FF;

    furi_string_cat_printf(
        text,
        "Scanning 0x%03lX-0x%03lX...\n",
        scan_min,
        scan_max);
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    if(scan_min == 0 && scan_max == 0) {
        furi_string_cat_printf(text, "Error: Range is 0\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        deinit_mcp2515(CAN);
        free(CAN);
        return 0;
    }

    uint8_t found_count = 0;

    for(uint32_t arb_id = scan_min; arb_id <= scan_max; arb_id++) {
        if(!furi_hal_gpio_read(&gpio_button_back)) break;

        CANFRAME frame_to_send = {0};
        frame_to_send.canId = arb_id;
        frame_to_send.data_length = 8;
        frame_to_send.buffer[0] = 0x02;
        frame_to_send.buffer[1] = 0x10;
        frame_to_send.buffer[2] = 0x01;
        // Pad remaining bytes
        for(uint8_t i = 3; i < 8; i++) frame_to_send.buffer[i] = 0xCC;

        if(send_can_frame(CAN, &frame_to_send) != ERROR_OK) continue;

        CANFRAME response = {0};
        uint32_t timeout = 0;
        bool got_response = false;

        while(timeout < DISCOVERY_TIMEOUT_US) {
            if(read_can_message(CAN, &response) == ERROR_OK) {
                if(response.buffer[1] == 0x50 || response.buffer[1] == 0x7F) {
                    got_response = true;
                    break;
                }
            }
            furi_delay_us(1);
            timeout++;
        }

        if(got_response) {
            found_count++;
            if(response.buffer[1] == 0x50) {
                furi_string_cat_printf(
                    text,
                    "ECU TX:0x%lX RX:0x%lX +\n",
                    arb_id,
                    response.canId);
            } else {
                uint8_t nrc = response.buffer[3];
                furi_string_cat_printf(
                    text,
                    "ECU TX:0x%lX RX:0x%lX\n  NRC:0x%02X %s\n",
                    arb_id,
                    response.canId,
                    nrc,
                    uds_get_nrc_name(nrc));
            }
            text_box_set_text(app->textBox, furi_string_get_cstr(text));
        }
    }

    if(found_count == 0) {
        furi_string_cat_printf(text, "\nNo ECU found\n");
    } else {
        furi_string_cat_printf(text, "\nFound %u ECU(s)\n", found_count);
    }

    furi_string_cat_printf(text, "Scan complete.");
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    deinit_mcp2515(CAN);
    free(CAN);
    return 0;
}
