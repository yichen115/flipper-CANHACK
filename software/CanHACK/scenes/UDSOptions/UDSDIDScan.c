#include "../../app_user.h"

typedef enum {
    DidRangeIdentification,
    DidRangeCommon,
    DidRangeOem,
    DidRangeExtended,
    DidRangeFullScan,
} DidRangeItems;

static uint16_t did_scan_min = 0xF100;
static uint16_t did_scan_max = 0xF1FF;
static uint32_t did_scan_selector = 0;

static int32_t uds_did_scan_thread(void* context);

/**
 * DID Scan Menu - select scan range
 */

void did_scan_menu_callback(void* context, uint32_t index) {
    App* app = context;
    did_scan_selector = index;

    switch(index) {
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

void app_scene_uds_did_scan_menu_on_enter(void* context) {
    App* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "DID Scanner");

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
    UNUSED(context);
    UNUSED(event);
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
    furi_thread_join(app->thread);
    furi_thread_free(app->thread);
    text_box_reset(app->textBox);
}

/**
 * Thread: scan DIDs in selected range
 */
static int32_t uds_did_scan_thread(void* context) {
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
        "DID Scan 0x%04X-0x%04X\n\n",
        did_scan_min,
        did_scan_max);
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    uint16_t found_count = 0;
    uint32_t total = (uint32_t)(did_scan_max - did_scan_min + 1);
    uint32_t scanned = 0;

    for(uint32_t did = did_scan_min; did <= did_scan_max; did++) {
        if(!furi_hal_gpio_read(&gpio_button_back)) break;

        scanned++;

        // Send Read DID request directly (0x22 DID_H DID_L)
        CANFRAME request = {0};
        request.canId = uds->id_to_send;
        request.data_lenght = 4;
        request.buffer[0] = 0x03;  // PCI - single frame, 3 bytes
        request.buffer[1] = 0x22;  // Service: Read DID
        request.buffer[2] = (uint8_t)(did >> 8);  // DID High byte
        request.buffer[3] = (uint8_t)(did & 0xFF); // DID Low byte

        if(send_can_frame(uds->CAN, &request) != ERROR_OK) continue;

        // Wait for any response with timeout
        CANFRAME response = {0};
        uint32_t timeout = 0;
        bool got_response = false;
        bool is_positive_response = false;

        while(timeout < 5000) {  // 5ms timeout
            if(read_can_message(uds->CAN, &response) == ERROR_OK) {
                if(response.canId == uds->id_to_received) {
                    got_response = true;
                    // Check if positive response (0x62) or flow control (0x30)
                    // PCI byte: 0x00-0x7F = single frame, 0x10 = first frame, 0x30 = flow control
                    uint8_t pci = response.buffer[0];
                    uint8_t service = response.buffer[1];
                    
                    // Positive response: 0x62 (Read DID response)
                    // Or flow control frame (0x30) - means ECU wants to send more data
                    // Or negative response (0x7F) - but at least we know DID exists
                    if(service == 0x62 || pci == 0x30 || service == 0x7F) {
                        is_positive_response = true;
                    }
                    break;
                }
            }
            furi_delay_us(1);
            timeout++;
        }

        if(!got_response || !is_positive_response) continue;

        // DID exists - show it
        found_count++;
        
        // If positive response with data, show the data
        if(response.buffer[1] == 0x62) {
            furi_string_cat_printf(text, "0x%04X:", (uint16_t)did);
            
            uint8_t data_len = response.buffer[0] & 0x0F;  // Get length from PCI
            if(data_len > 3) {
                // Show available data bytes
                uint8_t show_bytes = data_len - 3;  // Subtract PCI + Service + DID(2 bytes)
                if(show_bytes > 4) show_bytes = 4;  // Max 4 bytes in single frame
                
                for(uint8_t i = 0; i < show_bytes && (4 + i) < response.data_lenght; i++) {
                    furi_string_cat_printf(text, "%02X", response.buffer[4 + i]);
                }
            }
            furi_string_cat_printf(text, "+");  // Indicate more data available
        } else if(response.buffer[0] == 0x30 || (response.buffer[0] & 0xF0) == 0x10) {
            // Flow control or first frame - multi-frame response
            furi_string_cat_printf(text, "0x%04X: [multi-frame]", (uint16_t)did);
        } else if(response.buffer[1] == 0x7F) {
            // Negative response - DID exists but access denied or other error
            uint8_t nrc = response.buffer[3];
            furi_string_cat_printf(text, "0x%04X: [NRC 0x%02X]", (uint16_t)did, nrc);
        } else {
            furi_string_cat_printf(text, "0x%04X: [exists]", (uint16_t)did);
        }
        
        furi_string_cat_printf(text, "\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));

        if(scanned % 64 == 0) {
            uint8_t pct = (uint8_t)((scanned * 100) / total);
            UNUSED(pct);
        }
    }

    if(found_count == 0) {
        furi_string_cat_printf(text, "No DIDs found\n");
    } else {
        furi_string_cat_printf(text, "\nFound %u DID(s)\n", found_count);
    }

    furi_string_cat_printf(text, "Scan complete.");
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    free_uds(uds);
    return 0;
}
