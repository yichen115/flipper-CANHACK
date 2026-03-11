#include "../../app_user.h"

typedef enum {
    SecSeedScanLevels,
    SecSeedDumpLv01,
    SecSeedDumpLv03,
    SecSeedDumpLv05,
    SecSeedDumpLv11,
    SecSeedDumpLv21,
} SecSeedMenuItems;

static uint8_t sec_seed_mode = 0;
static uint8_t sec_seed_level = 0x01;
static uint32_t sec_seed_selector = 0;

static int32_t uds_security_seed_scan_thread(void* context);
static int32_t uds_security_seed_dump_thread(void* context);

/**
 * Security Seed Menu
 */

void sec_seed_menu_callback(void* context, uint32_t index) {
    App* app = context;
    sec_seed_selector = index;

    switch(index) {
    case SecSeedScanLevels:
        sec_seed_mode = 0;
        break;
    case SecSeedDumpLv01:
        sec_seed_mode = 1;
        sec_seed_level = 0x01;
        break;
    case SecSeedDumpLv03:
        sec_seed_mode = 1;
        sec_seed_level = 0x03;
        break;
    case SecSeedDumpLv05:
        sec_seed_mode = 1;
        sec_seed_level = 0x05;
        break;
    case SecSeedDumpLv11:
        sec_seed_mode = 1;
        sec_seed_level = 0x11;
        break;
    case SecSeedDumpLv21:
        sec_seed_mode = 1;
        sec_seed_level = 0x21;
        break;
    default:
        break;
    }

    scene_manager_next_scene(app->scene_manager, app_scene_uds_security_seed_result_option);
}

void app_scene_uds_security_seed_menu_on_enter(void* context) {
    App* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Security Access");

    submenu_add_item(app->submenu, "Scan All Levels", SecSeedScanLevels, sec_seed_menu_callback, app);
    submenu_add_item(app->submenu, "Dump Seeds Lv.0x01", SecSeedDumpLv01, sec_seed_menu_callback, app);
    submenu_add_item(app->submenu, "Dump Seeds Lv.0x03", SecSeedDumpLv03, sec_seed_menu_callback, app);
    submenu_add_item(app->submenu, "Dump Seeds Lv.0x05", SecSeedDumpLv05, sec_seed_menu_callback, app);
    submenu_add_item(app->submenu, "Dump Seeds Lv.0x11", SecSeedDumpLv11, sec_seed_menu_callback, app);
    submenu_add_item(app->submenu, "Dump Seeds Lv.0x21", SecSeedDumpLv21, sec_seed_menu_callback, app);

    submenu_set_selected_item(app->submenu, sec_seed_selector);
    view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);
}

bool app_scene_uds_security_seed_menu_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_security_seed_menu_on_exit(void* context) {
    App* app = context;
    submenu_reset(app->submenu);
    // Stop session keepalive
    uds_stop_keepalive();
}

/**
 * Security Seed Result
 */

void app_scene_uds_security_seed_result_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusEnd);

    if(sec_seed_mode == 0) {
        app->thread =
            furi_thread_alloc_ex("SecScan", 4 * 1024, uds_security_seed_scan_thread, app);
    } else {
        app->thread =
            furi_thread_alloc_ex("SecDump", 4 * 1024, uds_security_seed_dump_thread, app);
    }
    furi_thread_start(app->thread);

    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
}

bool app_scene_uds_security_seed_result_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_security_seed_result_on_exit(void* context) {
    App* app = context;
    furi_thread_join(app->thread);
    furi_thread_free(app->thread);
    text_box_reset(app->textBox);
}

/**
 * Thread: scan all security access levels (odd: 0x01-0x41)
 */
static int32_t uds_security_seed_scan_thread(void* context) {
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

    furi_string_cat_printf(text, "Scanning sec levels...\n");
    furi_string_cat_printf(text, "Setting Extended Session\n\n");
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    uds_set_diagnostic_session(uds, EXTENDED_UDS_SESSION);
    furi_delay_ms(100);

    uint8_t found_count = 0;

    for(uint8_t level = 0x01; level <= 0x41; level += 2) {
        if(!furi_hal_gpio_read(&gpio_button_back)) break;

        uds_set_diagnostic_session(uds, EXTENDED_UDS_SESSION);
        furi_delay_ms(50);

        CANFRAME response = {0};
        bool got_response = uds_security_request_seed(uds, level, &response);

        if(!got_response) continue;

        if(response.buffer[1] == 0x67) {
            found_count++;
            furi_string_cat_printf(text, "Lv.0x%02X SEED:", level);
            uint8_t seed_len = (response.buffer[0] & 0x0F) - 2;
            for(uint8_t i = 0; i < seed_len && i < 5; i++) {
                furi_string_cat_printf(text, "%02X", response.buffer[3 + i]);
            }
            furi_string_cat_printf(text, "\n");
            text_box_set_text(app->textBox, furi_string_get_cstr(text));
        } else if(response.buffer[1] == 0x7F) {
            uint8_t nrc = response.buffer[3];
            if(nrc != UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED &&
               nrc != UDS_NRC_SERVICE_NOT_SUPPORTED) {
                found_count++;
                furi_string_cat_printf(
                    text, "Lv.0x%02X NRC:%s\n", level, uds_get_nrc_name(nrc));
                text_box_set_text(app->textBox, furi_string_get_cstr(text));
            }
        }
    }

    if(found_count == 0) {
        furi_string_cat_printf(text, "No levels found\n");
    } else {
        furi_string_cat_printf(text, "\nFound %u level(s)\n", found_count);
    }

    furi_string_cat_printf(text, "Scan complete.");
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    free_uds(uds);
    return 0;
}

/**
 * Thread: dump security seeds at a specific level
 */
static int32_t uds_security_seed_dump_thread(void* context) {
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

    furi_string_cat_printf(text, "Capturing seeds Lv.0x%02X\n", sec_seed_level);
    furi_string_cat_printf(text, "Press BACK to stop\n\n");
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    uint32_t capture_count = 0;

    while(furi_hal_gpio_read(&gpio_button_back)) {
        uds_set_diagnostic_session(uds, EXTENDED_UDS_SESSION);
        furi_delay_ms(100);

        CANFRAME response = {0};
        bool got_response = uds_security_request_seed(uds, sec_seed_level, &response);

        if(!got_response) {
            furi_string_cat_printf(text, "No response\n");
            text_box_set_text(app->textBox, furi_string_get_cstr(text));
            furi_delay_ms(500);
            continue;
        }

        if(response.buffer[1] == 0x67) {
            capture_count++;
            uint8_t seed_len = (response.buffer[0] & 0x0F) - 2;
            furi_string_cat_printf(text, "#%lu ", capture_count);
            for(uint8_t i = 0; i < seed_len && i < 5; i++) {
                furi_string_cat_printf(text, "%02X", response.buffer[3 + i]);
            }
            furi_string_cat_printf(text, "\n");
            text_box_set_text(app->textBox, furi_string_get_cstr(text));
        } else if(response.buffer[1] == 0x7F) {
            uint8_t nrc = response.buffer[3];
            furi_string_cat_printf(text, "NRC: %s\n", uds_get_nrc_name(nrc));
            text_box_set_text(app->textBox, furi_string_get_cstr(text));

            if(nrc == UDS_NRC_SERVICE_NOT_SUPPORTED ||
               nrc == UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED) {
                break;
            }
        }

        furi_delay_ms(500);
    }

    furi_string_cat_printf(text, "\nCaptured %lu seed(s).", capture_count);
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    free_uds(uds);
    return 0;
}
