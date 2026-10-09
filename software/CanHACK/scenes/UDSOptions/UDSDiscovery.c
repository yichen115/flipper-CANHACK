#include "../../app_user.h"

#define DISCOVERY_MAX_RESULTS 32
static struct { uint32_t tx; uint32_t rx; } found[DISCOVERY_MAX_RESULTS];
static uint16_t found_count;
static bool result_menu_shown;

static void discovery_select(void* context, uint32_t index) {
    App* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

static int32_t discovery_worker(void* context) {
    App* app = context;
    MCP2515* can = mcp_alloc(MCP_NORMAL, app->mcp_can->clck, app->mcp_can->bitRate);
    uint32_t min = app->ecu_discovery_start_id;
    uint32_t max = app->ecu_discovery_end_id;
    if(min == 0 && max == 0) { min = 0x700; max = 0x7FF; }
    if(min > 0x7FF) min = 0x7FF;
    if(max > 0x7FF) max = 0x7FF;
    if(min > max) { uint32_t temp = min; min = max; max = temp; }
    furi_string_reset(app->data);
    furi_string_set(app->text, "Discovery\n");
    if(!can || mcp2515_init(can) != ERROR_OK) {
        text_box_set_text(app->textBox, "CAN init failed");
        free_mcp2515(can);
        return 0;
    }
    init_mask(can, 0, 0);
    init_mask(can, 1, 0);
    uint32_t start = furi_get_tick();
    uint32_t last_update = start - 100;
    uint32_t scanned = 0;
    for(uint32_t id = min; id <= max && !uds_worker_cancelled(); id++) {
        CANFRAME response = {0};
        if(uds_discovery_probe(can, id, app->uds_discovery_wait_ms, &response) &&
           uds_discovery_verify(can, id, response.canId, app->uds_discovery_wait_ms)) {
            found[found_count].tx = id;
            found[found_count].rx = response.canId;
            found_count++;
            furi_string_cat_printf(app->data, "%03lX -> %03lX\n", id, response.canId);
        }
        scanned++;
        uint32_t now = furi_get_tick();
        if(now - last_update >= 100 || id == max || found_count == DISCOVERY_MAX_RESULTS) {
            furi_string_printf(app->text,
                "Discovery %lu/%lu\nWait %lu ms, %lu ms elapsed\nFound %u verified pair(s)\n%s\nBACK: cancel",
                scanned, max - min + 1, app->uds_discovery_wait_ms, now - start,
                found_count, furi_string_get_cstr(app->data));
            text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
            last_update = now;
        }
        if(found_count == DISCOVERY_MAX_RESULTS) break;
        furi_delay_ms(1);
    }
    furi_string_cat_printf(app->text, "\n%s", uds_worker_cancelled() ? "Cancelled" : "Scan complete");
    if(found_count == DISCOVERY_MAX_RESULTS) furi_string_cat_printf(app->text, " (32 pair limit)");
    text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
    deinit_mcp2515(can);
    free_mcp2515(can);
    return 0;
}

void app_scene_uds_ecu_discovery_on_enter(void* context) {
    App* app = context;
    found_count = 0;
    result_menu_shown = false;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusEnd);
    text_box_set_text(app->textBox, "Discovering ECUs...\nBACK: cancel");
    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
    app->thread = furi_thread_alloc_ex("UdsDiscovery", 4096, discovery_worker, app);
    furi_thread_start(app->thread);
}

bool app_scene_uds_ecu_discovery_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    if(event.type == SceneManagerEventTypeTick && app->thread &&
       furi_thread_get_state(app->thread) == FuriThreadStateStopped) {
        app_uds_stop_worker(app);
        if(found_count) {
            submenu_reset(app->submenu);
            submenu_set_header(app->submenu, "Select ECU (TX -> RX)");
            for(uint16_t i = 0; i < found_count; i++) {
                char label[32];
                snprintf(label, sizeof(label), "%03lX -> %03lX", found[i].tx, found[i].rx);
                submenu_add_item(app->submenu, label, i, discovery_select, app);
            }
            submenu_add_item(app->submenu, "Scan report", found_count, discovery_select, app);
            result_menu_shown = true;
            view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);
        }
        return true;
    }
    if(event.type == SceneManagerEventTypeCustom && result_menu_shown) {
        if(event.event < found_count) {
            app->uds_send_id = found[event.event].tx;
            app->uds_received_id = found[event.event].rx;
            app->uds_session_type = 1;
            scene_manager_search_and_switch_to_previous_scene(app->scene_manager, app_scene_uds_menu_option);
        } else {
            view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
        }
        return true;
    }
    return false;
}

void app_scene_uds_ecu_discovery_on_exit(void* context) {
    App* app = context;
    app_uds_stop_worker(app);
    text_box_reset(app->textBox);
    submenu_reset(app->submenu);
}
