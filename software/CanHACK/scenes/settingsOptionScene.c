#include "../app_user.h"

// To save the current clock
static uint8_t currentClock = MCP_8MHZ;

// To save the current Bitrate
static uint8_t currentBitrate = MCP_500KBPS;

// Texts for the bitrate
static const char* bitratesValues[] = {"125KBPS", "250KBPS", "500KBPS", "1000KBPS"};

// Text for the clocks
static const char* clockValues[] = {"8MHz", "16MHz", "20MHz"};

// Text to save the sniffing
static const char* save_logs[] = {"No Save", "Save All", "Only Address"};

/**
 * Scene for the options
 */

static void bitrate_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    currentBitrate = variable_item_get_current_value_index(item);
    app->mcp_can->bitRate = currentBitrate;
    variable_item_set_current_value_text(item, bitratesValues[currentBitrate]);
}
static void clock_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    currentClock = variable_item_get_current_value_index(item);
    app->mcp_can->clck = currentClock;
    variable_item_set_current_value_text(item, clockValues[currentClock]);
}
static void save_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->save_logs = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, save_logs[app->save_logs]);
}

void settings_enter_callback(void* context, uint32_t index) {
    App* app = context;
    if(index == WiringOption) {
        view_dispatcher_send_custom_event(app->view_dispatcher, WiringOption);
    }
}

// Scene on enter
void app_scene_settings_on_enter(void* context) {
    App* app = context;
    VariableItem* item;

    currentBitrate = app->mcp_can->bitRate;
    currentClock = app->mcp_can->clck;

    variable_item_list_reset(app->varList);

    // First Item
    item = variable_item_list_add(
        app->varList, "Bitrate", COUNT_OF(bitratesValues), bitrate_changed, app);
    variable_item_set_current_value_index(item, currentBitrate);
    variable_item_set_current_value_text(item, bitratesValues[currentBitrate]);

    // Second Item
    item = variable_item_list_add(app->varList, "Clock", COUNT_OF(clockValues), clock_changed, app);
    variable_item_set_current_value_index(item, currentClock);
    variable_item_set_current_value_text(item, clockValues[currentClock]);

    // Third Item
    item = variable_item_list_add(app->varList, "Save LOGS?", 3, save_changed, app);
    variable_item_set_current_value_index(item, app->save_logs);
    variable_item_set_current_value_text(item, save_logs[app->save_logs]);

    // Fourth Item - Wiring
    item = variable_item_list_add(app->varList, "Wiring", 0, NULL, app);

    variable_item_list_set_enter_callback(app->varList, settings_enter_callback, app);

    variable_item_list_set_selected_item(app->varList, 0);
    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

// Scene on event
bool app_scene_settings_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    if(event.type == SceneManagerEventTypeCustom && event.event == WiringOption) {
        scene_manager_next_scene(app->scene_manager, app_scene_wiring_option);
        return true;
    }
    return false;
}

// Scene on exit
void app_scene_settings_on_exit(void* context) {
    App* app = context;
    variable_item_list_reset(app->varList);
}
