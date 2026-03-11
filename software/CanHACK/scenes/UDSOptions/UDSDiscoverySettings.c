#include "../../app_user.h"

// Scene states
#define STATE_MENU 0
#define STATE_INPUT_START_ID 1
#define STATE_INPUT_END_ID 2

static uint8_t current_state = STATE_MENU;
static uint8_t start_id_bytes[2] = {0x06, 0x00}; // Default 0x600
static uint8_t end_id_bytes[2] = {0x07, 0xFF};   // Default 0x7FF
static uint32_t start_id = 0x600;
static uint32_t end_id = 0x7FF;
static VariableItem* start_id_item = NULL;
static VariableItem* end_id_item = NULL;

static void update_id_from_bytes(void) {
    start_id = ((uint32_t)start_id_bytes[0] << 8) | start_id_bytes[1];
    end_id = ((uint32_t)end_id_bytes[0] << 8) | end_id_bytes[1];
}

static void update_bytes_from_id(void) {
    start_id_bytes[0] = (start_id >> 8) & 0xFF;
    start_id_bytes[1] = start_id & 0xFF;
    end_id_bytes[0] = (end_id >> 8) & 0xFF;
    end_id_bytes[1] = end_id & 0xFF;
}

static void update_menu_display(void) {
    char temp_str[16];
    if(start_id_item) {
        snprintf(temp_str, sizeof(temp_str), "0x%03lX", start_id);
        variable_item_set_current_value_text(start_id_item, temp_str);
    }
    if(end_id_item) {
        snprintf(temp_str, sizeof(temp_str), "0x%03lX", end_id);
        variable_item_set_current_value_text(end_id_item, temp_str);
    }
}

static void byte_input_callback(void* context) {
    App* app = context;
    update_id_from_bytes();
    
    // Update menu display
    update_menu_display();
    
    // Return to menu
    current_state = STATE_MENU;
    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

void app_scene_uds_discovery_settings_callback(void* context, uint32_t index) {
    App* app = context;

    switch(index) {
    case 0: // Start ID
        current_state = STATE_INPUT_START_ID;
        update_bytes_from_id();
        byte_input_set_header_text(app->input_byte_value, "Enter Start CAN ID");
        byte_input_set_result_callback(
            app->input_byte_value,
            byte_input_callback,
            NULL,
            app,
            start_id_bytes,
            2);
        view_dispatcher_switch_to_view(app->view_dispatcher, InputByteView);
        break;
    case 1: // End ID
        current_state = STATE_INPUT_END_ID;
        update_bytes_from_id();
        byte_input_set_header_text(app->input_byte_value, "Enter End CAN ID");
        byte_input_set_result_callback(
            app->input_byte_value,
            byte_input_callback,
            NULL,
            app,
            end_id_bytes,
            2);
        view_dispatcher_switch_to_view(app->view_dispatcher, InputByteView);
        break;
    case 2: // Start Scan
        update_id_from_bytes();
        app->ecu_discovery_start_id = start_id;
        app->ecu_discovery_end_id = end_id;
        scene_manager_next_scene(app->scene_manager, app_scene_uds_ecu_discovery_option);
        break;
    default:
        break;
    }
}

void app_scene_uds_discovery_settings_on_enter(void* context) {
    App* app = context;
    char temp_str[16];

    // Initialize with saved values or defaults
    if(app->ecu_discovery_start_id == 0 && app->ecu_discovery_end_id == 0) {
        start_id = 0x600;
        end_id = 0x7FF;
    } else {
        start_id = app->ecu_discovery_start_id;
        end_id = app->ecu_discovery_end_id;
    }
    update_bytes_from_id();

    current_state = STATE_MENU;

    variable_item_list_reset(app->varList);

    // Start ID option
    snprintf(temp_str, sizeof(temp_str), "0x%03lX", start_id);
    start_id_item = variable_item_list_add(app->varList, "Start ID", 0, NULL, app);
    variable_item_set_current_value_text(start_id_item, temp_str);

    // End ID option
    snprintf(temp_str, sizeof(temp_str), "0x%03lX", end_id);
    end_id_item = variable_item_list_add(app->varList, "End ID", 0, NULL, app);
    variable_item_set_current_value_text(end_id_item, temp_str);

    // Start Scan option
    variable_item_list_add(app->varList, "Start Scan", 0, NULL, app);

    variable_item_list_set_enter_callback(app->varList, app_scene_uds_discovery_settings_callback, app);
    variable_item_list_set_selected_item(app->varList, 0);

    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

bool app_scene_uds_discovery_settings_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_discovery_settings_on_exit(void* context) {
    App* app = context;
    variable_item_list_reset(app->varList);
    start_id_item = NULL;
    end_id_item = NULL;
    current_state = STATE_MENU;
}
