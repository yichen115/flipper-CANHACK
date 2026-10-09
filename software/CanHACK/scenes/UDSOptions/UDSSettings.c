#include "../../app_user.h"

static uint8_t id_request_array[4];
static uint8_t id_response_array[4];

static uint32_t selected_item = 0;
static const uint32_t response_waits[] = {10, 50, 100, 500};
static const char* response_wait_text[] = {"10 ms", "50 ms", "100 ms", "500 ms"};
static const uint32_t request_gaps[] = {0, 5, 20, 50};
static const char* request_gap_text[] = {"0 ms", "5 ms", "20 ms", "50 ms"};

static void response_wait_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    uint8_t index = variable_item_get_current_value_index(item);
    app->uds_timeout_ms = response_waits[index];
    variable_item_set_current_value_text(item, response_wait_text[index]);
}

static void request_gap_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    uint8_t index = variable_item_get_current_value_index(item);
    app->uds_gap_ms = request_gaps[index];
    variable_item_set_current_value_text(item, request_gap_text[index]);
}

/**
 * Scene to set the Ids for UDS services
 */

// Callback for the settings
void settings_input_callback(void* context, uint32_t index) {
    App* app = context;
    if(index < 2) view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

// Scene on enter
void app_scene_uds_settings_on_enter(void* context) {
    App* app = context;

    VariableItem* item;

    variable_item_list_reset(app->varList);

    // First Item
    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "0x%lx", app->uds_send_id);

    item = variable_item_list_add(app->varList, "REQUEST ID", 0, NULL, app);
    variable_item_set_current_value_index(item, 0);
    variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));

    // Second Item
    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "0x%lx", app->uds_received_id);

    item = variable_item_list_add(app->varList, "RESPONSE ID", 0, NULL, app);
    variable_item_set_current_value_index(item, 0);
    variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));

    item = variable_item_list_add(app->varList, "Response wait", COUNT_OF(response_waits), response_wait_changed, app);
    uint8_t wait_index = 1;
    for(uint8_t i = 0; i < COUNT_OF(response_waits); i++) {
        if(app->uds_timeout_ms == response_waits[i]) wait_index = i;
    }
    variable_item_set_current_value_index(item, wait_index);
    variable_item_set_current_value_text(item, response_wait_text[wait_index]);
    item = variable_item_list_add(app->varList, "Request gap", COUNT_OF(request_gaps), request_gap_changed, app);
    uint8_t gap_index = 1;
    for(uint8_t i = 0; i < COUNT_OF(request_gaps); i++) {
        if(app->uds_gap_ms == request_gaps[i]) gap_index = i;
    }
    variable_item_set_current_value_index(item, gap_index);
    variable_item_set_current_value_text(item, request_gap_text[gap_index]);

    variable_item_list_set_enter_callback(app->varList, settings_input_callback, app);

    variable_item_list_set_selected_item(app->varList, selected_item);

    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

// Scene on event
bool app_scene_uds_settings_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    if(event.type == SceneManagerEventTypeCustom && event.event < 2) {
        selected_item = event.event;
        scene_manager_set_scene_state(app->scene_manager, app_scene_uds_set_ids_option, event.event);
        scene_manager_next_scene(app->scene_manager, app_scene_uds_set_ids_option);
        return true;
    }
    return false;
}

// Scene on exit
void app_scene_uds_settings_on_exit(void* context) {
    App* app = context;
    variable_item_list_reset(app->varList);
}

/**
 * To set the id's
 */

void set_data(void* context) {
    App* app = context;

    uint32_t state =
        scene_manager_get_scene_state(app->scene_manager, app_scene_uds_set_ids_option);

    switch(state) {
    case 0:

        app->uds_send_id = ((uint32_t)id_request_array[0] << 24) | ((uint32_t)id_request_array[1] << 16) |
                           ((uint32_t)id_request_array[2] << 8) | (id_request_array[3]);
        break;

    case 1:

        app->uds_received_id = ((uint32_t)id_response_array[0] << 24) | ((uint32_t)id_response_array[1] << 16) |
                               ((uint32_t)id_response_array[2] << 8) | (id_response_array[3]);
        break;

    default:
        break;
    }

    app->uds_send_id &= 0x1FFFFFFF;
    app->uds_received_id &= 0x1FFFFFFF;
    app->uds_session_type = 1;
    uds_stop_keepalive();
    scene_manager_previous_scene(app->scene_manager);
}

// Scene on enter
void app_scene_uds_set_ids_on_enter(void* context) {
    App* app = context;
    ByteInput* scene = app->input_byte_value;

    uint32_t state =
        scene_manager_get_scene_state(app->scene_manager, app_scene_uds_set_ids_option);

    switch(state) {
    case 0:

        id_request_array[3] = app->uds_send_id;
        id_request_array[2] = app->uds_send_id >> 8;
        id_request_array[1] = app->uds_send_id >> 16;
        id_request_array[0] = app->uds_send_id >> 24;

        byte_input_set_result_callback(scene, set_data, NULL, app, id_request_array, 4);
        byte_input_set_header_text(scene, "SET REQUEST DATA");
        break;

    case 1:

        id_response_array[3] = app->uds_received_id;
        id_response_array[2] = app->uds_received_id >> 8;
        id_response_array[1] = app->uds_received_id >> 16;
        id_response_array[0] = app->uds_received_id >> 24;

        byte_input_set_result_callback(scene, set_data, NULL, app, id_response_array, 4);
        byte_input_set_header_text(scene, "SET RESPONSE DATA");
        break;

    default:
        break;
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, InputByteView);
}

// Scene on event
bool app_scene_uds_set_ids_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

// Scene on exit
void app_scene_uds_set_ids_on_exit(void* context) {
    App* app = context;
    UNUSED(app);
}
