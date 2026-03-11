#include "../app_user.h"

// This variable works to get the value of the selector and set it when the user
// enter at the Scene
static uint8_t menu_selector = 0;

// Function to display init (removed logo display)
void draw_start(App* app) {
    UNUSED(app);
    // Logo display removed
}

void basic_scenes_menu_callback(void* context, uint32_t index) {
    App* app = context;

    menu_selector = index;

    switch(index) {
    case SniffingTestOption:
        scene_manager_handle_custom_event(app->scene_manager, SniffingOptionEvent);
        break;

    case SenderOption:
        scene_manager_handle_custom_event(app->scene_manager, SenderOptionEvent);
        break;

    case UDSOption:
        scene_manager_handle_custom_event(app->scene_manager, UDSOptionEvent);
        break;

    case SettingsOption:
        scene_manager_handle_custom_event(app->scene_manager, SettingsOptionEvent);
        break;

    default:
        break;
    }
}

void app_scene_menu_on_enter(void* context) {
    App* app = context;

    *app->can_send_frame = false;
    *app->send_timestamp = false;

    uint32_t state = scene_manager_get_scene_state(app->scene_manager, app_scene_main_menu);

    if(state == 0) {
        draw_start(app);
        furi_delay_ms(START_TIME);
        scene_manager_set_scene_state(app->scene_manager, app_scene_main_menu, 1);
    }

    submenu_reset(app->submenu);

    submenu_set_header(app->submenu, "MENU");

    submenu_add_item(
        app->submenu, "Sniffing", SniffingTestOption, basic_scenes_menu_callback, app);

    submenu_add_item(app->submenu, "Sender", SenderOption, basic_scenes_menu_callback, app);

    submenu_add_item(app->submenu, "UDS Services", UDSOption, basic_scenes_menu_callback, app);

    submenu_add_item(app->submenu, "Settings", SettingsOption, basic_scenes_menu_callback, app);

    submenu_set_selected_item(app->submenu, menu_selector);

    view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);

    app->obdii_aux_index = 0;
}

bool app_scene_menu_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    bool consumed = false;

    switch(event.type) {
    case SceneManagerEventTypeCustom:
        switch(event.event) {
        case SniffingOptionEvent:
            scene_manager_next_scene(app->scene_manager, app_scene_sniffing_option);
            consumed = true;
            break;

        case SenderOptionEvent:
            scene_manager_next_scene(app->scene_manager, app_scene_sender_option);
            break;

        case SettingsOptionEvent:
            scene_manager_next_scene(app->scene_manager, app_scene_settings_option);
            consumed = true;
            break;

        case UDSOptionEvent:
            scene_manager_next_scene(app->scene_manager, app_scene_uds_menu_option);
            consumed = true;
            break;

        default:
            break;
        }
        break;
    default:
        break;
    }
    return consumed;
}

void app_scene_menu_on_exit(void* context) {
    App* app = context;
    submenu_reset(app->submenu);
}
