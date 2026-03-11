#include "../app_user.h"

typedef enum {
    UDS_SETTINGS,
    ECU_DISCOVERY_OPTION,
    ALLINONE_OPTION,
    SERVICE_SCAN_OPTION,
    ECU_RESET_OPTION,
    SECURITY_SEED_OPTION,
    KEY_BRUTEFORCE_OPTION,
    DID_SCAN_OPTION,
} uds_elements_list;

static uint32_t selector_option = 0;

// Forward declarations for session check
void uds_menu_callback(void* context, uint32_t index);
static void check_and_enter_function(App* app, uint32_t target_scene);

static void check_and_enter_function(App* app, uint32_t target_scene) {
    // Save target scene and go to session select
    scene_manager_set_scene_state(app->scene_manager, app_scene_uds_menu_option, target_scene);
    scene_manager_next_scene(app->scene_manager, app_scene_uds_session_select_option);
}

void uds_menu_callback(void* context, uint32_t index) {
    App* app = context;
    selector_option = index;

    switch(index) {
    case UDS_SETTINGS:
        scene_manager_next_scene(app->scene_manager, app_scene_uds_settings_option);
        break;

    case ECU_DISCOVERY_OPTION:
        scene_manager_next_scene(app->scene_manager, app_scene_uds_discovery_settings_option);
        break;

    case ALLINONE_OPTION:
        scene_manager_next_scene(app->scene_manager, app_scene_uds_allinone_option);
        break;

    case SERVICE_SCAN_OPTION:
        check_and_enter_function(app, app_scene_uds_service_scan_option);
        break;

    case ECU_RESET_OPTION:
        check_and_enter_function(app, app_scene_uds_ecu_reset_option);
        break;

    case SECURITY_SEED_OPTION:
        check_and_enter_function(app, app_scene_uds_security_seed_menu_option);
        break;

    case KEY_BRUTEFORCE_OPTION:
        check_and_enter_function(app, app_scene_uds_bruteforce_menu_option);
        break;

    case DID_SCAN_OPTION:
        check_and_enter_function(app, app_scene_uds_did_scan_menu_option);
        break;

    default:
        break;
    }
}

void app_scene_uds_menu_on_enter(void* context) {
    App* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "UDS Services");

    // Settings first
    submenu_add_item(
        app->submenu, "Settings", UDS_SETTINGS, uds_menu_callback, app);
    // ECU Discovery (no session needed)
    submenu_add_item(
        app->submenu, "ECU Discovery", ECU_DISCOVERY_OPTION, uds_menu_callback, app);
    // ALLINONE (complete test suite)
    submenu_add_item(
        app->submenu, "ALLINONE Test", ALLINONE_OPTION, uds_menu_callback, app);
    // Functions that need session
    submenu_add_item(
        app->submenu, "Service Scan", SERVICE_SCAN_OPTION, uds_menu_callback, app);
    submenu_add_item(
        app->submenu, "ECU Reset", ECU_RESET_OPTION, uds_menu_callback, app);
    submenu_add_item(
        app->submenu, "Security Seed", SECURITY_SEED_OPTION, uds_menu_callback, app);
    submenu_add_item(
        app->submenu, "Key Bruteforce", KEY_BRUTEFORCE_OPTION, uds_menu_callback, app);
    submenu_add_item(
        app->submenu, "DID Scanner", DID_SCAN_OPTION, uds_menu_callback, app);

    submenu_set_selected_item(app->submenu, selector_option);

    view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);
}

bool app_scene_uds_menu_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_menu_on_exit(void* context) {
    App* app = context;
    submenu_reset(app->submenu);
}
