#include "../../app_user.h"

static const char* session_names[] = {
    "Default (0x01)", "Programming (0x02)", "Extended (0x03)", "Safety System (0x04)",
};
static uint8_t selected_session = 1;
static uint32_t target_scene;
static bool session_active;
static UdsStatus session_status;
static uint8_t session_nrc;

static int32_t session_worker(void* context) {
    App* app = context;
    UDS_SERVICE* uds = app_uds_open(app);
    session_status = UdsSendError;
    session_nrc = 0;
    if(!uds) return 0;
    uint8_t request[] = {0x10, selected_session};
    uint8_t response[8];
    size_t len = 0;
    session_status = uds_request_payload(uds, request, sizeof(request), response, sizeof(response), &len);
    if(session_status == UdsNegative) session_nrc = response[2];
    free_uds(uds);
    return 0;
}

void uds_session_select_callback(void* context, uint32_t index) {
    App* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void app_scene_uds_session_select_on_enter(void* context) {
    App* app = context;
    target_scene = scene_manager_get_scene_state(app->scene_manager, app_scene_uds_menu_option);
    session_active = false;
    app->uds_session_type = 1;
    app->thread = NULL;
    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Select Session");
    for(uint8_t i = 0; i < COUNT_OF(session_names); i++) {
        submenu_add_item(app->submenu, session_names[i], i, uds_session_select_callback, app);
    }
    submenu_set_selected_item(app->submenu, selected_session - 1);
    view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);
}

bool app_scene_uds_session_select_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    if(event.type == SceneManagerEventTypeCustom && event.event < COUNT_OF(session_names) && !app->thread) {
        selected_session = event.event + 1;
        view_dispatcher_switch_to_view(app->view_dispatcher, LoadingView);
        app->thread = furi_thread_alloc_ex("UdsSession", 4096, session_worker, app);
        furi_thread_start(app->thread);
        return true;
    }
    if(event.type == SceneManagerEventTypeTick && app->thread &&
       furi_thread_get_state(app->thread) == FuriThreadStateStopped) {
        app_uds_stop_worker(app);
        if(session_status == UdsOk) {
            app->uds_session_type = selected_session;
            session_active = true;
            scene_manager_next_scene(app->scene_manager, target_scene);
        } else {
            session_active = false;
            // A failed switch leaves the ECU's actual session unknown.
            app->uds_session_type = 1;
            furi_string_printf(app->text, "Session failed\n%s", uds_status_name(session_status));
            if(session_status == UdsNegative) {
                furi_string_cat_printf(app->text, "\nNRC %02X %s", session_nrc, uds_get_nrc_name(session_nrc));
            }
            furi_string_cat_printf(app->text, "\nBACK: return");
            text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
            view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
        }
        return true;
    }
    return false;
}

void app_scene_uds_session_select_on_exit(void* context) {
    App* app = context;
    app_uds_stop_worker(app);
    submenu_reset(app->submenu);
    text_box_reset(app->textBox);
}

// Keepalive is sent by the diagnostic worker that owns the initialized MCP2515.
// No timer may access a controller while another scene reinitializes it.
void uds_stop_keepalive(void) {
    session_active = false;
}

bool uds_need_session_select(void) {
    return !session_active;
}
