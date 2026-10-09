#include "../../app_user.h"

// Thread to get the vin
static int32_t uds_get_vin_thread(void* context);

/**
 * UDS get Vin Scene
 */
// Scene on enter
void app_scene_uds_request_vin_on_enter(void* context) {
    App* app = context;

    widget_reset(app->widget);

    app->thread = furi_thread_alloc_ex("ManualUDS", 4096, uds_get_vin_thread, app);
    furi_thread_start(app->thread);

    view_dispatcher_switch_to_view(app->view_dispatcher, ViewWidget);
}

// Scene on event
bool app_scene_uds_request_vin_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

// Scene on exit
void app_scene_uds_request_vin_on_exit(void* context) {
    App* app = context;

    app_uds_stop_worker(app);

    widget_reset(app->widget);
}

/**
 * Thread to work with
 */

static int32_t uds_get_vin_thread(void* context) {
    App* app = context;

    FuriString* text = app->text;

    furi_string_reset(text);

    UDS_SERVICE* uds_service = app_uds_open(app);

    if(uds_service) {
        if(uds_get_vin(uds_service, text)) {
            widget_add_string_element(
                app->widget, 64, 25, AlignCenter, AlignCenter, FontPrimary, "VIN:");
            widget_add_string_element(
                app->widget,
                64,
                35,
                AlignCenter,
                AlignCenter,
                FontSecondary,
                furi_string_get_cstr(text));
        } else {
            draw_transmition_failure(app);
        }
    } else {
        draw_device_no_connected(app);
    }

    free_uds(uds_service);

    return 0;
}
