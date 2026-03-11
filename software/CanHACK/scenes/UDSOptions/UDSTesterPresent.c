#include "../../app_user.h"

#define TESTER_PRESENT_INTERVAL_MS 500

static int32_t uds_tester_present_thread(void* context);

void app_scene_uds_tester_present_on_enter(void* context) {
    App* app = context;
    widget_reset(app->widget);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewWidget);

    app->thread =
        furi_thread_alloc_ex("UdsTP", 2 * 1024, uds_tester_present_thread, app);
    furi_thread_start(app->thread);
}

bool app_scene_uds_tester_present_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_tester_present_on_exit(void* context) {
    App* app = context;
    furi_thread_join(app->thread);
    furi_thread_free(app->thread);
    widget_reset(app->widget);
}

static int32_t uds_tester_present_thread(void* context) {
    App* app = context;
    MCP2515* mcp = app->mcp_can;

    UDS_SERVICE* uds = uds_service_alloc(
        app->uds_send_id, app->uds_received_id, MCP_NORMAL, mcp->clck, mcp->bitRate);

    if(!uds_init(uds)) {
        draw_device_no_connected(app);
        free_uds(uds);
        return 0;
    }

    furi_delay_ms(500);

    uint32_t counter = 0;
    uint32_t ok_count = 0;
    uint32_t fail_count = 0;

    while(furi_hal_gpio_read(&gpio_button_back)) {
        counter++;
        bool ok = uds_tester_present(uds);

        if(ok) {
            ok_count++;
        } else {
            fail_count++;
        }

        widget_reset(app->widget);

        furi_string_reset(app->text);
        furi_string_cat_printf(
            app->text,
            "TX:0x%lX  RX:0x%lX\nSending TesterPresent\n(0x3E 0x00)",
            app->uds_send_id,
            app->uds_received_id);

        widget_add_string_multiline_element(
            app->widget,
            64,
            14,
            AlignCenter,
            AlignCenter,
            FontSecondary,
            furi_string_get_cstr(app->text));

        furi_string_reset(app->text);
        furi_string_cat_printf(app->text, "Sent: %lu", counter);

        widget_add_string_element(
            app->widget, 64, 32, AlignCenter, AlignCenter, FontPrimary,
            furi_string_get_cstr(app->text));

        furi_string_reset(app->text);
        furi_string_cat_printf(app->text, "OK:%lu  FAIL:%lu", ok_count, fail_count);

        widget_add_string_element(
            app->widget, 64, 48, AlignCenter, AlignCenter, FontSecondary,
            furi_string_get_cstr(app->text));

        widget_add_string_element(
            app->widget, 64, 60, AlignCenter, AlignCenter, FontSecondary,
            "Press BACK to stop");

        furi_delay_ms(TESTER_PRESENT_INTERVAL_MS);
    }

    free_uds(uds);
    return 0;
}
