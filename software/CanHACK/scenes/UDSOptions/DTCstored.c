#include "../../app_user.h"

static bool delete_dtc;
static bool confirm_clear;

static void dtc_confirm_callback(DialogExResult result, void* context) {
    App* app = context;
    if(result == DialogExResultRight) view_dispatcher_send_custom_event(app->view_dispatcher, 3);
    else if(result == DialogExResultLeft) view_dispatcher_send_custom_event(app->view_dispatcher, 4);
}

void storage_dtc_menu_callback(void* context, uint32_t index) {
    App* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index + 1);
}

void app_scene_uds_get_dtc_menu_on_enter(void* context) {
    App* app = context;
    confirm_clear = false;
    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "DTC (24-bit UDS)");
    submenu_add_item(app->submenu, "Read DTC", 0, storage_dtc_menu_callback, app);
    submenu_add_item(app->submenu, "Clear all DTC", 1, storage_dtc_menu_callback, app);
    view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);
}

bool app_scene_uds_get_dtc_menu_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    if(event.type == SceneManagerEventTypeBack && confirm_clear) {
        app_scene_uds_get_dtc_menu_on_enter(app);
        return true;
    }
    if(event.type != SceneManagerEventTypeCustom) return false;
    if(event.event == 2) {
        confirm_clear = true;
        dialog_ex_reset(app->dialog_ex);
        dialog_ex_set_header(app->dialog_ex, "Clear all DTC?", 64, 12, AlignCenter, AlignCenter);
        dialog_ex_set_text(app->dialog_ex, "Stored faults will\nbe erased", 64, 32, AlignCenter, AlignCenter);
        dialog_ex_set_left_button_text(app->dialog_ex, "Cancel");
        dialog_ex_set_right_button_text(app->dialog_ex, "Clear");
        dialog_ex_set_context(app->dialog_ex, app);
        dialog_ex_set_result_callback(app->dialog_ex, dtc_confirm_callback);
        view_dispatcher_switch_to_view(app->view_dispatcher, DialogView);
    } else if(event.event == 1 || (event.event == 3 && confirm_clear)) {
        delete_dtc = event.event == 3;
        scene_manager_next_scene(app->scene_manager, app_scene_uds_dtc_response_option);
    } else if(event.event == 4) {
        app_scene_uds_get_dtc_menu_on_enter(app);
    } else return false;
    return true;
}

void app_scene_uds_get_dtc_menu_on_exit(void* context) {
    App* app = context;
    submenu_reset(app->submenu);
    dialog_ex_reset(app->dialog_ex);
}

static int32_t dtc_worker(void* context) {
    App* app = context;
    UDS_SERVICE* uds = app_uds_open(app);
    furi_string_set(app->text, delete_dtc ? "Clear DTC\n" : "Read DTC\n");
    if(!uds) {
        furi_string_cat_printf(app->text, "CAN/session init failed");
    } else {
        uint8_t response[UDS_PAYLOAD_MAX];
        size_t len = 0;
        const uint8_t read[] = {0x19, 0x02, 0xFF};
        const uint8_t clear[] = {0x14, 0xFF, 0xFF, 0xFF};
        UdsStatus status = uds_request_payload(
            uds, delete_dtc ? clear : read, delete_dtc ? sizeof(clear) : sizeof(read),
            response, sizeof(response), &len);
        if(status == UdsNegative) {
            furi_string_cat_printf(app->text, "NRC %02X\n%s", response[2], uds_get_nrc_name(response[2]));
        } else if(status != UdsOk) {
            furi_string_cat_printf(app->text, "%s", uds_status_name(status));
        } else if(delete_dtc) {
            furi_string_cat_printf(app->text, len == 1 ? "DTC cleared" : "Invalid clear response");
        } else if(len < 3 || (len - 3) % 4) {
            furi_string_cat_printf(app->text, "Invalid DTC response");
        } else {
            furi_string_cat_printf(app->text, "Count: %u\nCode / status\n", (unsigned)((len - 3) / 4));
            for(size_t i = 3; i + 3 < len; i += 4) {
                furi_string_cat_printf(app->text, "%02X%02X%02X / %02X\n",
                    response[i], response[i + 1], response[i + 2], response[i + 3]);
            }
            if(len == 3) furi_string_cat_printf(app->text, "No stored DTC");
        }
        free_uds(uds);
    }
    text_box_set_text(app->textBox, furi_string_get_cstr(app->text));
    return 0;
}

void app_scene_uds_dtc_response_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusStart);
    text_box_set_text(app->textBox, "Working...\nBACK: cancel");
    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
    app->thread = furi_thread_alloc_ex("UdsDtc", 4096, dtc_worker, app);
    furi_thread_start(app->thread);
}

bool app_scene_uds_dtc_response_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_dtc_response_on_exit(void* context) {
    App* app = context;
    app_uds_stop_worker(app);
    text_box_reset(app->textBox);
}
