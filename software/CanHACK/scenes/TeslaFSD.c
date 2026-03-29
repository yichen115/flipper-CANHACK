/*
    Tesla FSD CAN Bus Enabler for Flipper Zero
    Ported from CanFeather.ino (tesla-fsd-can-mod-main)
    Original: GPL-3.0 License

    Intercepts Tesla CAN frames and modifies bits to enable FSD,
    set speed profiles, and suppress hands-on-wheel nag.
*/

#include "../app_user.h"

/* ---- HW Variant Enum ---- */

typedef enum {
    TeslaHW_Legacy = 0, // HW3 Retrofit, portrait screen
    TeslaHW_HW3,        // HW3, landscape screen
    TeslaHW_HW4,        // HW4 (firmware >= 2026.2.3)
} TeslaHWVariant;

static const char* hw_variant_names[] = {"Legacy", "HW3", "HW4"};
#define HW_VARIANT_COUNT 3

/* ---- Speed Profile Names ---- */

static const char* profile_names_3[] = {"Chill", "Normal", "Hurry"};
static const char* profile_names_5[] = {"Chill", "Normal", "Hurry", "Max", "Sloth"};

/* ---- Static State ---- */

static TeslaHWVariant fsd_hw_variant = TeslaHW_HW3;
static uint32_t fsd_menu_selector = 0;

/* ---- Bit Manipulation Helpers (from CanFeather.ino) ---- */

static inline uint8_t fsd_read_mux_id(const CANFRAME* frame) {
    return frame->buffer[0] & 0x07;
}

static inline bool fsd_is_selected_in_ui(const CANFRAME* frame) {
    return (frame->buffer[4] >> 6) & 0x01;
}

static inline void fsd_set_speed_profile_v12v13(CANFRAME* frame, int profile) {
    frame->buffer[6] &= ~0x06;
    frame->buffer[6] |= (profile << 1);
}

static inline void fsd_set_bit(CANFRAME* frame, int bit, bool value) {
    int byte_index = bit / 8;
    int bit_index = bit % 8;
    uint8_t mask = (uint8_t)(1U << bit_index);
    if(value) {
        frame->buffer[byte_index] |= mask;
    } else {
        frame->buffer[byte_index] &= (uint8_t)(~mask);
    }
}

/* ---- Per-Variant Handlers ---- */

static void fsd_handle_legacy(
    MCP2515* CAN,
    CANFRAME* frame,
    int* speed_profile,
    bool* fsd_enabled,
    uint32_t* modified_count) {
    if(frame->canId != 1006) return;

    uint8_t mux = fsd_read_mux_id(frame);

    if(mux == 0 && fsd_is_selected_in_ui(frame)) {
        *fsd_enabled = true;
        int off = (int)((frame->buffer[3] >> 1) & 0x3F) - 30;
        switch(off) {
        case 2: *speed_profile = 2; break;
        case 1: *speed_profile = 1; break;
        case 0: *speed_profile = 0; break;
        default: break;
        }
        fsd_set_bit(frame, 46, true);
        fsd_set_speed_profile_v12v13(frame, *speed_profile);
        send_can_frame(CAN, frame);
        (*modified_count)++;
    } else if(mux == 0) {
        *fsd_enabled = false;
    }

    if(mux == 1) {
        fsd_set_bit(frame, 19, false); // Clear nag
        send_can_frame(CAN, frame);
        (*modified_count)++;
    }
}

static void fsd_handle_hw3(
    MCP2515* CAN,
    CANFRAME* frame,
    int* speed_profile,
    int* speed_offset,
    bool* fsd_enabled,
    uint32_t* modified_count) {
    if(frame->canId == 1016) {
        uint8_t follow_distance = (frame->buffer[5] & 0xE0) >> 5;
        switch(follow_distance) {
        case 1: *speed_profile = 2; break; // Hurry
        case 2: *speed_profile = 1; break; // Normal
        case 3: *speed_profile = 0; break; // Chill
        default: break;
        }
        return;
    }

    if(frame->canId != 1021) return;

    uint8_t mux = fsd_read_mux_id(frame);
    bool fsd_sel = fsd_is_selected_in_ui(frame);

    if(mux == 0) {
        *fsd_enabled = fsd_sel;
    }

    if(mux == 0 && fsd_sel) {
        int raw_off = (int)((frame->buffer[3] >> 1) & 0x3F) - 30;
        int calc_offset = raw_off * 5;
        if(calc_offset < 0) calc_offset = 0;
        if(calc_offset > 100) calc_offset = 100;
        *speed_offset = calc_offset;

        switch(raw_off) {
        case 2: *speed_profile = 2; break;
        case 1: *speed_profile = 1; break;
        case 0: *speed_profile = 0; break;
        default: break;
        }
        fsd_set_bit(frame, 46, true);
        fsd_set_speed_profile_v12v13(frame, *speed_profile);
        send_can_frame(CAN, frame);
        (*modified_count)++;
    }

    if(mux == 1) {
        fsd_set_bit(frame, 19, false); // Clear nag
        send_can_frame(CAN, frame);
        (*modified_count)++;
    }

    if(mux == 2 && *fsd_enabled) {
        frame->buffer[0] &= ~(0xC0);
        frame->buffer[1] &= ~(0x3F);
        frame->buffer[0] |= (*speed_offset & 0x03) << 6;
        frame->buffer[1] |= (*speed_offset >> 2);
        send_can_frame(CAN, frame);
        (*modified_count)++;
    }
}

static void fsd_handle_hw4(
    MCP2515* CAN,
    CANFRAME* frame,
    int* speed_profile,
    bool* fsd_enabled,
    uint32_t* modified_count) {
    if(frame->canId == 1016) {
        uint8_t fd = (frame->buffer[5] & 0xE0) >> 5;
        switch(fd) {
        case 1: *speed_profile = 3; break; // Max
        case 2: *speed_profile = 2; break; // Hurry
        case 3: *speed_profile = 1; break; // Normal
        case 4: *speed_profile = 0; break; // Chill
        case 5: *speed_profile = 4; break; // Sloth
        default: break;
        }
        return;
    }

    if(frame->canId != 1021) return;

    uint8_t mux = fsd_read_mux_id(frame);
    bool fsd_sel = fsd_is_selected_in_ui(frame);

    if(mux == 0) {
        *fsd_enabled = fsd_sel;
    }

    if(mux == 0 && fsd_sel) {
        fsd_set_bit(frame, 46, true);
        fsd_set_bit(frame, 60, true);
        send_can_frame(CAN, frame);
        (*modified_count)++;
    }

    if(mux == 1) {
        fsd_set_bit(frame, 19, false); // Clear nag
        fsd_set_bit(frame, 47, true);
        send_can_frame(CAN, frame);
        (*modified_count)++;
    }

    if(mux == 2) {
        frame->buffer[7] &= ~(0x07 << 4);
        frame->buffer[7] |= (*speed_profile & 0x07) << 4;
        send_can_frame(CAN, frame);
        (*modified_count)++;
    }
}

/* ---- Worker Thread ---- */

static int32_t tesla_fsd_worker_thread(void* context) {
    App* app = context;
    MCP2515* mcp = app->mcp_can;
    FuriString* text = app->text;

    furi_string_reset(text);

    MCP2515* CAN = mcp_alloc(MCP_NORMAL, mcp->clck, mcp->bitRate);
    if(mcp2515_init(CAN) != ERROR_OK) {
        furi_string_cat_printf(text, "Device not connected\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        free_mcp2515(CAN);
        return 0;
    }

    // Accept all CAN IDs
    init_mask(CAN, 0, 0);
    init_mask(CAN, 1, 0);

    furi_string_cat_printf(text, "Tesla FSD [%s]\n", hw_variant_names[fsd_hw_variant]);
    furi_string_cat_printf(text, "Running... BACK to stop\n\n");
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    int speed_profile = 1;
    int speed_offset = 0;
    bool fsd_enabled = false;
    uint32_t frame_count = 0;
    uint32_t modified_count = 0;
    uint32_t last_status_update = 0;

    while(furi_hal_gpio_read(&gpio_button_back)) {
        CANFRAME frame = {0};

        if(read_can_message(CAN, &frame) != ERROR_OK) {
            furi_delay_us(100);
            continue;
        }

        frame_count++;

        switch(fsd_hw_variant) {
        case TeslaHW_Legacy:
            fsd_handle_legacy(CAN, &frame, &speed_profile, &fsd_enabled, &modified_count);
            break;
        case TeslaHW_HW3:
            fsd_handle_hw3(CAN, &frame, &speed_profile, &speed_offset, &fsd_enabled, &modified_count);
            break;
        case TeslaHW_HW4:
            fsd_handle_hw4(CAN, &frame, &speed_profile, &fsd_enabled, &modified_count);
            break;
        }

        // Update display every 500ms
        uint32_t now = furi_get_tick();
        if(now - last_status_update > 500) {
            last_status_update = now;
            furi_string_reset(text);
            furi_string_cat_printf(text, "Tesla FSD [%s]\n", hw_variant_names[fsd_hw_variant]);
            furi_string_cat_printf(text, "FSD: %s\n", fsd_enabled ? "ENABLED" : "disabled");

            if(fsd_hw_variant == TeslaHW_HW4) {
                furi_string_cat_printf(text, "Profile: %s\n",
                    (speed_profile < 5) ? profile_names_5[speed_profile] : "?");
            } else {
                furi_string_cat_printf(text, "Profile: %s\n",
                    (speed_profile < 3) ? profile_names_3[speed_profile] : "?");
            }

            if(fsd_hw_variant == TeslaHW_HW3) {
                furi_string_cat_printf(text, "Offset: %d km/h\n", speed_offset);
            }

            furi_string_cat_printf(text, "\nRX: %lu  MOD: %lu\n", frame_count, modified_count);
            furi_string_cat_printf(text, "BACK to stop");
            text_box_set_text(app->textBox, furi_string_get_cstr(text));
        }
    }

    furi_string_reset(text);
    furi_string_cat_printf(text, "Tesla FSD [%s]\n", hw_variant_names[fsd_hw_variant]);
    furi_string_cat_printf(text, "Stopped.\n");
    furi_string_cat_printf(text, "RX: %lu  MOD: %lu\n", frame_count, modified_count);
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    deinit_mcp2515(CAN);
    free(CAN);
    return 0;
}

/* ---- Settings Menu Scene ---- */

static void fsd_setting_changed(VariableItem* item) {
    uint8_t index = variable_item_get_current_value_index(item);
    fsd_hw_variant = index;
    variable_item_set_current_value_text(item, hw_variant_names[index]);
}

static void fsd_start_callback(void* context, uint32_t index) {
    App* app = context;
    fsd_menu_selector = index;
    if(index == 1) { // "Start" item
        scene_manager_next_scene(app->scene_manager, app_scene_tesla_fsd_run_option);
    }
}

void app_scene_tesla_fsd_menu_on_enter(void* context) {
    App* app = context;
    VariableItem* item;

    variable_item_list_reset(app->varList);

    // HW Variant
    item = variable_item_list_add(
        app->varList, "HW Variant", HW_VARIANT_COUNT, fsd_setting_changed, app);
    variable_item_set_current_value_index(item, fsd_hw_variant);
    variable_item_set_current_value_text(item, hw_variant_names[fsd_hw_variant]);

    // Start button
    variable_item_list_add(app->varList, ">> Start", 0, NULL, app);

    variable_item_list_set_enter_callback(app->varList, fsd_start_callback, app);
    variable_item_list_set_selected_item(app->varList, fsd_menu_selector);

    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

bool app_scene_tesla_fsd_menu_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_tesla_fsd_menu_on_exit(void* context) {
    App* app = context;
    variable_item_list_reset(app->varList);
}

/* ---- Run Scene ---- */

void app_scene_tesla_fsd_run_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusEnd);

    app->thread = furi_thread_alloc_ex("TeslaFSD", 4 * 1024, tesla_fsd_worker_thread, app);
    furi_thread_start(app->thread);

    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
}

bool app_scene_tesla_fsd_run_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_tesla_fsd_run_on_exit(void* context) {
    App* app = context;
    furi_thread_join(app->thread);
    furi_thread_free(app->thread);
    text_box_reset(app->textBox);
}
