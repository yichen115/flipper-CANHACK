#include "../app_user.h"
#include "../libraries/can_clock.h"
#include "../libraries/can_trace.h"

typedef enum {
    SEND_OK,
    SEND_ERROR,
} sender_status;

// This part is for the time
enum {
    ONCE,
    PERIODIC
} sender_periods;

static uint8_t timing = 0;

static const char* timing_texts[] = {"ONCE", "PERIODIC", "REPEAT"};
static const char* timing_multiply[] = {"x1", "x10", "x100", "x1000", "x10000", "x100000"};

static uint8_t time = 1;
static uint8_t multiply = 3;

static uint8_t quantity_to_repeat = 10;
static uint8_t multiply_quantity = 0;

// Only solution I think for the text with
// the dynamic menu in set data to get the bytes
static const char* text_bytes[] = {
    "Byte [0]",
    "Byte [1]",
    "Byte [2]",
    "Byte [3]",
    "Byte [4]",
    "Byte [5]",
    "Byte [6]",
    "Byte [7]",
};

// Data for the can Id
uint8_t can_id[4];

// Empty Callback
void empty_input_callback(void* context, uint32_t index) {
    UNUSED(context);
    UNUSED(index);
}

/**
 * Threads
 */

static int32_t sender_worker(void* context);
#define SENDER_REFRESH 100U
#define SENDER_EVENT_REBUILD 1000U
static struct {
    FuriMutex* mutex;
    uint32_t attempted;
    uint32_t sent;
    uint32_t errors;
    uint32_t total;
    uint32_t remaining_ms;
    ERROR_CAN last_status;
    bool finished;
    bool init_failed;
} sender;

/**
 *  Scene for the Menu Sender
 */

// Option callback using button OK
static void sender_select(void* context, uint32_t index) {
    App* app = context;
    app->sender_selected_item = index;

    switch(index) {
    case 0:
        scene_manager_next_scene(app->scene_manager, app_scene_send_message_option);
        break;
    case 1:
        scene_manager_next_scene(app->scene_manager, app_scene_set_timing_option);
        break;

    case 2:
        scene_manager_next_scene(app->scene_manager, app_scene_set_data_sender_option);
        break;

    case 3:
        if(!app->frame_to_send->data_length || app->frame_to_send->req) break;
        scene_manager_set_scene_state(app->scene_manager, app_scene_input_data_option, 0xff);
        scene_manager_next_scene(app->scene_manager, app_scene_input_data_option);

    default:
        break;
    }
}

void callback_input_sender_options(void* context, uint32_t index) {
    App* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void set_timing_menu_callback(VariableItem* item) {
    timing = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, timing_texts[timing]);
}

// To display the variable list
void default_list_for_sender_menu(App* app) {
    VariableItem* item;
    variable_item_list_reset(app->varList);

    // First Item [0]
    item = variable_item_list_add(app->varList, "SEND MESSAGE", 0, NULL, app);
    variable_item_set_current_value_index(item, 0);

    // Second Item [1]
    item = variable_item_list_add(app->varList, "Timing", 3, set_timing_menu_callback, app);
    variable_item_set_current_value_index(item, timing);
    variable_item_set_current_value_text(item, timing_texts[timing]);

    // Third Item [2]
    item = variable_item_list_add(app->varList, "DATA", 0, NULL, app);
    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "0x%lx", app->frame_to_send->canId);
    variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));

    // This is for the
    furi_string_reset(app->text);

    for(uint8_t i = 0; i < app->frame_to_send->data_length; i++) {
        if(app->frame_to_send->buffer[i] < 0x10) {
            furi_string_cat_printf(app->text, "0%x ", app->frame_to_send->buffer[i]);
        } else {
            furi_string_cat_printf(app->text, "%x ", app->frame_to_send->buffer[i]);
        }
    }

    if(app->frame_to_send->data_length == 0 || app->frame_to_send->req == 1) {
        furi_string_reset(app->text);
        furi_string_cat_printf(app->text, "---");
    }

    // Fourth Item [3]
    item = variable_item_list_add(app->varList, furi_string_get_cstr(app->text), 0, NULL, app);

    variable_item_list_set_enter_callback(app->varList, callback_input_sender_options, app);

    variable_item_list_set_selected_item(app->varList, app->sender_selected_item);
}

// Menu sender Scene On enter
void app_scene_sender_on_enter(void* context) {
    App* app = context;

    default_list_for_sender_menu(app);

    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

// Menu Sender On event
bool app_scene_sender_on_event(void* context, SceneManagerEvent event) {
    if(event.type == SceneManagerEventTypeCustom && event.event <= 3) {
        sender_select(context, event.event);
        return true;
    }
    return false;
}

// Menu Sender On exit
void app_scene_sender_on_exit(void* context) {
    App* app = context;
    variable_item_list_reset(app->varList);
}

/**
 * Scene to set the timming
 */

void set_timing_view(App* app);

void set_timings_callback(VariableItem* item) {
    App* app = variable_item_get_context(item);
    timing = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, timing_texts[timing]);

    view_dispatcher_send_custom_event(app->view_dispatcher, SENDER_EVENT_REBUILD);
}

void set_time_sender(VariableItem* item) {
    App* app = variable_item_get_context(item);
    time = variable_item_get_current_value_index(item) + 1;

    furi_string_reset(app->text);

    furi_string_cat_printf(app->text, "%u ms", time);

    variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));
}

void set_multiply_time(VariableItem* item) {
    multiply = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, timing_multiply[multiply]);
}

void set_multiply_count(VariableItem* item) {
    multiply_quantity = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, timing_multiply[multiply_quantity]);
}

void set_count_to_send(VariableItem* item) {
    App* app = variable_item_get_context(item);
    quantity_to_repeat = variable_item_get_current_value_index(item) + 1;

    furi_string_reset(app->text);

    furi_string_cat_printf(app->text, "%u", quantity_to_repeat);

    variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));
}

// View to display
void set_timing_view(App* app) {
    VariableItem* item;
    variable_item_list_reset(app->varList);
    variable_item_list_set_enter_callback(app->varList, empty_input_callback, app);

    // First Item
    item = variable_item_list_add(app->varList, "Timing", 3, set_timings_callback, app);
    variable_item_set_current_value_index(item, timing);
    variable_item_set_current_value_text(item, timing_texts[timing]);

    // Second Item
    if(timing) {
        item = variable_item_list_add(app->varList, "Time", 255, set_time_sender, app);
        variable_item_set_current_value_index(item, time - 1);
        furi_string_reset(app->text);
        furi_string_cat_printf(app->text, "%u ms", time);
        variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));
    } else {
        item = variable_item_list_add(app->varList, "After", 255, set_time_sender, app);
        variable_item_set_current_value_index(item, time - 1);
        furi_string_reset(app->text);
        furi_string_cat_printf(app->text, "%u ms", time);
        variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));
    }

    // Third Item

    item = variable_item_list_add(app->varList, "Multiply by", 4, set_multiply_time, app);
    variable_item_set_current_value_index(item, multiply);
    variable_item_set_current_value_text(item, timing_multiply[multiply]);

    if(timing == 2) {
        item = variable_item_list_add(app->varList, "Count to send", 100, set_count_to_send, app);
        variable_item_set_current_value_index(item, quantity_to_repeat - 1);
        furi_string_reset(app->text);
        furi_string_cat_printf(app->text, "%u", quantity_to_repeat);
        variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));

        item = variable_item_list_add(app->varList, "Count Multiply", 6, set_multiply_count, app);
        variable_item_set_current_value_index(item, multiply_quantity);
        variable_item_set_current_value_text(item, timing_multiply[multiply_quantity]);
    }
}

// Menu sender Scene On enter
void app_scene_set_timing_on_enter(void* context) {
    App* app = context;

    set_timing_view(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

// Menu Sender On event
bool app_scene_set_timing_on_event(void* context, SceneManagerEvent event) {
    if(event.type == SceneManagerEventTypeCustom && event.event == SENDER_EVENT_REBUILD) {
        set_timing_view(context);
        return true;
    }
    return false;
}

// Menu Sender On exit
void app_scene_set_timing_on_exit(void* context) {
    App* app = context;
    variable_item_list_reset(app->varList);
}

/**
 * Scene to set the timing
 */

void set_data_view(App* app);

// Go to set the option
static void sender_data_select(void* context, uint32_t index) {
    App* app = context;

    if(index == 1 || index > 3) {
        scene_manager_set_scene_state(app->scene_manager, app_scene_input_data_option, index);
        scene_manager_next_scene(app->scene_manager, app_scene_input_data_option);
    }
}

void input_set_data(void* context, uint32_t index) {
    App* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

// Callback for the frame
void set_frame_request_callback(VariableItem* item) {
    App* app = variable_item_get_context(item);

    app->frame_to_send->req = variable_item_get_current_value_index(item);

    view_dispatcher_send_custom_event(app->view_dispatcher, SENDER_EVENT_REBUILD);
}

// Callback to set the data length
void set_data_length_callback(VariableItem* item) {
    App* app = variable_item_get_context(item);

    app->frame_to_send->data_length = variable_item_get_current_value_index(item);

    view_dispatcher_send_custom_event(app->view_dispatcher, SENDER_EVENT_REBUILD);
}

// View to set the Data
void set_data_view(App* app) {
    VariableItem* item;
    variable_item_list_reset(app->varList);

    variable_item_list_set_enter_callback(app->varList, input_set_data, app);

    // first item [0]
    item = variable_item_list_add(app->varList, "Choose last ID", 0, NULL, app);

    // second item [1]
    item = variable_item_list_add(app->varList, "Set Id", 0, NULL, app);
    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "0x%lx", app->frame_to_send->canId);
    variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));

    // third item [2]
    item =
        variable_item_list_add(app->varList, "Frame request", 2, set_frame_request_callback, app);
    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "%u", app->frame_to_send->req);
    variable_item_set_current_value_index(item, app->frame_to_send->req);
    variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));

    if(app->frame_to_send->req) return;

    // fourth item [4]
    item = variable_item_list_add(app->varList, "Data Length", 9, set_data_length_callback, app);
    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "%u", app->frame_to_send->data_length);
    variable_item_set_current_value_index(item, app->frame_to_send->data_length);
    variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));

    for(uint8_t i = 0; i < app->frame_to_send->data_length; i++) {
        item = variable_item_list_add(app->varList, text_bytes[i], 0, NULL, app);

        furi_string_reset(app->text);
        furi_string_cat_printf(app->text, "0x");
        if(app->frame_to_send->buffer[i] < 0x10) {
            furi_string_cat_printf(app->text, "0");
        }
        furi_string_cat_printf(app->text, "%x", app->frame_to_send->buffer[i]);
        variable_item_set_current_value_text(item, furi_string_get_cstr(app->text));
    }
}

// Menu sender Scene On enter
void app_scene_set_data_sender_on_enter(void* context) {
    App* app = context;

    set_data_view(app);

    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

// Menu Sender On event
bool app_scene_set_data_sender_on_event(void* context, SceneManagerEvent event) {
    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == SENDER_EVENT_REBUILD) set_data_view(context);
        else sender_data_select(context, event.event);
        return true;
    }
    return false;
}

// Menu Sender On exit
void app_scene_set_data_sender_on_exit(void* context) {
    App* app = context;
    variable_item_list_reset(app->varList);
}

/**
 * Scene used for the input on the menu sender
 */

void input_byte_sender_callback(void* context) {
    App* app = context;

    uint32_t state =
        scene_manager_get_scene_state(app->scene_manager, app_scene_input_data_option);

    switch(state) {
    case 1:
        app->frame_to_send->canId = ((uint32_t)can_id[0] << 24) | ((uint32_t)can_id[1] << 16) | ((uint32_t)can_id[2] << 8) |
                                    (can_id[3]);
        app->frame_to_send->canId &= 0x1FFFFFFF;
        app->frame_to_send->ext = app->frame_to_send->canId > 0x7FF;
        break;

    default:
        break;
    }

    scene_manager_previous_scene(app->scene_manager);
}

void app_scene_input_data_on_enter(void* context) {
    App* app = context;
    ByteInput* scene = app->input_byte_value;

    uint32_t state =
        scene_manager_get_scene_state(app->scene_manager, app_scene_input_data_option);

    if(state == 1) {
        can_id[3] = app->frame_to_send->canId;
        can_id[2] = app->frame_to_send->canId >> 8;
        can_id[1] = app->frame_to_send->canId >> 16;
        can_id[0] = app->frame_to_send->canId >> 24;

        byte_input_set_header_text(scene, "SET ID");
        byte_input_set_result_callback(scene, input_byte_sender_callback, NULL, app, can_id, 4);
    }
    if((state > 1) && (state < 0xff)) {
        state = state - 4;

        furi_string_reset(app->text);
        furi_string_cat_printf(app->text, "Set Byte [%lu]", state);
        byte_input_set_header_text(scene, furi_string_get_cstr(app->text));
        byte_input_set_result_callback(
            scene, input_byte_sender_callback, NULL, app, &(app->frame_to_send->buffer[state]), 1);
    }

    if(state == 0xff) {
        byte_input_set_header_text(scene, "Set Data");
        byte_input_set_result_callback(
            scene,
            input_byte_sender_callback,
            NULL,
            app,
            app->frame_to_send->buffer,
            app->frame_to_send->data_length);
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, InputByteView);
}

bool app_scene_input_data_on_event(void* context, SceneManagerEvent event) {
    App* app = context;
    bool consumed = false;
    UNUSED(event);
    UNUSED(app);

    return consumed;
}

void app_scene_input_data_on_exit(void* context) {
    UNUSED(context);
}

/**
 *  Scene for display the sender
 */

// Views for the sender
void draw_timer_to_send(App* app, double time) {
    widget_reset(app->widget);
    widget_add_string_multiline_element(
        app->widget,
        64,
        20,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        "Message will be\nsent in...");

    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "%.3f ms", time);

    widget_add_string_element(
        app->widget,
        64,
        40,
        AlignCenter,
        AlignCenter,
        FontPrimary,
        furi_string_get_cstr(app->text));
}

// Views to know if it was send it
void draw_data_send(App* app, bool was_send_it, uint32_t count) {
    widget_reset(app->widget);

    if(was_send_it) {
        widget_add_string_element(
            app->widget, 64, 10, AlignCenter, AlignCenter, FontPrimary, "Successfully");
    } else {
        widget_add_string_element(
            app->widget, 64, 10, AlignCenter, AlignCenter, FontPrimary, "Failure");
    }

    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "%lx\n", app->frame_to_send->canId);

    if(app->frame_to_send->req) {
        furi_string_cat_printf(app->text, "Request");
        widget_add_string_element(
            app->widget,
            64,
            32,
            AlignCenter,
            AlignCenter,
            FontPrimary,
            furi_string_get_cstr(app->text));

        return;
    }

    for(uint8_t i = 0; i < app->frame_to_send->data_length; i++) {
        if(app->frame_to_send->buffer[i] > 0xf) {
            furi_string_cat_printf(app->text, "%x ", app->frame_to_send->buffer[i]);
            continue;
        }

        furi_string_cat_printf(app->text, "0%x ", app->frame_to_send->buffer[i]);
    }

    widget_add_string_multiline_element(
        app->widget,
        64,
        30,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        furi_string_get_cstr(app->text));

    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "Message count: %lu", count);

    widget_add_string_element(
        app->widget,
        64,
        50,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        furi_string_get_cstr(app->text));
}

void draw_data_send_repeat(App* app, bool was_send_it, uint32_t count, uint32_t total_count) {
    widget_reset(app->widget);

    furi_string_reset(app->text);

    if(was_send_it) {
        widget_add_string_element(
            app->widget, 64, 20, AlignCenter, AlignCenter, FontPrimary, "Successfully");
    } else {
        widget_add_string_element(
            app->widget, 64, 20, AlignCenter, AlignCenter, FontPrimary, "Failure");
    }

    furi_string_cat_printf(app->text, "%lx ", app->frame_to_send->canId);

    if(app->frame_to_send->req) {
        furi_string_cat_printf(app->text, "Request");
        widget_add_string_element(
            app->widget,
            64,
            32,
            AlignCenter,
            AlignCenter,
            FontPrimary,
            furi_string_get_cstr(app->text));

        return;
    }

    for(uint8_t i = 0; i < app->frame_to_send->data_length; i++) {
        if(app->frame_to_send->buffer[i] > 0xf) {
            furi_string_cat_printf(app->text, "%x ", app->frame_to_send->buffer[i]);
            continue;
        }

        furi_string_cat_printf(app->text, "0%x ", app->frame_to_send->buffer[i]);
    }

    widget_add_string_element(
        app->widget,
        64,
        32,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        furi_string_get_cstr(app->text));

    furi_string_reset(app->text);
    furi_string_cat_printf(app->text, "%lu of %lu", count, total_count);

    widget_add_string_element(
        app->widget,
        64,
        45,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        furi_string_get_cstr(app->text));
}

void draw_waiting_time_to_send(App* app) {
    widget_reset(app->widget);

    widget_add_string_multiline_element(
        app->widget, 64, 32, AlignCenter, AlignCenter, FontPrimary, "WAITING TIME\n TO SEND");
}

void draw_finished_to_send(App* app) {
    widget_reset(app->widget);

    widget_add_string_multiline_element(
        app->widget, 64, 32, AlignCenter, AlignCenter, FontPrimary, "FINISHED\n TO SEND");
}

static void sender_refresh(App* app) {
    furi_mutex_acquire(sender.mutex, FuriWaitForever);
    uint32_t attempted = sender.attempted, sent = sender.sent, errors = sender.errors;
    uint32_t total = sender.total, remaining = sender.remaining_ms;
    bool finished = sender.finished, init_failed = sender.init_failed;
    ERROR_CAN status = sender.last_status;
    furi_mutex_release(sender.mutex);
    widget_reset(app->widget);
    if(init_failed) { draw_device_no_connected(app); return; }
    furi_string_printf(app->text, "%s %03lX\nSent %lu  Errors %lu\nAttempts %lu",
        finished ? "Finished" : timing == 0 ? "Once" : timing == 1 ? "Periodic" : "Repeat",
        app->frame_to_send->canId, sent, errors, attempted);
    if(timing != 1) furi_string_cat_printf(app->text, "/%lu", total);
    if(!attempted && !finished) furi_string_cat_printf(app->text, "\nIn %lu ms", remaining);
    if(errors) furi_string_cat_printf(app->text, "\nCAN status %u", status);
    furi_string_cat_printf(app->text, "\nBACK: stop");
    widget_add_string_multiline_element(app->widget, 64, 32, AlignCenter, AlignCenter,
        FontSecondary, furi_string_get_cstr(app->text));
}

void app_scene_send_message_on_enter(void* context) {
    App* app = context;
    memset(&sender, 0, sizeof(sender));
    sender.mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    sender.total = timing == 0 ? 1 : can_scaled_count(quantity_to_repeat, multiply_quantity);
    sender.remaining_ms = can_scaled_count(time, multiply);
    widget_reset(app->widget);
    sender_refresh(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewWidget);
    app->thread = furi_thread_alloc_ex("CanSender", 3072, sender_worker, app);
    furi_thread_start(app->thread);
}

bool app_scene_send_message_on_event(void* context, SceneManagerEvent event) {
    if(event.type == SceneManagerEventTypeTick) { sender_refresh(context); return true; }
    return false;
}

void app_scene_send_message_on_exit(void* context) {
    App* app = context;
    if(app->thread) {
        FuriThreadId id = furi_thread_get_id(app->thread);
        if(id) furi_thread_flags_set(id, THREAD_SNIFFER_STOP);
        furi_thread_join(app->thread);
        furi_thread_free(app->thread);
        app->thread = NULL;
    }
    furi_mutex_free(sender.mutex);
    sender.mutex = NULL;
    widget_reset(app->widget);
}

static int32_t sender_worker(void* context) {
    App* app = context;
    MCP2515* can = app->mcp_can;
    can->mode = MCP_NORMAL;
    if(mcp2515_init(can) != ERROR_OK) {
        furi_mutex_acquire(sender.mutex, FuriWaitForever);
        sender.init_failed = true;
        sender.finished = true;
        furi_mutex_release(sender.mutex);
        deinit_mcp2515(can);
        return 0;
    }
    CanClock clock = can_clock_start();
    uint64_t period = (uint64_t)can_scaled_count(time, multiply) * 1000;
    uint64_t deadline = period;
    uint32_t attempted = 0;
    uint32_t last_ui = furi_get_tick();
    while(!(furi_thread_flags_get() & THREAD_SNIFFER_STOP)) {
        uint64_t now = can_clock_us(&clock);
        if(now < deadline) {
            if(furi_get_tick() - last_ui >= SENDER_REFRESH) {
                furi_mutex_acquire(sender.mutex, FuriWaitForever);
                sender.remaining_ms = (deadline - now + 999) / 1000;
                furi_mutex_release(sender.mutex);
                last_ui = furi_get_tick();
            }
            // Bound the wait so the countdown snapshot remains current.
            if(!can_wait_until(&clock, deadline < now + 10000 ? deadline : now + 10000)) break;
            continue;
        }
        ERROR_CAN status = send_can_frame(can, app->frame_to_send);
        attempted++;
        furi_mutex_acquire(sender.mutex, FuriWaitForever);
        sender.attempted = attempted;
        sender.last_status = status;
        if(status == ERROR_OK) sender.sent++;
        else sender.errors++;
        furi_mutex_release(sender.mutex);
        if((timing != 1 && attempted >= sender.total) || attempted == UINT32_MAX ||
           status == ERROR_BUSOFF || status == ERROR_TX_UNCERTAIN || status == ERROR_SPI) break;
        deadline = can_periodic_next(deadline, period, can_clock_us(&clock));
    }
    can_clock_stop(&clock);
    deinit_mcp2515(can);
    furi_mutex_acquire(sender.mutex, FuriWaitForever);
    sender.finished = true;
    furi_mutex_release(sender.mutex);
    return 0;
}
