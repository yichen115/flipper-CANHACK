#include "../../app_user.h"

#define SESSION_KEEPALIVE_INTERVAL_MS 2000

typedef enum {
    SessionDefault = 0x01,
    SessionProgramming = 0x02,
    SessionExtended = 0x03,
    SessionSafety = 0x04,
} DiagnosticSessionType;

static const char* session_names[] = {
    "Default (0x01)",
    "Programming (0x02)",
    "Extended (0x03)",
    "Safety System (0x04)",
};

static uint8_t selected_session = SessionDefault;
static uint32_t target_scene = 0;
static FuriTimer* keepalive_timer = NULL;
static bool session_active = false;
static uint8_t current_session_type = SessionDefault;

// Forward declaration
static void send_tester_present(void* context);

static void keepalive_timer_callback(void* context) {
    App* app = context;
    
    // Only send if session is active and not default session
    if(session_active && current_session_type != SessionDefault) {
        send_tester_present(app);
    }
}

static void send_tester_present(void* context) {
    App* app = context;

    // Create a simple CAN frame for Tester Present (0x3E 0x80)
    // 0x80 = suppressPositiveResponseMessage, ECU will not reply
    CANFRAME frame = {0};
    frame.canId = app->uds_send_id;
    frame.data_length = 8;
    frame.buffer[0] = 0x02;  // PCI - single frame, 2 bytes
    frame.buffer[1] = 0x3E;  // Service: Tester Present
    frame.buffer[2] = 0x80;  // Sub-function: suppress response
    // Pad remaining bytes
    for(uint8_t i = 3; i < 8; i++) frame.buffer[i] = 0xCC;

    // Use the app's existing MCP2515 instance - SPI acquire/release provides mutual exclusion
    send_can_frame(app->mcp_can, &frame);
}

static bool set_diagnostic_session(App* app, uint8_t session_type) {
    CANFRAME frame = {0};
    frame.canId = app->uds_send_id;
    frame.data_length = 8;
    frame.buffer[0] = 0x02;  // PCI - single frame, 2 bytes
    frame.buffer[1] = 0x10;  // Service: Diagnostic Session Control
    frame.buffer[2] = session_type;  // Session type
    // Pad remaining bytes
    for(uint8_t i = 3; i < 8; i++) frame.buffer[i] = 0xCC;

    MCP2515* CAN = mcp_alloc(MCP_NORMAL, app->mcp_can->clck, app->mcp_can->bitRate);
    if(mcp2515_init(CAN) != ERROR_OK) {
        free_mcp2515(CAN);
        return false;
    }

    init_mask(CAN, 0, 0);
    init_mask(CAN, 1, 0);

    if(send_can_frame(CAN, &frame) != ERROR_OK) {
        deinit_mcp2515(CAN);
        free(CAN);
        return false;
    }

    // Wait for response with timeout
    CANFRAME response = {0};
    uint32_t timeout = 0;
    bool success = false;

    while(timeout < 10000) {  // 10ms timeout
        if(read_can_message(CAN, &response) == ERROR_OK) {
            if(response.buffer[1] == 0x50) {  // Positive response
                success = true;
                break;
            } else if(response.buffer[1] == 0x7F) {  // Negative response
                break;
            }
        }
        furi_delay_us(1);
        timeout++;
    }

    deinit_mcp2515(CAN);
    free(CAN);

    return success;
}

void uds_session_select_callback(void* context, uint32_t index) {
    App* app = context;
    selected_session = index + 1;  // Session types start from 0x01
    
    // Try to set the session
    if(set_diagnostic_session(app, selected_session)) {
        current_session_type = selected_session;
        session_active = true;
        
        // Start keepalive timer if not default session
        if(selected_session != SessionDefault) {
            if(keepalive_timer == NULL) {
                keepalive_timer = furi_timer_alloc(keepalive_timer_callback, FuriTimerTypePeriodic, app);
            }
            furi_timer_start(keepalive_timer, SESSION_KEEPALIVE_INTERVAL_MS);
        }
        
        // Go to target scene
        scene_manager_next_scene(app->scene_manager, target_scene);
    } else {
        // Show error - session not set
        // For now, just go to target anyway (user can retry)
        current_session_type = selected_session;
        session_active = true;
        scene_manager_next_scene(app->scene_manager, target_scene);
    }
}

void app_scene_uds_session_select_on_enter(void* context) {
    App* app = context;
    
    // Get target scene from scene state
    target_scene = scene_manager_get_scene_state(app->scene_manager, app_scene_uds_menu_option);
    
    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Select Session");
    
    for(uint8_t i = 0; i < COUNT_OF(session_names); i++) {
        submenu_add_item(
            app->submenu, 
            session_names[i], 
            i, 
            uds_session_select_callback, 
            app);
    }
    
    submenu_set_selected_item(app->submenu, selected_session - 1);
    
    view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);
}

bool app_scene_uds_session_select_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_session_select_on_exit(void* context) {
    App* app = context;
    submenu_reset(app->submenu);
}

// Function to stop keepalive (call when exiting UDS functions)
void uds_stop_keepalive(void) {
    if(keepalive_timer != NULL) {
        furi_timer_stop(keepalive_timer);
        furi_timer_free(keepalive_timer);
        keepalive_timer = NULL;
    }
    session_active = false;
}

// Function to check if we need session select
bool uds_need_session_select(void) {
    // If no session is active, we need to select
    return !session_active;
}
