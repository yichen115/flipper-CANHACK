#ifndef UDS_ALLINONE_H
#define UDS_ALLINONE_H

#include <furi.h>
#include <furi_hal.h>
#include <storage/storage.h>
#include <datetime/datetime.h>

#define ALLINONE_KEEPALIVE_INTERVAL_MS 2000
#define ALLINONE_MAX_SECURITY_LEVEL 0x1F
#define ALLINONE_DID_RANGES_COUNT 4

typedef enum {
    AllInOneState_Settings,
    AllInOneState_Discovery,
    AllInOneState_Testing,
    AllInOneState_Complete,
} AllInOneState;

typedef enum {
    SessionType_Default = 0x01,
    SessionType_Programming = 0x02,
    SessionType_Extended = 0x03,
    SessionType_Safety = 0x04,
} SessionType;

typedef struct {
    uint32_t tx_id;
    uint32_t rx_id;
} ECUInfo;

typedef struct {
    uint8_t level;
    bool supported;
    bool locked;
    uint32_t seed;
    uint8_t seed_len;
    bool key_found;
    uint32_t key;
    uint16_t bruteforce_attempts;
    uint8_t nrc;
} SecurityLevelInfo;

typedef struct {
    SessionType session_type;
    bool session_set_success;
    uint16_t* found_dids;
    uint16_t found_did_count;
    SecurityLevelInfo security_levels[16];
    uint8_t security_level_count;
} SessionTestResult;

typedef struct {
    ECUInfo ecu;
    SessionTestResult sessions[4];
    uint8_t session_count;
} ECUTestResult;

typedef struct {
    uint32_t scan_start_id;
    uint32_t scan_end_id;
    ECUInfo* found_ecus;
    uint8_t ecu_count;
    ECUTestResult* ecu_results;
    uint8_t current_ecu_index;
    uint8_t current_session_index;
    AllInOneState state;
    FuriTimer* keepalive_timer;
    bool keepalive_running;
    SessionType current_session;
    Storage* storage;
    File* result_file;
    char result_file_path[128];
} AllInOneContext;

// DID ranges to scan
typedef struct {
    uint16_t start;
    uint16_t end;
    const char* name;
} DIDRange;

static const DIDRange allinone_did_ranges[ALLINONE_DID_RANGES_COUNT] = {
    {0xF180, 0xF1A0, "Identification"},
    // {0xF000, 0xF0FF, "Common"},
    // {0x0100, 0x01FF, "OEM"},
    // {0xFD00, 0xFEFF, "Extended"},
};

// Function prototypes
void allinone_context_init(AllInOneContext* ctx);
void allinone_context_free(AllInOneContext* ctx);
bool allinone_create_result_file(AllInOneContext* ctx);
void allinone_close_result_file(AllInOneContext* ctx);
void allinone_write_header(AllInOneContext* ctx);
void allinone_write_ecu_header(AllInOneContext* ctx, ECUInfo* ecu);
void allinone_write_session_header(AllInOneContext* ctx, SessionType session);
void allinone_write_did_results(AllInOneContext* ctx, uint16_t* dids, uint16_t count);
void allinone_write_security_results(AllInOneContext* ctx, SecurityLevelInfo* levels, uint8_t count);
void allinone_write_footer(AllInOneContext* ctx);

#endif // UDS_ALLINONE_H
