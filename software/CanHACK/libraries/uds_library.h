#ifndef UDS_LIBRARY
#define UDS_LIBRARY

#include <furi_hal.h>
#include "mcp_can_2515.h"
#include "uds_transport.h"

#define DEFAULT_ECU_REQUEST  0x7e0
#define DEFAULT_ECU_RESPONSE 0x7e8

#define UDS_NRC_SERVICE_NOT_SUPPORTED      0x11
#define UDS_NRC_SUB_FUNCTION_NOT_SUPPORTED 0x12
#define UDS_NRC_INVALID_KEY                0x35
#define UDS_NRC_EXCEEDED_ATTEMPTS          0x36
#define UDS_NRC_TIME_DELAY_NOT_EXPIRED     0x37
#define UDS_NRC_RESPONSE_PENDING           0x78

#define UDS_MAX_SEED_KEY_LEN 5

typedef enum {
    DEFAULT_UDS_SESSION = 1,
    PROGRAMMING_UDS_SESSION = 2,
    EXTENDED_UDS_SESSION = 3,
    SAFETY_UDS_SESSION = 4,
} diagnostic_session;

typedef enum {
    HARD_RESET = 1,
    KEY_OFF_ON_RESET = 2,
    SOFT_RESET = 3,
} type_ecu_reset;

typedef struct {
    MCP2515* CAN;
    uint32_t id_to_send;
    uint32_t id_to_received;
    bool initialized;
    uint32_t timeout_ms;
    uint32_t pending_timeout_ms;
    uint32_t last_keepalive_ms;
    uint8_t session;
} UDS_SERVICE;

UdsStatus uds_request_payload(
    UDS_SERVICE* uds,
    const uint8_t* request,
    size_t request_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len);
bool uds_worker_cancelled(void);
void uds_keepalive(UDS_SERVICE* uds);
bool uds_session_response_matches(const CANFRAME* response, uint8_t session);
bool uds_discovery_probe(MCP2515* can, uint32_t request_id, uint32_t wait_ms, CANFRAME* response);
bool uds_discovery_verify(MCP2515* can, uint32_t request_id, uint32_t response_id, uint32_t wait_ms);

UDS_SERVICE* uds_service_alloc(
    uint32_t id_to_send,
    uint32_t id_to_received,
    MCP_MODE mode,
    MCP_CLOCK clk,
    MCP_BITRATE bitrate);

bool uds_init(UDS_SERVICE* uds_instance);

bool uds_single_frame_request(
    UDS_SERVICE* uds_instance,
    uint8_t* data_to_send,
    uint8_t count_of_bytes,
    CANFRAME* frames_to_received,
    uint8_t count_of_frames);

bool uds_multi_frame_request(
    UDS_SERVICE* uds,
    uint8_t* data,
    uint8_t length,
    CANFRAME* canframes_to_send,
    uint8_t count_of_frames_to_received,
    CANFRAME* canframes_to_received);

// sent must hold 1 frame for length <= 7, otherwise 1 + ceil((length - 6) / 7).
// received must hold count_of_frames_to_received frames; incomplete data is failure.

bool uds_get_vin(UDS_SERVICE* uds_instance, FuriString* text);

bool uds_set_diagnostic_session(UDS_SERVICE* uds_instance, diagnostic_session session);

bool uds_reset_ecu(UDS_SERVICE* uds_instance, type_ecu_reset type);

bool uds_get_count_stored_dtc(UDS_SERVICE* uds_instance, uint16_t* count_of_dtc);

// Each codes[i] needs 7 bytes. *count_of_dtc is capacity on input, count on success.
bool uds_get_stored_dtc(UDS_SERVICE* uds_instance, char* codes[], uint16_t* count_of_dtc);

bool uds_delete_dtc(UDS_SERVICE* uds_instance);

void free_uds(UDS_SERVICE* uds_instance);

const char* uds_get_service_name(uint8_t service_id);

const char* uds_get_nrc_name(uint8_t nrc);

bool uds_tester_present(UDS_SERVICE* uds_instance);

bool uds_security_request_seed(
    UDS_SERVICE* uds_instance,
    uint8_t level,
    CANFRAME* response);

bool uds_read_did(
    UDS_SERVICE* uds_instance,
    uint16_t did,
    CANFRAME* frames,
    uint8_t count_of_frames);

bool uds_security_send_key(
    UDS_SERVICE* uds_instance,
    uint8_t level,
    uint8_t* key,
    uint8_t key_len,
    CANFRAME* response);

#endif
