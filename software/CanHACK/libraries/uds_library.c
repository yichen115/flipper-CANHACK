#include "uds_library.h"

typedef struct {
    uint8_t id;
    const char* name;
} UdsNameEntry;

static const UdsNameEntry uds_service_table[] = {
    {0x10, "DiagSessCtrl"},
    {0x11, "ECUReset"},
    {0x14, "ClearDTC"},
    {0x19, "ReadDTC"},
    {0x20, "ReturnNormal"},
    {0x22, "ReadDID"},
    {0x23, "ReadMemAddr"},
    {0x24, "ReadScalDID"},
    {0x27, "SecurityAccess"},
    {0x28, "CommCtrl"},
    {0x29, "Auth"},
    {0x2A, "ReadPeriodicDID"},
    {0x2C, "DynDefDID"},
    {0x2D, "DefPIDByMem"},
    {0x2E, "WriteDID"},
    {0x2F, "IOCtrlByID"},
    {0x31, "RoutineCtrl"},
    {0x34, "ReqDownload"},
    {0x35, "ReqUpload"},
    {0x36, "TransferData"},
    {0x37, "ReqTransExit"},
    {0x38, "ReqFileTrans"},
    {0x3D, "WriteMemAddr"},
    {0x3E, "TesterPresent"},
    {0x83, "AccessTimePar"},
    {0x84, "SecDataTrans"},
    {0x85, "CtrlDTCSetting"},
    {0x86, "RespOnEvent"},
    {0x87, "LinkCtrl"},
};

static const UdsNameEntry uds_nrc_table[] = {
    {0x10, "GeneralReject"},
    {0x11, "SvcNotSupported"},
    {0x12, "SubFuncNotSupp"},
    {0x13, "InvalidMsgLen"},
    {0x14, "RespTooLong"},
    {0x21, "BusyRepeat"},
    {0x22, "CondNotCorrect"},
    {0x24, "ReqSeqError"},
    {0x25, "NoRespSubnet"},
    {0x26, "FailPrevent"},
    {0x31, "OutOfRange"},
    {0x33, "SecAccessDenied"},
    {0x35, "InvalidKey"},
    {0x36, "ExceedAttempts"},
    {0x37, "TimeDelayReq"},
    {0x70, "UpDnNotAccepted"},
    {0x71, "TransSuspended"},
    {0x72, "GenProgFailure"},
    {0x73, "WrongBlockSeq"},
    {0x78, "RespPending"},
    {0x7E, "SubFuncNotInSess"},
    {0x7F, "SvcNotInSess"},
};

const char* uds_get_service_name(uint8_t service_id) {
    for(size_t i = 0; i < COUNT_OF(uds_service_table); i++) {
        if(uds_service_table[i].id == service_id) {
            return uds_service_table[i].name;
        }
    }
    return "Unknown";
}

const char* uds_get_nrc_name(uint8_t nrc) {
    for(size_t i = 0; i < COUNT_OF(uds_nrc_table); i++) {
        if(uds_nrc_table[i].id == nrc) {
            return uds_nrc_table[i].name;
        }
    }
    return "Unknown";
}

// Function to malloc the instance
UDS_SERVICE* uds_service_alloc(
    uint32_t id_to_send,
    uint32_t id_to_received,
    MCP_MODE mode,
    MCP_CLOCK clk,
    MCP_BITRATE bitrate) {
    UDS_SERVICE* instance = calloc(1, sizeof(UDS_SERVICE));
    if(!instance) return NULL;
    instance->CAN = mcp_alloc(mode, clk, bitrate);
    if(!instance->CAN) {
        free(instance);
        return NULL;
    }
    instance->id_to_send = id_to_send;
    instance->id_to_received = id_to_received;

    return instance;
}

// Init the mcp2515 with it respeclty mask and filters
bool uds_init(UDS_SERVICE* uds_instance) {
    if(!uds_instance || !uds_instance->CAN) return false;
    MCP2515* CAN = uds_instance->CAN;
    CAN->mode = MCP_NORMAL;
    if(mcp2515_init(CAN) != ERROR_OK) return false;

    uint32_t mask = 0x7ff;

    if(uds_instance->id_to_received > 0x7ff) {
        mask = 0x1FFFFFFF;
    }

    init_mask(CAN, 0, mask);
    init_filter(CAN, 0, uds_instance->id_to_received);
    init_filter(CAN, 1, uds_instance->id_to_received);

    init_mask(CAN, 1, mask);
    init_filter(CAN, 2, uds_instance->id_to_received);
    init_filter(CAN, 3, uds_instance->id_to_received);
    init_filter(CAN, 4, uds_instance->id_to_received);
    init_filter(CAN, 5, uds_instance->id_to_received);

    uds_instance->initialized = true;
    return true;
}

// Free instance
void free_uds(UDS_SERVICE* uds_instance) {
    if(!uds_instance) return;
    if(uds_instance->initialized) deinit_mcp2515(uds_instance->CAN);
    free_mcp2515(uds_instance->CAN);
    free(uds_instance);
}

// Get Frames - with NRC 0x78 ResponsePending support
bool read_frames_uds(MCP2515* CAN, uint32_t id, CANFRAME* frame) {
    uint32_t start = furi_get_tick();
    uint32_t timeout = 50;
    uint32_t total_start = start;
    while(furi_get_tick() - start < timeout && furi_get_tick() - total_start < 15000) {
        if(uds_worker_cancelled()) return false;
        if(read_can_message(CAN, frame) == ERROR_OK && frame->canId == id && !frame->req) {
            if(frame->data_length >= 4 && frame->buffer[0] == 3 &&
               frame->buffer[1] == 0x7F && frame->buffer[3] == UDS_NRC_RESPONSE_PENDING) {
                start = furi_get_tick();
                timeout = 5000;
            } else {
                return true;
            }
        } else {
            furi_delay_us(100);
        }
    }
    return false;
}

// Function to send a service
bool uds_single_frame_request(
    UDS_SERVICE* uds_instance,
    uint8_t* data_to_send,
    uint8_t count_of_bytes,
    CANFRAME* frames_to_received,
    uint8_t count_of_frames) {
    if(!data_to_send || !count_of_bytes || count_of_bytes > 7 ||
       data_to_send[0] != count_of_bytes) return false;
    CANFRAME request = {0};
    return uds_multi_frame_request(
        uds_instance, data_to_send + 1, count_of_bytes, &request,
        count_of_frames, frames_to_received);
}

// Function to get VIN
bool uds_get_vin(UDS_SERVICE* uds, FuriString* text) {
    uint8_t request[] = {0x22, 0xF1, 0x90};
    uint8_t response[20];
    size_t len = 0;
    if(uds_request_payload(uds, request, sizeof(request), response, sizeof(response), &len) != UdsOk || len != 20) return false;
    char vin[18];
    memcpy(vin, response + 3, 17);
    vin[17] = '\0';
    furi_string_set(text, vin);
    return true;
}

// Function to send multiframes
// This will be on development
bool uds_multi_frame_request(
    UDS_SERVICE* uds,
    uint8_t* data,
    uint8_t length,
    CANFRAME* sent,
    uint8_t count,
    CANFRAME* received) {
    if(!uds || !data || !length || !sent || !count || !received) return false;
    memset(received, 0, count * sizeof(CANFRAME));
    // Preserve the raw-frame API for existing callers; the transport validates
    // and reassembles the complete payload before exposing any result.
    size_t offset = 0;
    uint8_t index = 0;
    do {
        CANFRAME* frame = &sent[index];
        memset(frame, 0, sizeof(*frame));
        memset(frame->buffer, 0xCC, sizeof(frame->buffer));
        frame->canId = uds->id_to_send;
        frame->ext = uds->id_to_send > 0x7FF;
        frame->data_length = 8;
        size_t begin = 1;
        if(length <= 7) frame->buffer[0] = length;
        else if(index == 0) {
            frame->buffer[0] = 0x10;
            frame->buffer[1] = length;
            begin = 2;
        } else frame->buffer[0] = 0x20 | (index & 15);
        size_t bytes = length - offset < 8 - begin ? length - offset : 8 - begin;
        memcpy(frame->buffer + begin, data + offset, bytes);
        offset += bytes;
        index++;
    } while(offset < length);
    size_t capacity = count == 1 ? 7 : 6 + (size_t)(count - 1) * 7;
    if(capacity > UDS_PAYLOAD_MAX) capacity = UDS_PAYLOAD_MAX;
    uint8_t* payload = malloc(capacity);
    if(!payload) return false;
    size_t len = 0;
    UdsStatus status = uds_request_payload(uds, data, length, payload, capacity, &len);
    if(status != UdsOk && status != UdsNegative) {
        free(payload);
        return false;
    }
    offset = 0;
    index = 0;
    do {
        CANFRAME* frame = &received[index];
        frame->canId = uds->id_to_received;
        frame->ext = uds->id_to_received > 0x7FF;
        frame->data_length = 8;
        memset(frame->buffer, 0xCC, sizeof(frame->buffer));
        size_t begin = 1;
        if(len <= 7) frame->buffer[0] = len;
        else if(index == 0) {
            frame->buffer[0] = 0x10 | (len >> 8);
            frame->buffer[1] = len;
            begin = 2;
        } else frame->buffer[0] = 0x20 | (index & 15);
        size_t bytes = len - offset < 8 - begin ? len - offset : 8 - begin;
        memcpy(frame->buffer + begin, payload + offset, bytes);
        offset += bytes;
        index++;
    } while(offset < len && index < count);
    free(payload);
    return offset == len;
}

// Set diagnostic session
bool uds_set_diagnostic_session(UDS_SERVICE* uds_instance, diagnostic_session session) {
    uint8_t data[2] = {0x10, (uint8_t)session};

    if(session == 0) return false;

    CANFRAME frame_to_send = {0};
    CANFRAME frame_to_received = {0};

    if(!uds_multi_frame_request(
           uds_instance, data, COUNT_OF(data), &frame_to_send, 1, &frame_to_received))
        return false;

    if(frame_to_received.buffer[1] != 0x50 || frame_to_received.buffer[2] != session) return false;

    return true;
}

// Reset the ECU
bool uds_reset_ecu(UDS_SERVICE* uds_instance, type_ecu_reset type) {
    uint8_t data[2] = {0x11, (uint8_t)type};

    if(type == 0) return false;

    CANFRAME frame_to_send = {0};
    CANFRAME frame_to_received = {0};

    if(!uds_multi_frame_request(
           uds_instance, data, COUNT_OF(data), &frame_to_send, 1, &frame_to_received))
        return false;

    if(frame_to_received.buffer[1] != 0x51 || frame_to_received.buffer[2] != type) return false;

    return true;
}

// Get count of DTC
bool uds_get_count_stored_dtc(UDS_SERVICE* uds_instance, uint16_t* count_of_dtc) {
    uint8_t data[3] = {0x19, 0x1, 0xff};

    CANFRAME frame_to_send = {0};
    CANFRAME frame_to_received = {0};

    if(!uds_multi_frame_request(
           uds_instance, data, COUNT_OF(data), &frame_to_send, 1, &frame_to_received))
        return false;

    if(frame_to_received.buffer[0] != 6 || frame_to_received.buffer[1] != 0x59 || frame_to_received.buffer[2] != 1) return false;

    *count_of_dtc = (uint16_t)frame_to_received.buffer[5] << 8 | frame_to_received.buffer[6];

    return true;
}

// Show the real DTC
void get_data_trouble_code(char* text, uint8_t* data) {
    // Preserve the complete 24-bit UDS DTC instead of discarding its third byte.
    snprintf(text, 7, "%02X%02X%02X", data[0], data[1], data[2]);
}

// Get the DTC
bool uds_get_stored_dtc(UDS_SERVICE* uds, char* codes[], uint16_t* count) {
    if(!uds || !codes || !count || !*count || *count > 20) return false;
    uint16_t capacity = *count;
    uint8_t request[] = {0x19, 0x02, 0xFF};
    uint8_t response[3 + 20 * 4];
    size_t len = 0;
    if(uds_request_payload(uds, request, sizeof(request), response, sizeof(response), &len) != UdsOk ||
       len < 3 || (len - 3) % 4 != 0) return false;
    size_t available = (len - 3) / 4;
    if(available > capacity) return false;
    for(size_t i = 0; i < available; i++) {
        if(!codes[i]) return false;
        get_data_trouble_code(codes[i], response + 3 + i * 4);
    }
    *count = available;
    return true;
}

// Delete DTC Storaged
bool uds_delete_dtc(UDS_SERVICE* uds_instance) {
    uint8_t data[4] = {0x14, 0xff, 0xff, 0xff};

    CANFRAME frame_to_send = {0};
    CANFRAME frame_to_received = {0};

    if(!uds_multi_frame_request(
           uds_instance, data, COUNT_OF(data), &frame_to_send, 1, &frame_to_received)) {
        return false;
    }

    if(frame_to_received.buffer[0] != 1 || frame_to_received.buffer[1] != 0x54) return false;

    return true;
}

bool uds_tester_present(UDS_SERVICE* uds_instance) {
    uint8_t data[2] = {0x3E, 0x00};

    CANFRAME frames_to_send[2] = {0};
    CANFRAME frame_to_received = {0};

    if(!uds_multi_frame_request(
           uds_instance, data, COUNT_OF(data), frames_to_send, 1, &frame_to_received)) {
        return false;
    }

    if(frame_to_received.buffer[1] != 0x7E) return false;

    return true;
}

bool uds_security_request_seed(
    UDS_SERVICE* uds_instance,
    uint8_t level,
    CANFRAME* response) {
    uint8_t data[2] = {0x27, level};

    CANFRAME frames_to_send[2] = {0};

    if(!uds_multi_frame_request(
           uds_instance, data, COUNT_OF(data), frames_to_send, 1, response)) {
        return false;
    }

    return true;
}

bool uds_read_did(
    UDS_SERVICE* uds_instance,
    uint16_t did,
    CANFRAME* frames,
    uint8_t count_of_frames) {
    uint8_t data[3] = {0x22, (uint8_t)(did >> 8), (uint8_t)(did & 0xFF)};

    CANFRAME frames_to_send[2] = {0};

    if(!uds_multi_frame_request(
           uds_instance, data, COUNT_OF(data), frames_to_send, count_of_frames, frames)) {
        return false;
    }

    return true;
}

bool uds_security_send_key(
    UDS_SERVICE* uds_instance,
    uint8_t level,
    uint8_t* key,
    uint8_t key_len,
    CANFRAME* response) {
    uint8_t data[7];
    data[0] = 0x27;
    data[1] = level;

    uint8_t copy_len = key_len;
    if(copy_len > UDS_MAX_SEED_KEY_LEN) copy_len = UDS_MAX_SEED_KEY_LEN;

    for(uint8_t i = 0; i < copy_len; i++) {
        data[2 + i] = key[i];
    }

    CANFRAME frames_to_send[2] = {0};

    if(!uds_multi_frame_request(
           uds_instance, data, 2 + copy_len, frames_to_send, 1, response)) {
        return false;
    }

    return true;
}
