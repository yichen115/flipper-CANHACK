#include "uds_library.h"
#include <string.h>

bool uds_worker_cancelled(void) {
    return (furi_thread_flags_get() & UDS_WORKER_STOP) != 0;
}

static bool adapter_cancelled(void* context) {
    UNUSED(context);
    return uds_worker_cancelled();
}

static uint32_t adapter_now(void* context) {
    UNUSED(context);
    return furi_get_tick();
}

static void adapter_idle(void* context, uint32_t us) {
    UNUSED(context);
    if(us >= 1000) furi_delay_ms(us / 1000);
    else furi_delay_us(us);
}

static bool adapter_send(void* context, const UdsCanFrame* frame) {
    UDS_SERVICE* uds = context;
    CANFRAME out = {0};
    out.canId = frame->id;
    out.ext = frame->extended;
    out.data_length = frame->len;
    memcpy(out.buffer, frame->data, frame->len);
    return send_can_frame(uds->CAN, &out) == ERROR_OK;
}

static bool adapter_receive(void* context, UdsCanFrame* frame) {
    UDS_SERVICE* uds = context;
    CANFRAME in = {0};
    if(read_can_message(uds->CAN, &in) != ERROR_OK) return false;
    frame->id = in.canId;
    frame->extended = in.ext;
    frame->remote = in.req;
    frame->len = in.data_length;
    memcpy(frame->data, in.buffer, sizeof(frame->data));
    return true;
}

UdsStatus uds_request_payload(
    UDS_SERVICE* uds,
    const uint8_t* request,
    size_t request_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    if(response_len) *response_len = 0;
    if(!uds || !uds->initialized) return UdsSendError;
    UdsTransport transport = {
        .context = uds,
        .send = adapter_send,
        .receive = adapter_receive,
        .now_ms = adapter_now,
        .idle = adapter_idle,
        .cancelled = adapter_cancelled,
        .request_id = uds->id_to_send,
        .response_id = uds->id_to_received,
        .p2_ms = uds->timeout_ms ? uds->timeout_ms : 50,
        .p2_star_ms = uds->pending_timeout_ms ? uds->pending_timeout_ms : 5000,
        .frame_timeout_ms = 1000,
    };
    UdsStatus status = uds_transport_request(
        &transport, request, request_len, response, response_capacity, response_len);
    if(status == UdsOk && request_len == 2 && request[0] == 0x10 && *response_len >= 2) {
        uds->session = response[1];
        uds->last_keepalive_ms = furi_get_tick();
        if(*response_len >= 6) {
            uint32_t p2 = ((uint32_t)response[2] << 8) | response[3];
            uint32_t p2_star = (((uint32_t)response[4] << 8) | response[5]) * 10;
            if(p2) uds->timeout_ms = p2 > 5000 ? 5000 : p2;
            if(p2_star) uds->pending_timeout_ms = p2_star > 10000 ? 10000 : p2_star;
        }
    }
    return status;
}

void uds_keepalive(UDS_SERVICE* uds) {
    if(!uds || uds->session <= 1 || furi_get_tick() - uds->last_keepalive_ms < 2000) return;
    CANFRAME frame = {.canId = uds->id_to_send, .ext = uds->id_to_send > 0x7FF, .data_length = 8};
    memset(frame.buffer, 0xCC, sizeof(frame.buffer));
    frame.buffer[0] = 2;
    frame.buffer[1] = 0x3E;
    frame.buffer[2] = 0x80;
    send_can_frame(uds->CAN, &frame);
    uds->last_keepalive_ms = furi_get_tick();
}

bool uds_session_response_matches(const CANFRAME* frame, uint8_t session) {
    if(frame->req || frame->data_length < 4) return false;
    size_t len = frame->buffer[0];
    if(len < 2 || len > 7 || len + 1 > frame->data_length) return false;
    uint8_t request[] = {0x10, session};
    return uds_response_matches(request, sizeof(request), frame->buffer + 1, len);
}

bool uds_discovery_probe(MCP2515* can, uint32_t request_id, uint32_t wait_ms, CANFRAME* response) {
    for(uint8_t i = 0; i < 32 && read_can_message(can, response) == ERROR_OK; i++) {
        if(uds_worker_cancelled()) return false;
    }
    CANFRAME request = {.canId = request_id, .data_length = 8};
    memset(request.buffer, 0xCC, sizeof(request.buffer));
    request.buffer[0] = 2;
    request.buffer[1] = 0x10;
    request.buffer[2] = 1;
    if(uds_worker_cancelled() || send_can_frame(can, &request) != ERROR_OK) return false;
    uint32_t start = furi_get_tick();
    while(furi_get_tick() - start < wait_ms) {
        if(uds_worker_cancelled()) return false;
        if(read_can_message(can, response) == ERROR_OK) {
            if(!response->ext && uds_session_response_matches(response, 1)) return true;
        } else {
            furi_delay_us(100);
        }
    }
    return false;
}

bool uds_discovery_verify(MCP2515* can, uint32_t request_id, uint32_t response_id, uint32_t wait_ms) {
    UDS_SERVICE uds = {
        .CAN = can, .initialized = true, .id_to_send = request_id,
        .id_to_received = response_id, .timeout_ms = wait_ms < 50 ? 50 : wait_ms,
    };
    uint8_t request[] = {0x10, 1};
    uint8_t response[8];
    size_t len = 0;
    UdsStatus status = uds_request_payload(&uds, request, sizeof(request), response, sizeof(response), &len);
    return status == UdsOk || status == UdsNegative;
}
