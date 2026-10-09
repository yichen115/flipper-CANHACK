#include "uds_transport.h"
#include <string.h>

#define UDS_TRANSACTION_LIMIT_MS 15000U
#define UDS_RX_BLOCK_SIZE 8U
#define UDS_RX_STMIN_MS 2U

const char* uds_status_name(UdsStatus status) {
    switch(status) {
    case UdsOk: return "OK";
    case UdsNegative: return "Negative response";
    case UdsTimeout: return "Timeout";
    case UdsCancelled: return "Cancelled";
    case UdsSendError: return "CAN TX failed";
    case UdsProtocolError: return "ISO-TP error";
    case UdsOverflow: return "Response too large";
    default: return "Unknown error";
    }
}

bool uds_response_matches(const uint8_t* request, size_t request_len, const uint8_t* response, size_t response_len) {
    if(!request_len || !response_len) return false;
    if(response[0] == 0x7F) return response_len == 3 && response[1] == request[0];
    if(response[0] != (uint8_t)(request[0] + 0x40)) return false;
    // A SID-only capability probe cannot validate an absent DID/subfunction.
    if(request_len == 1) return true;
    if(request[0] == 0x22) {
        return request_len >= 3 && response_len >= 3 &&
               request[1] == response[1] && request[2] == response[2];
    }
    switch(request[0]) {
    case 0x10:
    case 0x11:
    case 0x19:
    case 0x27:
    case 0x3E:
        return request_len >= 2 && response_len >= 2 &&
               (request[1] & 0x7F) == response[1];
    default: return true;
    }
}

static bool cancelled(UdsTransport* t) {
    return t->cancelled && t->cancelled(t->context);
}

static bool transmit(UdsTransport* t, const uint8_t* data, size_t len) {
    UdsCanFrame frame = {.id = t->request_id, .len = 8, .extended = t->request_id > 0x7FF};
    memset(frame.data, 0xCC, sizeof(frame.data));
    memcpy(frame.data, data, len);
    return t->send(t->context, &frame);
}

static UdsStatus receive(UdsTransport* t, UdsCanFrame* frame, uint32_t start, uint32_t timeout, uint32_t transaction_start) {
    for(;;) {
        if(cancelled(t)) return UdsCancelled;
        uint32_t now = t->now_ms(t->context);
        if(now - start >= timeout || now - transaction_start >= UDS_TRANSACTION_LIMIT_MS) return UdsTimeout;
        if(t->receive(t->context, frame)) {
            if(frame->id == t->response_id && frame->extended == (t->response_id > 0x7FF) &&
               !frame->remote && frame->len > 0 && frame->len <= 8) return UdsOk;
        } else {
            t->idle(t->context, 100);
        }
    }
}

static UdsStatus send_flow_control(UdsTransport* t, uint8_t status) {
    uint8_t fc[] = {status, UDS_RX_BLOCK_SIZE, UDS_RX_STMIN_MS};
    return transmit(t, fc, sizeof(fc)) ? UdsOk : UdsSendError;
}

static UdsStatus wait_separation(UdsTransport* t, uint32_t us, uint32_t transaction_start) {
    while(us) {
        if(cancelled(t)) return UdsCancelled;
        if(t->now_ms(t->context) - transaction_start >= UDS_TRANSACTION_LIMIT_MS) return UdsTimeout;
        uint32_t step = us > 1000 ? 1000 : us;
        t->idle(t->context, step);
        us -= step;
    }
    return UdsOk;
}

static UdsStatus send_request(UdsTransport* t, const uint8_t* request, size_t len, uint32_t transaction_start) {
    uint8_t data[8];
    if(len <= 7) {
        data[0] = (uint8_t)len;
        memcpy(data + 1, request, len);
        return transmit(t, data, len + 1) ? UdsOk : UdsSendError;
    }
    data[0] = 0x10 | (uint8_t)(len >> 8);
    data[1] = (uint8_t)len;
    memcpy(data + 2, request, 6);
    if(!transmit(t, data, sizeof(data))) return UdsSendError;
    size_t sent = 6;
    uint8_t sequence = 1;
    while(sent < len) {
        UdsCanFrame fc;
        uint32_t start = t->now_ms(t->context);
        UdsStatus status;
        for(;;) {
            status = receive(t, &fc, start, t->frame_timeout_ms, transaction_start);
            if(status != UdsOk) return status;
            if((fc.data[0] & 0xF0) != 0x30) continue;
            if(fc.len < 3) return UdsProtocolError;
            if(fc.data[0] == 0x31) continue; // WAIT, bounded by the same deadline.
            if(fc.data[0] == 0x32) return UdsOverflow;
            if(fc.data[0] != 0x30) return UdsProtocolError;
            break;
        }
        uint8_t separation = fc.data[2];
        uint32_t us;
        if(separation <= 0x7F) us = separation * 1000U;
        else if(separation >= 0xF1 && separation <= 0xF9) us = (separation - 0xF0) * 100U;
        else return UdsProtocolError;
        uint16_t block = fc.data[1] ? fc.data[1] : 256;
        while(block-- && sent < len) {
            status = wait_separation(t, us, transaction_start);
            if(status != UdsOk) return status;
            data[0] = 0x20 | (sequence++ & 0x0F);
            size_t count = len - sent > 7 ? 7 : len - sent;
            memcpy(data + 1, request + sent, count);
            if(!transmit(t, data, count + 1)) return UdsSendError;
            sent += count;
        }
    }
    return UdsOk;
}

UdsStatus uds_transport_request(
    UdsTransport* t,
    const uint8_t* request,
    size_t request_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len) {
    if(response_len) *response_len = 0;
    if(!t || !t->send || !t->receive || !t->now_ms || !t->idle ||
       !request || !request_len || request_len > UDS_PAYLOAD_MAX ||
       !response || !response_capacity || !response_len) return UdsProtocolError;
    *response_len = 0;
    if(cancelled(t)) return UdsCancelled;
    // Drain stale responses with a fixed bound, even on a busy CAN network.
    UdsCanFrame frame;
    for(uint8_t i = 0; i < 32 && t->receive(t->context, &frame); i++) {
        if(cancelled(t)) return UdsCancelled;
    }
    uint32_t transaction_start = t->now_ms(t->context);
    UdsStatus status = send_request(t, request, request_len, transaction_start);
    if(status != UdsOk) return status;
    uint32_t start = t->now_ms(t->context);
    uint32_t timeout = t->p2_ms;
    for(;;) {
        status = receive(t, &frame, start, timeout, transaction_start);
        if(status != UdsOk) return status;
        uint8_t pci = frame.data[0] >> 4;
        size_t len;
        if(pci == 0) {
            len = frame.data[0] & 0x0F;
            if(!len || len > 7 || frame.len < len + 1) return UdsProtocolError;
            if(!uds_response_matches(request, request_len, frame.data + 1, len)) continue;
            if(len == 3 && frame.data[1] == 0x7F && frame.data[3] == 0x78) {
                start = t->now_ms(t->context);
                timeout = t->p2_star_ms;
                continue;
            }
            if(len > response_capacity) return UdsOverflow;
            memcpy(response, frame.data + 1, len);
        } else if(pci == 1) {
            if(frame.len != 8) return UdsProtocolError;
            len = ((size_t)(frame.data[0] & 0x0F) << 8) | frame.data[1];
            if(len <= 7) return UdsProtocolError;
            if(!uds_response_matches(request, request_len, frame.data + 2, 6)) continue;
            if(len > response_capacity || len > UDS_PAYLOAD_MAX) {
                status = send_flow_control(t, 0x32);
                return status == UdsOk ? UdsOverflow : status;
            }
            memcpy(response, frame.data + 2, 6);
            status = send_flow_control(t, 0x30);
            if(status != UdsOk) return status;
            size_t copied = 6;
            uint8_t sequence = 1;
            uint8_t block = 0;
            while(copied < len) {
                status = receive(t, &frame, t->now_ms(t->context), t->frame_timeout_ms, transaction_start);
                if(status != UdsOk) return status;
                if(frame.data[0] != (0x20 | (sequence++ & 0x0F))) return UdsProtocolError;
                size_t count = len - copied > 7 ? 7 : len - copied;
                if(frame.len < count + 1) return UdsProtocolError;
                memcpy(response + copied, frame.data + 1, count);
                copied += count;
                if(++block == UDS_RX_BLOCK_SIZE && copied < len) {
                    status = send_flow_control(t, 0x30);
                    if(status != UdsOk) return status;
                    block = 0;
                }
            }
        } else {
            continue; // Ignore stale flow control / consecutive frames.
        }
        *response_len = len;
        return response[0] == 0x7F ? UdsNegative : UdsOk;
    }
}
