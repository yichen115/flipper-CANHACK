#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UDS_PAYLOAD_MAX 512U
#define UDS_WORKER_STOP (1U << 1)

typedef struct {
    uint32_t id;
    uint8_t data[8];
    uint8_t len;
    bool extended;
    bool remote;
} UdsCanFrame;

typedef enum {
    UdsOk,
    UdsNegative,
    UdsTimeout,
    UdsCancelled,
    UdsSendError,
    UdsProtocolError,
    UdsOverflow,
} UdsStatus;

typedef struct {
    void* context;
    bool (*send)(void* context, const UdsCanFrame* frame);
    bool (*receive)(void* context, UdsCanFrame* frame);
    uint32_t (*now_ms)(void* context);
    void (*idle)(void* context, uint32_t us);
    bool (*cancelled)(void* context);
    uint32_t request_id;
    uint32_t response_id;
    uint32_t p2_ms;
    uint32_t p2_star_ms;
    uint32_t frame_timeout_ms;
} UdsTransport;

bool uds_response_matches(const uint8_t* request, size_t request_len, const uint8_t* response, size_t response_len);
UdsStatus uds_transport_request(
    UdsTransport* transport,
    const uint8_t* request,
    size_t request_len,
    uint8_t* response,
    size_t response_capacity,
    size_t* response_len);
const char* uds_status_name(UdsStatus status);
