#include "../app_user.h"

UDS_SERVICE* app_uds_open(App* app) {
    UDS_SERVICE* uds = uds_service_alloc(
        app->uds_send_id, app->uds_received_id, MCP_NORMAL,
        app->mcp_can->clck, app->mcp_can->bitRate);
    if(!uds) return NULL;
    if(!uds_init(uds)) {
        free_uds(uds);
        return NULL;
    }
    uds->timeout_ms = app->uds_timeout_ms;
    uds->session = app->uds_session_type;
    uds->last_keepalive_ms = furi_get_tick();
    // Menus can remain open longer than the ECU's S3 session timeout.
    if(uds->session > 1) {
        uint8_t request[] = {0x10, uds->session};
        uint8_t response[8];
        size_t len = 0;
        if(uds_request_payload(uds, request, sizeof(request), response, sizeof(response), &len) != UdsOk) {
            app->uds_session_type = 1;
            free_uds(uds);
            return NULL;
        }
    }
    return uds;
}

void app_uds_stop_worker(App* app) {
    if(!app->thread) return;
    FuriThreadId id = furi_thread_get_id(app->thread);
    if(id) furi_thread_flags_set(id, UDS_WORKER_STOP);
    furi_thread_join(app->thread);
    furi_thread_free(app->thread);
    app->thread = NULL;
}

bool app_uds_delay(UDS_SERVICE* uds, uint32_t ms) {
    uint32_t start = furi_get_tick();
    do {
        if(uds_worker_cancelled()) return false;
        uds_keepalive(uds);
        uint32_t elapsed = furi_get_tick() - start;
        if(elapsed >= ms) return true;
        furi_delay_ms(ms - elapsed > 5 ? 5 : ms - elapsed);
    } while(true);
}
