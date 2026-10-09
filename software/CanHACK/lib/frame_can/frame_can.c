#include "frame_can.h"

FrameCAN* frame_can_alloc(void) {
    FrameCAN* frame = malloc(sizeof(FrameCAN));

    if(!frame) return NULL;

    frame->timestamp = (uint32_t*)calloc(1, sizeof(uint32_t));
    frame->extended = (bool*)calloc(1, sizeof(bool));
    frame->dir = furi_string_alloc();
    frame->can_id = furi_string_alloc();
    frame->len = (char*)calloc(1, sizeof(char));
    frame->dlc = furi_string_alloc();

    if(!frame->timestamp || !frame->extended || !frame->dir || !frame->can_id || !frame->len ||
       !frame->dlc) {
        frame_can_free(frame);
        return NULL;
    }

    return frame;
}

void frame_can_free(FrameCAN* frame) {
    if(!frame) return;
    free(frame->timestamp);
    free(frame->extended);
    if(frame->dir) furi_string_free(frame->dir);
    if(frame->can_id) furi_string_free(frame->can_id);
    free(frame->len);
    if(frame->dlc) furi_string_free(frame->dlc);

    free(frame);
}
