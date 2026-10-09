#include "frame_queue.h"

FrameCANQueueNode* frame_can_queue_node_alloc() {
    return malloc(sizeof(FrameCANQueueNode));
}

void frame_can_queue_node_free(FrameCANQueueNode* node) {
    free(node);
}

FrameCANQueue* frame_can_queue_alloc() {
    FrameCANQueue* frame_queue = malloc(sizeof(FrameCANQueue));

    if(!frame_queue) return NULL;

    frame_queue->head = NULL;
    frame_queue->tail = NULL;

    return frame_queue;
}

void frame_can_queue_free(FrameCANQueue* frame_queue) {
    if(!frame_queue) return;
    FrameCANQueueNode* node = frame_queue->head;
    while(node != NULL) {
        FrameCANQueueNode* next = node->next_node;
        free(node);
        node = next;
    }
    free(frame_queue);
}

void frame_can_queue_push(FrameCANQueue* queue, CANFRAME frame) {
    if(!queue) return;
    FrameCANQueueNode* new_node = frame_can_queue_node_alloc();
    if(!new_node) return;
    new_node->frame = frame;

    new_node->next_node = NULL;
    if(queue->tail) {
        queue->tail->next_node = new_node;
    } else {
        queue->head = new_node;
    }
    queue->tail = new_node;
}

void frame_can_queue_pop(FrameCANQueue* queue) {
    if(!queue) return;
    FrameCANQueueNode* node = queue->head;
    if(!node) return;

    queue->head = node->next_node;
    if(!queue->head) queue->tail = NULL;
    frame_can_queue_node_free(node);
}

CANFRAME* frame_can_queue_get(FrameCANQueue* queue) {
    if(!queue || queue->head == NULL) return NULL;
    return &queue->head->frame;
}
