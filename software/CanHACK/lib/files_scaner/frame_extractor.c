#include "files_scaner.h"
#include "frame_can.h"

#include <stdlib.h>
#include <string.h>

#define STREAM_BUFFER_SIZE (32U)
#define FRAME_DELIMITER    (char)':'
#define FRAME_MAX_DLC      (8U)

#define TAG "FRAMES EXTRACTOR"

uint64_t stream_get_lines_count(Stream* stream) {
    uint64_t lines_count = 0;

    if(!stream || stream_size(stream) == 0) return 0;

    for(;;) {
        if(stream_seek_to_char(stream, '\n', StreamDirectionForward)) {
            lines_count++;
        } else {
            if(stream_tell(stream) < stream_size(stream) - 1) {
                lines_count++;
            }
            break;
        }
    }

    stream_rewind(stream);

    return lines_count;
}

bool stream_read_line_index(Stream* stream, FuriString* str_result, uint64_t line_index) {
    if(!stream || !str_result) return false;
    furi_string_reset(str_result);

    if(line_index >= stream_get_lines_count(stream)) return false;

    uint8_t buffer[STREAM_BUFFER_SIZE];
    uint64_t current_line = 0;
    bool found = false;
    stream_rewind(stream);

    for(;;) {
        uint16_t bytes_were_read = stream_read(stream, buffer, sizeof(buffer));
        if(bytes_were_read == 0) break;

        for(uint16_t i = 0; i < bytes_were_read; i++) {
            if(buffer[i] == '\r') continue;
            if(buffer[i] == '\n') {
                if(current_line == line_index) {
                    found = true;
                    goto done;
                }
                current_line++;
                continue;
            }
            if(current_line == line_index) furi_string_push_back(str_result, buffer[i]);
        }
    }

    /* A final line does not need to end with a newline. */
    found = current_line == line_index && furi_string_size(str_result) > 0;

done:
    stream_rewind(stream);
    return found;
}

uint16_t count_char(FuriString* frame_line, char target) {
    if(!frame_line) return 0;
    uint16_t count = 0;

    for(uint16_t i = 0; i < furi_string_size(frame_line); i++) {
        if(target == furi_string_get_char(frame_line, i)) count++;
    }

    return count;
}

void frame_splitter(FrameCAN* frame, FuriString* frame_line) {
    if(!frame || !frame_line) return;
    furi_string_reset(frame->dir);
    furi_string_reset(frame->can_id);
    furi_string_reset(frame->dlc);
    *frame->timestamp = 0;
    *frame->extended = false;
    *frame->len = 0;
    furi_string_trim(frame_line);

    uint16_t delimiter_count = count_char(frame_line, FRAME_DELIMITER);

    if(delimiter_count >= 5) {
        uint64_t delimiter_index_dir = furi_string_search_char(frame_line, FRAME_DELIMITER, 0);
        uint64_t delimiter_index_extended =
            furi_string_search_char(frame_line, FRAME_DELIMITER, delimiter_index_dir + 1);
        uint64_t delimiter_index_timestamp =
            furi_string_search_char(frame_line, FRAME_DELIMITER, delimiter_index_extended + 1);
        uint64_t delimiter_index_canid =
            furi_string_search_char(frame_line, FRAME_DELIMITER, delimiter_index_timestamp + 1);
        uint64_t delimiter_index_len =
            furi_string_search_char(frame_line, FRAME_DELIMITER, delimiter_index_canid + 1);

        FuriString* extended_str = furi_string_alloc();
        FuriString* timestamp_str = furi_string_alloc();
        FuriString* len_str = furi_string_alloc();
        if(!extended_str || !timestamp_str || !len_str) {
            furi_string_free(len_str);
            furi_string_free(timestamp_str);
            furi_string_free(extended_str);
            return;
        }

        furi_string_set(timestamp_str, frame_line);
        furi_string_set(extended_str, frame_line);
        furi_string_set(frame->dir, frame_line);
        furi_string_set(frame->can_id, frame_line);
        furi_string_set(len_str, frame_line);
        furi_string_set(frame->dlc, frame_line);

        furi_string_left(frame->dir, delimiter_index_dir);
        furi_string_mid(
            extended_str,
            delimiter_index_dir + 1,
            delimiter_index_extended - delimiter_index_dir - 1);
        furi_string_mid(
            timestamp_str,
            delimiter_index_extended + 1,
            delimiter_index_timestamp - delimiter_index_extended - 1);
        furi_string_mid(
            frame->can_id,
            delimiter_index_timestamp + 1,
            delimiter_index_canid - delimiter_index_timestamp - 1);
        furi_string_mid(
            len_str, delimiter_index_canid + 1, delimiter_index_len - delimiter_index_canid - 1);
        furi_string_mid(
            frame->dlc,
            delimiter_index_len + 1,
            furi_string_size(frame->dlc) - delimiter_index_len - 1);

        /* Capture logs append :Q1 only for remote-request frames.  The CSV
         * exporter has no RTR column yet, so strip the marker from the data
         * field instead of exporting it as a ninth byte. */
        const char* dlc_text = furi_string_get_cstr(frame->dlc);
        const char* request_marker = strchr(dlc_text, ':');
        if(request_marker) {
            furi_string_left(frame->dlc, (size_t)(request_marker - dlc_text));
        }

        char* end = NULL;
        unsigned long extended = strtoul(furi_string_get_cstr(extended_str), &end, 10);
        if(end == furi_string_get_cstr(extended_str) || *end != '\0' || extended > 1) {
            FURI_LOG_E(TAG, "Invalid extended flag");
            goto cleanup;
        }

        unsigned long timestamp = strtoul(furi_string_get_cstr(timestamp_str), &end, 10);
        if(end == furi_string_get_cstr(timestamp_str) || *end != '\0') {
            FURI_LOG_E(TAG, "Invalid timestamp");
            goto cleanup;
        }

        unsigned long length = strtoul(furi_string_get_cstr(len_str), &end, 10);
        if(end == furi_string_get_cstr(len_str) || *end != '\0' || length > FRAME_MAX_DLC) {
            FURI_LOG_E(TAG, "Invalid CAN payload length");
            goto cleanup;
        }

        *frame->extended = (bool)extended;
        *frame->timestamp = (uint32_t)timestamp;
        *frame->len = (char)length;

cleanup:
        furi_string_free(len_str);
        furi_string_free(timestamp_str);
        furi_string_free(extended_str);
    } else if(furi_string_size(frame_line) && furi_string_get_char(frame_line, 0) != '#') {
        FURI_LOG_E(TAG, "Error: can't read frame format");
    }
}

void frame_extractor(Storage* storage, const char* path, FrameCAN* frame, uint64_t index) {
    if(!storage || !path || !frame) return;
    Stream* stream = file_stream_alloc(storage);
    FuriString* line = furi_string_alloc();
    if(!stream || !line) {
        furi_string_free(line);
        stream_free(stream);
        return;
    }

    bool opened = file_stream_open(stream, path, FSAM_READ, FSOM_OPEN_EXISTING);
    if(opened) {
        if(stream_read_line_index(stream, line, index)) {
            frame_splitter(frame, line);
        } else {
            FURI_LOG_E(TAG, "Failed to read line");
        }
    } else {
        FURI_LOG_E(TAG, "Failed to open file");
    }

    furi_string_free(line);
    if(opened) file_stream_close(stream);
    stream_free(stream);
}
