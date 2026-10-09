#include "files_scaner.h"

FileActive* file_active_alloc(void) {
    FileActive* file_active = malloc(sizeof(FileActive));
    if(!file_active) return NULL;

    file_active->path = furi_string_alloc();
    if(!file_active->path) {
        free(file_active);
        return NULL;
    }

    return file_active;
}

void file_active_free(FileActive* file_active) {
    if(!file_active) return;
    furi_string_free(file_active->path);

    free(file_active);
}
