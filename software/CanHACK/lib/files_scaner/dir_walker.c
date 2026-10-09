#include "files_scaner.h"

#define TAG "DIRECTORY WALKER"

#define NAME_BUFFER_SIZE (64U)

uint64_t storage_dir_get_files_count(Storage* storage, const char* path) {
    if(!storage || !path) return 0;

    File* file = storage_file_alloc(storage);
    if(!file) return 0;

    FileInfo fileinfo;
    char name_buffer[NAME_BUFFER_SIZE];

    uint64_t files_count = 0;

    if(storage_dir_open(file, path)) {
        while(storage_dir_read(file, &fileinfo, name_buffer, sizeof(name_buffer))) {
            if(!file_info_is_dir(&fileinfo)) {
                files_count++;
            }
        }
    } else {
        FURI_LOG_E(TAG, "Failed to open directory");
    }

    storage_file_free(file);

    return files_count;
}

bool storage_dir_read_index(
    Storage* storage,
    const char* path,
    FuriString* file_path,
    uint64_t index) {
    if(!storage || !path || !file_path) return false;
    furi_string_reset(file_path);
    File* file = storage_file_alloc(storage);
    if(!file) return false;

    FileInfo fileinfo;
    char name_buffer[NAME_BUFFER_SIZE];

    uint64_t files_count = 0;

    FuriString* dir_path = furi_string_alloc_set(path);
    if(!dir_path) {
        storage_file_free(file);
        return false;
    }
    furi_string_push_back(dir_path, '/');

    if(storage_dir_open(file, path)) {
        while(storage_dir_read(file, &fileinfo, name_buffer, sizeof(name_buffer))) {
            if(!file_info_is_dir(&fileinfo)) {
                files_count++;
                if(files_count - 1 == index) {
                    furi_string_cat(dir_path, name_buffer);
                    furi_string_move(file_path, dir_path);
                    break;
                }
            }
        }
    } else {
        FURI_LOG_E(TAG, "Failed to open directory");
    }

    storage_file_free(file);
    furi_string_free(dir_path);

    return furi_string_size(file_path) != 0;
}
