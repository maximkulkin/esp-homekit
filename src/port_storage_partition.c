
#include <string.h>
#include <esp_partition.h>
#include "port_storage.h"
#include "debug.h"

static const char storage_magic[] = "HAP";
static esp_partition_t *data_partition = NULL;

int homekit_storage_size() {
    if (!data_partition) {
        return 0;
    }
    return data_partition->size;
}

int homekit_storage_init() {
    char magic[sizeof(storage_magic)];
    memset(magic, 0, sizeof(magic));

    data_partition = (esp_partition_t*)esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_HOMEKIT, "homekit");
    if (!data_partition) {
         ERROR("HomeKit partition is not found");
         return -1;
    }

    if (homekit_storage_read(0, (byte *)magic, sizeof(magic))) {
        ERROR("Failed to read HomeKit storage magic");
    }

    if (strncmp(magic, storage_magic, sizeof(storage_magic))) {
        INFO("Formatting HomeKit partition %s", data_partition->label);
        esp_err_t error = esp_partition_erase_range(data_partition, 0, data_partition->erase_size);
        if (error != ESP_OK) {
            ERROR("Failed to erase HomeKit storage: %s (0x%x)", esp_err_to_name(error), error);
             return -1;
        }


        strncpy(magic, storage_magic, sizeof(magic));
        if (homekit_storage_write(0, (byte *)magic, sizeof(magic))) {
            ERROR("Failed to write HomeKit storage magic");
            return -1;
        }

        return 1;
    }

    return 0;
}

int homekit_storage_reset() {
    byte blank[sizeof(storage_magic)];
    memset(blank, 0, sizeof(blank));

    if (homekit_storage_write(0, blank, sizeof(blank))) {
        ERROR("Failed to reset HomeKit storage");
        return -1;
    }

    return homekit_storage_init();
}

int homekit_storage_read(size_t offset, void *dst, size_t size) {
    esp_err_t error = esp_partition_read(data_partition, offset, dst, size);
    if (error != ESP_OK) {
        DEBUG("Flash read failed: %s (0x%x)", esp_err_to_name(error), error);
        return -1;
    }

    return 0;
}

int homekit_storage_write(size_t offset, void *src, size_t size) {
    esp_err_t error = esp_partition_write(data_partition, offset, src, size);
    if (error != ESP_OK) {
        DEBUG("Flash write failed: %s (0x%x)", esp_err_to_name(error), error);
        return -1;
    }

    return 0;
}
