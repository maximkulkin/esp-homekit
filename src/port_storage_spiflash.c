#include <string.h>
#include "port_storage.h"
#include "debug.h"

#ifdef ESP_OPEN_RTOS
#include <spiflash.h>
#define ESP_OK 0
#endif

#ifdef ESP_IDF
#include <esp_system.h>
#include <esp_spi_flash.h>
#define SPI_FLASH_SECTOR_SIZE SPI_FLASH_SEC_SIZE
#define spiflash_read(addr, buffer, size) (spi_flash_read((addr), (buffer), (size)) == ESP_OK)
#define spiflash_write(addr, data, size) (spi_flash_write((addr), (data), (size)) == ESP_OK)
#define spiflash_erase_sector(addr) (spi_flash_erase_sector((addr) / SPI_FLASH_SECTOR_SIZE) == ESP_OK)
#endif

#ifndef SPIFLASH_BASE_ADDR
#define SPIFLASH_BASE_ADDR 0x200000
#endif

static const char storage_magic[] = "HAP";

int homekit_storage_size() {
    return SPI_FLASH_SECTOR_SIZE;
}

int homekit_storage_init() {
    char magic[sizeof(storage_magic)];
    memset(magic, 0, sizeof(magic));

    if (homekit_storage_read(0, (byte *)magic, sizeof(magic))) {
        ERROR("Failed to read HomeKit storage magic");
    }

    if (strncmp(magic, storage_magic, sizeof(storage_magic))) {
        INFO("Formatting HomeKit storage at 0x%x", SPIFLASH_BASE_ADDR);
        if (!spiflash_erase_sector(SPIFLASH_BASE_ADDR)) {
            ERROR("Failed to erase HomeKit storage");
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
    return spiflash_read(SPIFLASH_BASE_ADDR + offset, dst, size) ? 0 : -1;
}

int homekit_storage_write(size_t offset, void *src, size_t size) {
    return spiflash_write(SPIFLASH_BASE_ADDR + offset, src, size) ? 0 : -1;
}
