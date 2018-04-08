#pragma once

#include <stdint.h>

uint32_t homekit_random();
void homekit_random_fill(uint8_t *data, size_t size);

#ifdef ESP_OPEN_RTOS
#include <spiflash.h>
#define ESP_OK 0
#endif

#ifdef ESP_IDF
#include <esp_spi_flash.h>
#define SPI_FLASH_SECTOR_SIZE SPI_FLASH_SEC_SIZE
#define spiflash_read(addr, buffer, size) (spi_flash_read((addr), (buffer), (size)) == ESP_OK)
#define spiflash_write(addr, data, size) (spi_flash_write((addr), (data), (size)) == ESP_OK)
#define spiflash_erase_sector(addr) (spi_flash_erase_sector((addr) / SPI_FLASH_SECTOR_SIZE) == ESP_OK)
#endif
