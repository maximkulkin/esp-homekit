
#ifdef ESP_OPEN_RTOS

#include <esp/hwrand.h>
uint32_t homekit_random() {
    return hwrand();
}

void homekit_random_fill(uint8_t *data, size_t size) {
    hwrand_fill(data, size);
}

#endif

#ifdef ESP_IDF

#include <string.h>
#include <esp_system.h>
uint32_t homekit_random() {
    return esp_random();
}

void homekit_random_fill(uint8_t *data, size_t size) {
    uint32_t x;
    for (int i=0; i<size; i+=sizeof(x)) {
        x = esp_random();
        memcpy(data+i, &x, (size-i >= sizeof(x)) ? sizeof(x) : size-i);
    }
}

#endif
