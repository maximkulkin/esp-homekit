#pragma once

#include <stdint.h>

uint32_t homekit_random();
void homekit_random_fill(uint8_t *data, size_t size);
