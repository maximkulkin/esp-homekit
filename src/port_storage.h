#pragma once

#include <stddef.h>

int homekit_storage_init();
int homekit_storage_reset();
int homekit_storage_size();
int homekit_storage_read(size_t offset, void *dst, size_t size);
int homekit_storage_write(size_t offset, void *src, size_t size);
