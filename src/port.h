#pragma once

#include <stdint.h>
#include "port_storage.h"

uint32_t homekit_random();
void homekit_random_fill(uint8_t *data, size_t size);

void homekit_system_restart();
void homekit_overclock_start();
void homekit_overclock_end();


#ifdef ESP_IDF
#define SERVER_TASK_STACK 12288
#else
#define SERVER_TASK_STACK 1664
#endif


void homekit_mdns_init();
void homekit_mdns_configure_init(const char *instance_name, int port);
void homekit_mdns_add_txt(const char *key, const char *format, ...);
void homekit_mdns_configure_finalize();
