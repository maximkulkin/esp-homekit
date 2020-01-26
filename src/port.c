#include <stdarg.h>

#ifdef ESP_OPEN_RTOS

#include <string.h>
#include <esp/hwrand.h>
#include <espressif/esp_common.h>
#include <esplibs/libmain.h>
#include "mdnsresponder.h"

#ifndef MDNS_TTL
#define MDNS_TTL 4500
#endif

uint32_t homekit_random() {
    return hwrand();
}

void homekit_random_fill(uint8_t *data, size_t size) {
    hwrand_fill(data, size);
}

void homekit_system_restart() {
    sdk_system_restart();
}

void homekit_overclock_start() {
    sdk_system_overclock();
}

void homekit_overclock_end() {
    sdk_system_restoreclock();
}

static char mdns_instance_name[65] = {0};
static char mdns_txt_rec[128] = {0};
static int mdns_port = 80;

void homekit_mdns_init() {
    mdns_init();
}

void homekit_mdns_configure_init(const char *instance_name, int port) {
    strncpy(mdns_instance_name, instance_name, sizeof(mdns_instance_name));
    mdns_txt_rec[0] = 0;
    mdns_port = port;
}

void homekit_mdns_add_txt(const char *key, const char *format, ...) {
    va_list arg_ptr;
    va_start(arg_ptr, format);

    char value[128];
    int value_len = vsnprintf(value, sizeof(value), format, arg_ptr);

    va_end(arg_ptr);

    if (value_len && value_len < sizeof(value)-1) {
        char buffer[128];
        int buffer_len = snprintf(buffer, sizeof(buffer), "%s=%s", key, value);

        if (buffer_len < sizeof(buffer)-1)
            mdns_TXT_append(mdns_txt_rec, sizeof(mdns_txt_rec), buffer, buffer_len);
    }
}

void homekit_mdns_configure_finalize() {
    mdns_clear();
    mdns_add_facility(mdns_instance_name, "_hap", mdns_txt_rec, mdns_TCP, mdns_port, MDNS_TTL);

    printf("mDNS announcement: Name=%s %s Port=%d TTL=%d\n",
           mdns_instance_name, mdns_txt_rec, mdns_port, MDNS_TTL);
}

#endif

#ifdef ESP_IDF

#include <string.h>
#include <esp_system.h>
#include <esp_mdns.h>
#include <lwip/def.h>
#include <lwip/inet.h>
#include "tcpip_adapter.h"


static mdnsHandle *_handle = NULL;
static mdnsService *_service = NULL;

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

void homekit_system_restart() {
    esp_restart();
}

void homekit_overclock_start() {
}

void homekit_overclock_end() {
}

void homekit_mdns_init() {
    _handle = NULL;
    _service = NULL;
}

void homekit_mdns_configure_init(const char *instance_name, int port) {
    if(_handle){
        mdns_destroy(_handle);
    }
    _handle = mdns_create((char *)instance_name);
    _service = mdns_create_service("_hap",mdnsProtocolTCP, port);
    tcpip_adapter_ip_info_t local_ip;
#if LWIP_IPV4
    ip_address_t address4 = {0};
    int ret = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &local_ip);
    if ((ESP_OK == ret) && (local_ip.ip.addr != INADDR_ANY)) {
        memcpy(&address4, &local_ip.ip.addr, 4);
    }
#endif
#if LWIP_IPV6
    ip6_address_t address6 = {0};
    struct ip6_addr local_ip6;
    if (!tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &local_ip6)) {
        memcpy(&address6, &local_ip6.addr, 16);
    }
    mdns_update_ip(_handle, address4, address6);
#else
    mdns_update_ip(_handle, address4);
#endif
    mdns_add_service(_handle, _service);
}

void homekit_mdns_add_txt(const char *key, const char *format, ...) {
    va_list arg_ptr;
    va_start(arg_ptr, format);

    char value[128];
    int value_len = vsnprintf(value, sizeof(value), format, arg_ptr);

    va_end(arg_ptr);

    if (value_len && value_len < sizeof(value)-1) {
        mdns_service_add_txt(_service, (char *)key, value);
    }
}

void homekit_mdns_configure_finalize() {
    mdns_start(_handle);
    /*
    printf("mDNS announcement: Name=%s %s Port=%d TTL=%d\n",
           name->value.string_value, txt_rec, PORT, 0);
    */
}

#endif
