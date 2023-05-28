#include <FreeRTOS.h>
#include <timers.h>

#include <lwip/inet.h>
#include "homekit_mdns.h"

#ifndef MDNS_TTL
#define MDNS_TTL 4500
#endif

#ifndef HOMEKIT_MDNS_NETWORK_CHECK_PERIOD
#define HOMEKIT_MDNS_NETWORK_CHECK_PERIOD 2000
#endif


static mdns_server_t *mdns_server = NULL;
static TimerHandle_t netmon_timer = NULL;


static void homekit_check_network(TimerHandle_t timer) {
    static bool network_down = true;

    if (sdk_wifi_station_get_connect_status() == STATION_GOT_IP) {
        if (network_down) {
            struct ip_info ip;
            if (sdk_wifi_get_ip_info(STATION_IF, &ip)) {
                printf("Got IP, resuming mDNS\n");
                mdns_server_set_addr4(mdns_server, *((struct in_addr*)(&ip.ip)));
                mdns_server_resume(mdns_server);
                mdns_announce(mdns_server);
                network_down = false;
            }
        }
    } else {
        if (!network_down) {
            printf("No IP, pausing mDNS\n");
            network_down = true;
            mdns_server_pause(mdns_server);
        }
    }
}

void homekit_mdns_init() {
    if (mdns_server)
        return;

    mdns_server = mdns_server_new();
    if (!mdns_server) {
        printf("Failed to allocate memory for mDNS server\n");
        return;
    }

    mdns_server_start(mdns_server);

    netmon_timer = xTimerCreate(
        "HomeKit netmon", pdMS_TO_TICKS(HOMEKIT_MDNS_NETWORK_CHECK_PERIOD),
        true, NULL, homekit_check_network
    );
    if (!netmon_timer) {
        printf("Failed to create network monitor timer\n");
        return;
    }
    xTimerStart(netmon_timer, 1);
}

void homekit_mdns_configure_init(const char *instance_name, int port) {
    mdns_server_pause(mdns_server);
    mdns_server_set_name(mdns_server, instance_name);
    mdns_server_set_port(mdns_server, port);
    mdns_server_set_ttl(mdns_server, MDNS_TTL);
    mdns_server_clear_txt(mdns_server);
}

void homekit_mdns_add_txt(const char *key, const char *format, ...) {
    char buffer[128];

    int r;
    int buffer_len = 0;

    r = snprintf(buffer, sizeof(buffer), "%s=", key);
    if (r < 0) {
        printf("Failed to add mDNS TXT record %s: code %d\n", key, r);
        return;
    }

    buffer_len += r;
    if (buffer_len >= sizeof(buffer)) {
        printf("Failed to add mDNS TXT record %s: key is too large\n", key);
        return;
    }

    va_list arg_ptr;
    va_start(arg_ptr, format);

    r = vsnprintf(&buffer[buffer_len], sizeof(buffer) - buffer_len, format, arg_ptr);

    va_end(arg_ptr);

    if (r < 0) {
        printf("Failed to add mDNS TXT record %s: code %d\n", key, r);
        return;
    }

    buffer_len += r;

    if (buffer_len >= sizeof(buffer)-1) {
        printf("Failed to add mDNS TXT record %s: value is too large\n", key);
        return;
    }

    printf("HomeKit: adding mDNS TXT record %s\n", buffer);
    mdns_server_add_txt(mdns_server, buffer);
}

void homekit_mdns_configure_finalize() {
    mdns_server_resume(mdns_server);
    mdns_announce(mdns_server);
    /*
    printf("mDNS announcement: Name=%s %s Port=%d TTL=%d\n",
           mdns_instance_name, mdns_txt_rec, mdns_port, MDNS_TTL);
    */
}

