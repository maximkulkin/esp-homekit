#pragma once

#ifdef ESP_OPEN_RTOS
#include <lwip/inet.h>
#endif
#ifdef HOST_BUILD
#include <net/inet.h>
#endif

typedef struct _mdns_server mdns_server_t;

void mdns_server_set_addr4(mdns_server_t *server, struct in_addr addr);
void mdns_server_set_addr6(mdns_server_t *server, struct in6_addr addr);
void mdns_server_set_port(mdns_server_t *server, uint16_t port);
void mdns_server_set_ttl(mdns_server_t *server, uint32_t ttl);
void mdns_server_set_name(mdns_server_t *server, const char *name);

void mdns_server_set_txt(mdns_server_t *server, const char *txt);
void mdns_server_clear_txt(mdns_server_t *server);
void mdns_server_add_txt(mdns_server_t *server, const char *txt);

mdns_server_t *mdns_server_new();
void mdns_server_free(mdns_server_t *server);

int mdns_server_start(mdns_server_t *server);
int mdns_server_stop(mdns_server_t *server);
void mdns_server_pause(mdns_server_t *server);
void mdns_server_resume(mdns_server_t *server);

void mdns_announce(mdns_server_t *server);
