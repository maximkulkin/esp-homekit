#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ESP_OPEN_RTOS
#include <lwip/sockets.h>
#endif

#ifdef HOST_BUILD
#error "host"
#include <netinet/ip.h>
#define PP_HTONS(x) htons(x)
#define PP_HTONL(x) htonl(x)
// TODO:
#define IPADDR4_INIT_BYTES(a, b, c, d)
#endif

#define MDNS_ENABLE_IP4 1
#define MDNS_ENABLE_IP6 0

#include <unistd.h>

#include <FreeRTOS.h>
#include <queue.h>
#include <timers.h>

#include "homekit_mdns_private.h"
#include "homekit_mdns.h"
#include "homekit_mdns_debug.h"


#define LOG(message, ...) printf(message, ##__VA_ARGS__);

#define LOG_ERROR(message, ...) LOG("mDNS: " message "\n", ##__VA_ARGS__);
#define LOG_ERROR_(message, ...) LOG("mDNS: " message, ##__VA_ARGS__);
#define LOG_INFO(message, ...) LOG("mDNS: " message "\n", ##__VA_ARGS__);
#define LOG_INFO_(message, ...) LOG("mDNS: " message, ##__VA_ARGS__);

#ifdef HOMEKIT_MDNS_DEBUG
#define LOG_DEBUG(message, ...) LOG("mDNS: " message "\n", ##__VA_ARGS__);
#define LOG_DEBUG_(message, ...) LOG("mDNS: " message, ##__VA_ARGS__);
#else
#define LOG_DEBUG(message, ...)
#define LOG_DEBUG_(message, ...)
#endif


#define MDNS_BUFFER_SIZE 2000

#define MIN(a, b) ((b) < (a) ? (b) : (a))
#define MAX(a, b) ((a) < (b) ? (b) : (a))


long long get_millis() {
    struct timeval te;
    gettimeofday(&te, NULL);
    return te.tv_sec * 1000LL + te.tv_usec / 1000;
}


uint32_t random_integer() {
    return (uint32_t)rand();
}


static struct sockaddr_in DNS_MULTICAST_ADDR = {
    .sin_family = AF_INET,
    .sin_port = PP_HTONS(5353),
    .sin_addr = IPADDR4_INIT_BYTES(224, 0, 0, 251),
};


static inline uint8_t *mdns_write_u16(uint8_t *buffer, uint16_t value) {
    buffer[0] = value >> 8;
    buffer[1] = value & 0xFF;
    return buffer + 2;
}


static inline uint8_t *mdns_write_u32(uint8_t *buffer, uint32_t value) {
    buffer[0] = (value >> 24) & 0xFF;
    buffer[1] = (value >> 16) & 0xFF;
    buffer[2] = (value >>  8) & 0xFF;
    buffer[3] =  value        & 0xFF;
    return buffer + 4;
}


typedef enum {
    mdns_state_tentative = 0,
    mdns_state_normal,
    mdns_state_waiting_ip,
    mdns_state_paused,
    mdns_state_probe_delay,
    mdns_state_probe1,
    mdns_state_probe2,
    mdns_state_probe3,
    mdns_state_announcement1,
    mdns_state_announcement2,
    mdns_state_announcement3,
    mdns_state_announcement4,
} mdns_state_t;


typedef enum {
    mdns_command_set_addr4,
    mdns_command_set_addr6,
    mdns_command_set_port,
    mdns_command_set_ttl,
    mdns_command_set_name,
    mdns_command_set_txt,
    mdns_command_clear_txt,
    mdns_command_add_txt,

    mdns_command_probe,
    mdns_command_announce,
    mdns_command_timer,
    mdns_command_pause,
    mdns_command_resume,
    mdns_command_stop,
} mdns_command_type_t;


char *mdns_command_name(mdns_command_type_t type) {
    switch (type) {
        case mdns_command_set_addr4: return "set addr4";
        case mdns_command_set_addr6: return "set addr6";
        case mdns_command_set_port: return "set port";
        case mdns_command_set_ttl: return "set ttl";
        case mdns_command_set_name: return "set name";
        case mdns_command_set_txt: return "set txt";
        case mdns_command_clear_txt: return "clear txt";
        case mdns_command_add_txt: return "add txt";
        case mdns_command_probe: return "probe";
        case mdns_command_announce: return "announce";
        case mdns_command_timer: return "timer";
        case mdns_command_pause: return "pause";
        case mdns_command_resume: return "resume";
        case mdns_command_stop: return "stop";
    }

    static char buffer[16];
    snprintf(buffer, sizeof(buffer), "unknown(%d)", (int)type);

    return buffer;
}


typedef struct {
    mdns_command_type_t type;
    union {
        struct in_addr addr4;       // for mdns_command_set_addr4
        struct in6_addr addr6;      // for mdns_command_set_addr6
        uint16_t port;              // for mdns_command_set_port
        uint32_t ttl;               // for mdns_command_set_ttl
        char *name;                 // for mdns_command_set_name
        char *txt;                  // for mdns_command_set_txt
        uint8_t timer_token;
    };
} mdns_command_t;


struct _mdns_server {
    int fd;
    #if MDNS_ENABLE_IP4
    struct in_addr addr4;
    #endif
    #if MDNS_ENABLE_IP6
    struct in6_addr addr6;
    #endif
    bool has_addr4 : 1;
    bool has_addr6 : 1;
    mdns_state_t state : 6;

    uint8_t *buffer;
    uint16_t buffer_size;
    uint16_t buffer_len;

    QueueHandle_t queue;

    TimerHandle_t timer;
    uint8_t timer_token;

    uint8_t probe_count;

    uint8_t questioned;

    // service data
    uint16_t service_port;
    uint32_t service_ttl;
    char name[64];
    char txt[128];
    uint8_t name_len;       // full name of service
    uint8_t base_name_len;  // length of base name, without conflict resolution suffix
    uint8_t txt_len;
};


struct mreq {
    struct in_addr multiaddr;
    struct in_addr interface;
};


static void mdns_send_command(mdns_server_t *server, mdns_command_t command) {
    if (xQueueSend(server->queue, &command, portMAX_DELAY) != pdTRUE) {
        LOG_ERROR("Failed to send mDNS command")
    }
}


static void mdns_send_command_isr(mdns_server_t *server, mdns_command_t command) {
    if (xQueueSendFromISR(server->queue, &command, NULL) != pdTRUE) {
        LOG_ERROR("Failed to send mDNS command")
    }
}


#if MDNS_ENABLE_IP4
void mdns_server_set_addr4(mdns_server_t *server, struct in_addr addr) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_set_addr4,
        .addr4=addr,
    });
}
#endif

#if MDNS_ENABLE_IP6
void mdns_server_set_addr6(mdns_server_t *server, struct in6_addr addr) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_set_addr6,
        .addr6=addr,
    });
}
#endif

void mdns_server_set_port(mdns_server_t *server, uint16_t port) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_set_port,
        .port=port,
    });
}

void mdns_server_set_ttl(mdns_server_t *server, uint32_t ttl) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_set_ttl,
        .ttl=ttl,
    });
}

void mdns_server_set_name(mdns_server_t *server, const char *name) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_set_name,
        .name=strdup(name),
    });
}

void mdns_server_set_txt(mdns_server_t *server, const char *txt) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_set_txt,
        .txt=strdup(txt),
    });
}


void mdns_server_clear_txt(mdns_server_t *server) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_clear_txt,
    });
}


void mdns_server_add_txt(mdns_server_t *server, const char *txt) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_add_txt,
        .txt=strdup(txt),
    });
}


void mdns_server_pause(mdns_server_t *server) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_pause,
    });
}


void mdns_server_resume(mdns_server_t *server) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_resume,
    });
}


static uint8_t *mdns_write_label(uint8_t *buffer, const char *name, uint8_t len) {
    *buffer = len;
    if (len > 0)
        memcpy(buffer + 1, name, len);
    return buffer + 1 + len;
}


static inline uint8_t *mdns_write_label_reference(uint8_t *buffer, uint16_t offset) {
    buffer[0] = 0xC0 | (offset >> 8);
    buffer[1] = offset & 0xFF;
    return buffer + 2;
}


static uint8_t *mdns_write_query(uint8_t *buffer, uint16_t rrtype, uint16_t rrclass) {
    mdns_write_u16(buffer, rrtype);
    mdns_write_u16(buffer + 2, rrclass);
    return buffer + 4;
}


static uint8_t *mdns_write_answer(uint8_t *buffer, uint16_t rrtype, uint16_t rrclass, uint32_t ttl, uint16_t len) {
    mdns_write_u16(buffer, rrtype);
    mdns_write_u16(buffer + 2, rrclass);
    mdns_write_u32(buffer + 4, ttl);
    mdns_write_u16(buffer + 8, len);

    return buffer + 10;
}


typedef enum {
    NAME_LOCAL = 1,
    NAME_HAP,
    NAME_SRV,
    NAME_HOST,
    NAME_MAX
} name_t;


static int mdns_match_label(uint8_t *data, uint16_t size, uint16_t offset, const char *name, uint8_t len) {
    while (offset + 1 < size && (data[offset] & 0xC0) == 0xC0) {
        offset = ((data[offset] & 0x3F) << 8) + data[offset+1];
        if (offset >= size)
            return -1;
    }

    if (offset + 1 + len > size)
        return -1;

    if (data[offset] != len)
        return -1;

    if (len && memcmp(data + 1 + offset, name, len))
        return -1;

    return offset + 1 + len;
}


static int mdns_match_name(mdns_server_t *server, uint8_t *data, uint16_t size, uint16_t offset, name_t name_id) {
    int x = offset;
    switch (name_id) {
    case NAME_LOCAL:
        x = mdns_match_label(data, size, x, "local", 5);
        if (x > 0) x = mdns_match_label(data, size, x, NULL, 0);
        break;
    case NAME_HAP:
        x = mdns_match_label(data, size, x, "_hap", 4);
        if (x > 0) x = mdns_match_label(data, size, x, "_tcp", 4);
        if (x > 0) x = mdns_match_name(server, data, size, x, NAME_LOCAL);
        break;
    case NAME_SRV:
        x = mdns_match_label(data, size, x, server->name, server->name_len);
        if (x > 0) x = mdns_match_name(server, data, size, x, NAME_HAP);
        break;
    case NAME_HOST:
        x = mdns_match_label(data, size, x, server->name, server->name_len);
        if (x > 0) x = mdns_match_name(server, data, size, x, NAME_LOCAL);
        break;
    case NAME_MAX:
        x = 0;
    }
    return x;
}


static int mdns_skip_name(uint8_t *data, uint16_t size, uint16_t offset) {
    while (offset < size && data[offset] && !(data[offset] & 0xC0)) {
        offset += 1 + data[offset];
    }

    if (offset >= size)
        return -1;

    if ((data[offset] & 0xC0) == 0xC0)
        return offset + 2;

    return offset + 1;
}


static uint8_t *mdns_write_name(mdns_server_t *server, uint8_t *p, name_t name_id, uint16_t *refs) {
    if (refs[name_id]) {
        return mdns_write_label_reference(p, refs[name_id]);
    }

    refs[name_id] = p - server->buffer;

    switch (name_id) {
        case NAME_LOCAL:
            p = mdns_write_label(p, "local", 5);
            return mdns_write_label(p, NULL, 0);
        case NAME_HAP:
            p = mdns_write_label(p, "_hap", 4);
            p = mdns_write_label(p, "_tcp", 4);
            return mdns_write_name(server, p, NAME_LOCAL, refs);
        case NAME_SRV:
            p = mdns_write_label(p, server->name, server->name_len);
            return mdns_write_name(server, p, NAME_HAP, refs);
        case NAME_HOST:
            p = mdns_write_label(p, server->name, server->name_len);
            return mdns_write_name(server, p, NAME_LOCAL, refs);
        case NAME_MAX:
            return mdns_write_label(p, NULL, 0);
    }

    return p;
}


static uint8_t *mdns_add_A_answer(mdns_server_t *server, uint8_t *p, uint16_t *refs) {
    #if MDNS_ENABLE_IP4
    p = mdns_write_name(server, p, NAME_HOST, refs);
    p = mdns_write_answer(p, DNS_RRTYPE_A, DNS_RRCLASS_IN | DNS_CACHE_FLUSH_RRCLASS_FLAG,
                          server->service_ttl, 4);
    p = mdns_write_u32(p, htonl(server->addr4.s_addr));
    #endif
    return p;
}


static uint8_t *mdns_add_AAAA_answer(mdns_server_t *server, uint8_t *p, uint16_t *refs) {
    #if MDNS_ENABLE_IP6
    p = mdns_write_name(server, p, NAME_HOST, refs);
    p = mdns_write_answer(p, DNS_RRTYPE_AAAA, DNS_RRCLASS_IN | DNS_CACHE_FLUSH_RRCLASS_FLAG,
                          server->service_ttl, 16);

    uint8_t *a = (uint8_t*) &server->addr6;
    for (int i=0; i < 16; i++)
        (*p++) = (*a++);
    #endif

    return p;
}


static uint8_t *mdns_add_PTR_answer(mdns_server_t *server, uint8_t *p, uint16_t *refs) {
    uint8_t *pp = mdns_write_name(server, p, NAME_HAP, refs);

    p = pp + MDNS_ANSWER_SIZE;
    p = mdns_write_name(server, p, NAME_SRV, refs);

    mdns_write_answer(pp, DNS_RRTYPE_PTR, DNS_RRCLASS_IN,
                      server->service_ttl, p - pp - MDNS_ANSWER_SIZE);

    return p;
}


static uint8_t *mdns_add_SRV_answer(mdns_server_t *server, uint8_t *p, uint16_t *refs) {
    uint8_t *pp = mdns_write_name(server, p, NAME_SRV, refs);

    p = pp + MDNS_ANSWER_SIZE;

    // Assume buffer is already zeroed-out
    // mdns_write_u16(p + 0, 0); // SRV priority
    // mdns_write_u16(p + 2, 0); // SRV weight
    mdns_write_u16(p + 4, server->service_port); // SRV port
    p += 6;

    p = mdns_write_name(server, p, NAME_HOST, refs);

    mdns_write_answer(pp, DNS_RRTYPE_SRV, DNS_RRCLASS_IN | DNS_CACHE_FLUSH_RRCLASS_FLAG,
                      server->service_ttl, p - pp - MDNS_ANSWER_SIZE);

    return p;
}


static uint8_t *mdns_add_TXT_answer(mdns_server_t *server, uint8_t *p, uint16_t *refs) {
    uint8_t *pp = mdns_write_name(server, p, NAME_SRV, refs);

    p = pp + MDNS_ANSWER_SIZE;
    memcpy(p, server->txt, server->txt_len);
    p += server->txt_len;

    mdns_write_answer(pp, DNS_RRTYPE_TXT, DNS_RRCLASS_IN | DNS_CACHE_FLUSH_RRCLASS_FLAG,
                      server->service_ttl, p - pp - MDNS_ANSWER_SIZE);

    return p;
}


static void mdns_build_reply(mdns_server_t *server, uint8_t questions) {
    memset(server->buffer, 0, server->buffer_size);

    uint16_t refs[NAME_MAX+1];
    memset(refs, 0, sizeof(refs));

    uint8_t *hdr = server->buffer;
    hdr[2] = MDNS_FLAGS1_RESPONSE | MDNS_FLAGS1_AUTH;

    uint8_t *p = hdr + MDNS_HEADER_SIZE;

    // answers
    if (questions & QUESTIONED_PTR) {
        p = mdns_add_PTR_answer(server, p, refs);
        hdr[7]++;  // numanswers
    }
    if (questions & QUESTIONED_SRV) {
        p = mdns_add_SRV_answer(server, p, refs);
        hdr[7]++;  // numanswers
    }
    if (questions & QUESTIONED_TXT) {
        p = mdns_add_TXT_answer(server, p, refs);
        hdr[7]++;  // numanswers
    }
    if (questions & QUESTIONED_A && server->has_addr4) {
        p = mdns_add_A_answer(server, p, refs);
        hdr[7]++;  // numanswers
    }
    if (questions & QUESTIONED_AAAA && server->has_addr6) {
        p = mdns_add_AAAA_answer(server, p, refs);
        hdr[7]++;  // numanswers
    }

    if (questions & QUESTIONED_PTR) {
        // extra RR
        if (!(questions & QUESTIONED_PTR)) {
            p = mdns_add_PTR_answer(server, p, refs);
            hdr[11]++;  // numextrarr
        }
        if (!(questions & QUESTIONED_SRV)) {
            p = mdns_add_SRV_answer(server, p, refs);
            hdr[11]++;  // numextrarr
        }
        if (!(questions & QUESTIONED_TXT)) {
            p = mdns_add_TXT_answer(server, p, refs);
            hdr[11]++;  // numextrarr
        }
        if (!(questions & QUESTIONED_A) && server->has_addr4) {
            p = mdns_add_A_answer(server, p, refs);
            hdr[11]++;  // numextrarr
        }
        if (!(questions & QUESTIONED_AAAA) && server->has_addr6) {
            p = mdns_add_AAAA_answer(server, p, refs);
            hdr[11]++;  // numextrarr
        }
    }

    server->buffer_len = p - server->buffer;
}


static void mdns_build_announcement(mdns_server_t *server) {
    mdns_build_reply(
        server, 
        QUESTIONED_A | QUESTIONED_AAAA | QUESTIONED_PTR | QUESTIONED_SRV | QUESTIONED_TXT
    );
}


static void mdns_build_probe(mdns_server_t *server) {
    memset(server->buffer, 0, server->buffer_size);

    uint16_t refs[NAME_MAX+1];
    memset(refs, 0, sizeof(refs));

    uint8_t *p = server->buffer;
    p[5] = 2;  // 2 questions
    p[9] = 1 + (server->has_addr4 ? 1 : 0) + (server->has_addr6 ? 1 : 0);  // 2-3 authrr
    p += MDNS_HEADER_SIZE;

    // A query
    p = mdns_write_name(server, p, NAME_HOST, refs);
    // TODO: pick RR type based on has_addr4 and has_addr6
    p = mdns_write_query(p, DNS_RRTYPE_ANY, DNS_RRCLASS_IN | DNS_UNICAST_RESPONSE_FLAG);

    // SRV query
    p = mdns_write_name(server, p, NAME_SRV, refs);
    p = mdns_write_query(p, DNS_RRTYPE_SRV, DNS_RRCLASS_IN | DNS_UNICAST_RESPONSE_FLAG);

    if (server->has_addr4) {
        p = mdns_add_A_answer(server, p, refs);
    }
    if (server->has_addr6) {
        p = mdns_add_AAAA_answer(server, p, refs);
    }
    p = mdns_add_SRV_answer(server, p, refs);

    server->buffer_len = p - server->buffer;
}


static void mdns_randomize_name(mdns_server_t *server) {
    uint8_t len = MIN(server->base_name_len, sizeof(server->name)-6-1);
    snprintf(server->name + len, 7, "%02X%02X%02X",
             random_integer() % 256,
             random_integer() % 256,
             random_integer() % 256);
    server->name_len = len + 6;
}


/*
static void mdns_save_name_suffix(mdns_server_t *server) {
    // TODO:
}


static void mdns_load_name_suffix(mdns_server_t *server) {
    // TODO:
}
*/


static void mdns_probe(mdns_server_t *server) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_probe,
    });
}


void mdns_announce(mdns_server_t *server) {
    mdns_send_command(server, (mdns_command_t){
        .type=mdns_command_announce,
    });
}


static void mdns_timer_callback(TimerHandle_t timer) {
    mdns_server_t *server = (mdns_server_t*) pvTimerGetTimerID(timer);

    LOG_DEBUG("Timer callback");
    mdns_send_command_isr(server, (mdns_command_t){
        .type=mdns_command_timer,
        .timer_token=server->timer_token,
    });
}


int mdns_server_init(mdns_server_t *server) {
    memset(server, 0, sizeof(*server));

    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERROR("Failed to open socket (code %d)", errno);
        return -1;
    }

    #if MDNS_ENABLE_IP4
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = PP_HTONS(5353),
        .sin_addr = IPADDR4_INIT_BYTES(0, 0, 0, 0),
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind socket (code %d)", errno);
        close(fd);
        return -1;
    }
    #endif

    int r;

    // const struct timeval rcvtimeout = { 0, 100000 }; /* 100ms timeout */
    const struct timeval rcvtimeout = { 1, 0 }; /* 1s timeout */
    r = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcvtimeout, sizeof(rcvtimeout));
    if (r < 0) {
        LOG_ERROR("Failed to set socket options (code %d)", errno);
        close(fd);
        return -1;
    }

    /*
    int reuse = 1;
    r = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    if (r < 0) {
        LOG_ERROR("Failed to reuse port (code %d)", errno);
        close(fd);
        return -1;
    }
    */

    #if MDNS_ENABLE_IP4
    struct mreq mreq = {
        .multiaddr = IPADDR4_INIT_BYTES(224, 0, 0, 251),
        .interface = IPADDR4_INIT_BYTES(0, 0, 0, 0),
    };
    r = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (r < 0) {
        LOG_ERROR("Failed to join multicast group (code %d)", errno);
        close(fd);
        return -1;
    }
    #endif

    server->fd = fd;
    server->buffer_size = MDNS_BUFFER_SIZE;
    server->buffer = (uint8_t*) malloc(server->buffer_size);
    if (!server->buffer) {
        LOG_ERROR("Failed to allocate receive buffer");
        close(fd);
        return -1;
    }
    server->buffer_len = 0;

    server->timer = xTimerCreate("mDNS timer", pdMS_TO_TICKS(250), false, server, mdns_timer_callback);
    if (!server->timer) {
        LOG_ERROR("Failed to create mDNS probe timer");
        free(server->buffer);
        close(fd);
    }

    server->queue = xQueueCreate(16, sizeof(mdns_command_t));
    if (!server->queue) {
        LOG_ERROR("Failed to create mDNS command queue");
        xTimerDelete(server->timer, portMAX_DELAY);
        free(server->buffer);
        close(fd);
    }

    server->timer_token = 0;
    server->probe_count = 0;
    server->questioned = 0;
    server->state = mdns_state_tentative;

    return 0;
}


void mdns_server_done(mdns_server_t *server) {
    if (server->queue) {
        vQueueDelete(server->queue);
    }
    if (server->timer) {
        xTimerDelete(server->timer, portMAX_DELAY);
    }
    free(server->buffer);
    close(server->fd);
}


static void mdns_server_process_query(mdns_server_t *server, uint8_t *data, uint16_t data_len, struct sockaddr *peer_addr, socklen_t peer_addr_len) {
    // LOG_DEBUG("Processing query");
    // mdns_print_packet(data, data_len);

    // uint16_t packet_id = mdns_read_u16(data + 0);
    // uint8_t packet_flags2 = data[3];
    uint16_t packet_numquestions = mdns_read_u16(data + 4);
    uint16_t packet_numanswers = mdns_read_u16(data + 6);
    uint16_t packet_numauthrr = mdns_read_u16(data + 8);

    uint16_t offset = MDNS_HEADER_SIZE;

    uint8_t questioned_multicast = 0;
    uint8_t questioned_unicast = 0;

    int i, r;
    for (i=0; i < packet_numquestions; i++) {
        r = mdns_skip_name(data, data_len, offset);
        if (r < 0)
            // Some incorrect payload, skip it
            break;

        if (r + MDNS_QUERY_SIZE > data_len)
            // Some incorrect payload, skip it
            break;

        uint16_t question_type = mdns_read_u16(data + r);
        // uint16_t question_class = mdns_read_u16(data + r + 2) & 0x3F;
        bool question_unicast = (data[r + 2] & 0x80) != 0;

        int x;

        if ((x = mdns_match_label(data, data_len, offset, server->name, server->name_len)) > 0) {
            int xx;

            xx = mdns_match_name(server, data, data_len, x, NAME_LOCAL);
            if (xx > 0) {
                if (question_type == DNS_RRTYPE_A || question_type == DNS_RRTYPE_ANY) {
                    if (question_unicast)
                        questioned_unicast |= QUESTIONED_A;
                    else
                        questioned_multicast |= QUESTIONED_A;
                }
            }

            xx = mdns_match_name(server, data, data_len, x, NAME_HAP);
            if (xx > 0) {
                uint8_t q = 0;
                if (question_type == DNS_RRTYPE_ANY) {
                    q |= QUESTIONED_SRV;
                    q |= QUESTIONED_TXT;
                } else if (question_type == DNS_RRTYPE_SRV) {
                    q |= QUESTIONED_SRV;
                } else if (question_type == DNS_RRTYPE_TXT) {
                    q |= QUESTIONED_TXT;
                }

                if (question_unicast)
                    questioned_unicast |= q;
                else
                    questioned_multicast |= q;
            }
        } else if ((x = mdns_match_name(server, data, data_len, offset, NAME_HAP)) > 0) {
            if (question_type == DNS_RRTYPE_PTR || question_type == DNS_RRTYPE_ANY) {
                if (question_unicast)
                    questioned_unicast |= QUESTIONED_PTR;
                else
                    questioned_multicast |= QUESTIONED_PTR;
            }
        }

        offset = r + MDNS_QUERY_SIZE;
    }

    bool name_conflict = false;
    if (questioned_unicast & (QUESTIONED_A | QUESTIONED_AAAA | QUESTIONED_SRV)) {
        for (int i=0; i<packet_numauthrr; i++) {
            r = mdns_skip_name(data, data_len, offset);
            if (r < 0)
                // Some incorrect payload, skip it
                break;

            if (r + MDNS_ANSWER_SIZE > data_len)
                // Some incorrect payload, skip it
                break;

            uint16_t answer_type  = mdns_read_u16(data + r + 0);
            // uint16_t answer_class = mdns_read_u16(data + r + 2);
            // uint32_t answer_ttl   = mdns_read_u32(data + r + 4);
            uint16_t answer_len   = mdns_read_u16(data + r + 8);

            int x;
            if (answer_type == DNS_RRTYPE_A && server->has_addr4) {
                #if MDNS_ENABLE_IP4
                if ((x = mdns_match_name(server, data, data_len, offset, NAME_HOST)) > 0) {
                    uint32_t addr = htonl(server->addr4.s_addr);
                    if (memcmp(&addr, &data[x], sizeof(addr)) < 0) {
                        name_conflict = true;
                        break;
                    }
                }
                #endif
            } else if (answer_type == DNS_RRTYPE_AAAA && server->has_addr6) {
                #if MDNS_ENABLE_IP6
                if ((x = mdns_match_name(server, data, data_len, offset, NAME_HOST)) > 0) {
                    uint8_t *addr = (uint8_t*) &server->addr6;
                    if (memcmp(addr, &data[x], sizeof(server->addr6)) < 0) {
                        name_conflict = true;
                        break;
                    }
                }
                #endif
            /*
            } else if (answer_type == DNS_RRTYPE_SRV) {
                if ((x = mdns_match_name(server, data, data_len, offset, NAME_SRV)) > 0) {
                    uint8_t *p = &data[x];
                    if (p[0] || p[1] || p[2] || p[3] ||
                        (server->service_port >> 8) < p[4] ||
                        (server->service_port && 0xff) < p[5])
                    {
                        name_conflict = true;
                        break;
                    }

                    p += 6;
                }
            */
            }

            offset = r + MDNS_ANSWER_SIZE + answer_len;
        }
    }

    if (name_conflict) {
        LOG_INFO("Got potential name conflict, waiting 1s to retry and confirm");
        server->state = mdns_state_probe_delay;
        xTimerChangePeriod(server->timer, pdMS_TO_TICKS(1000), portMAX_DELAY);
        return;
    }

    // we only care about known PTR record
    if (questioned_multicast & QUESTIONED_PTR) {
        for (i=0; i < packet_numanswers; i++) {
            r = mdns_skip_name(data, data_len, offset);
            if (r < 0)
                // Some incorrect payload, skip it
                break;

            if (r + MDNS_ANSWER_SIZE > data_len)
                // Some incorrect payload, skip it
                break;

            uint16_t answer_type  = mdns_read_u16(data + r + 0);
            // uint16_t answer_class = mdns_read_u16(data + r + 2);
            // uint32_t answer_ttl   = mdns_read_u32(data + r + 4);
            uint16_t answer_len   = mdns_read_u16(data + r + 8);

            offset = r + MDNS_ANSWER_SIZE + answer_len;

            int x;
            if (answer_type == DNS_RRTYPE_PTR) {
                x = mdns_match_name(server, data, data_len, offset, NAME_HAP);
                if (x <= 0)
                    continue;

                x = mdns_match_name(server, data, data_len, r + MDNS_ANSWER_SIZE, NAME_SRV);
                if (x > 0) {
                    questioned_multicast &= ~(QUESTIONED_PTR);
                    break;
                }
            }
        }
    }

    if (questioned_unicast) {
        mdns_build_reply(server, questioned_unicast);

        // mdns_print_packet(server->buffer, server->buffer_len);
        sendto(server->fd, server->buffer, server->buffer_len, 0, peer_addr, peer_addr_len);
    }

    if (questioned_multicast) {
        if (server->state == mdns_state_normal) {
            server->questioned |= questioned_multicast;

            TickType_t ticks = pdMS_TO_TICKS(20 + random_integer() % 100);
            if (xTimerIsTimerActive(server->timer)) {
                TickType_t remaining_ticks = xTimerGetExpiryTime(server->timer) - xTaskGetTickCount();
                ticks = MIN(ticks, remaining_ticks);
            }

            xTimerChangePeriod(server->timer, ticks, portMAX_DELAY);
        }
    }
}


static void mdns_server_process_response(mdns_server_t *server, uint8_t *data, uint16_t data_len, struct sockaddr *peer_addr, socklen_t peer_addr_len) {
    bool name_conflict = false;

    uint16_t numanswers = mdns_read_u16(data+6);
    uint16_t offset = MDNS_HEADER_SIZE;

    int r;
    for (int i=0; i<numanswers; i++) {
        r = mdns_skip_name(data, data_len, offset);
        if (r < 0)
            // Some incorrect payload, skip it
            break;

        if (r + MDNS_ANSWER_SIZE > data_len)
            // Some incorrect payload, skip it
            break;

        uint16_t answer_type  = mdns_read_u16(data + r + 0);
        // uint16_t answer_class = mdns_read_u16(data + r + 2);
        // uint32_t answer_ttl   = mdns_read_u32(data + r + 4);
        uint16_t answer_len   = mdns_read_u16(data + r + 8);

        if (answer_type == DNS_RRTYPE_A || answer_type == DNS_RRTYPE_AAAA) {
            if (mdns_match_name(server, data, data_len, offset, NAME_HOST) > 0) {
                name_conflict = true;
                // mdns_print_packet(data, data_len);
                break;
            }
        } else if (answer_type == DNS_RRTYPE_SRV) {
            if (mdns_match_name(server, data, data_len, offset, NAME_SRV) > 0) {
                name_conflict = true;
                // mdns_print_packet(data, data_len);
                break;
            }
        }

        offset = r + MDNS_ANSWER_SIZE + answer_len;
    }

    if (name_conflict) {
        LOG_INFO("Got name conflict for %s, changing", server->name);
        mdns_randomize_name(server);
        LOG_INFO("Using new name %s", server->name);
        mdns_send_command(server, (mdns_command_t){.type=mdns_command_probe});
    }
}


static void mdns_broadcast(mdns_server_t *server) {
    int r = sendto(server->fd, server->buffer, server->buffer_len, 0,
                   (struct sockaddr *)&DNS_MULTICAST_ADDR, sizeof(DNS_MULTICAST_ADDR));
    if (r == -1) {
        LOG_ERROR("Failed to send broadcast (code %d)", errno);
    }
}

static void mdns_server_process_packet(mdns_server_t *server, uint8_t *data, uint16_t data_len, struct sockaddr *peer_addr, socklen_t peer_addr_len) {
    uint8_t packet_flags1 = data[2];

    if (packet_flags1 & MDNS_FLAGS1_RESPONSE)
        mdns_server_process_response(server, data, data_len, peer_addr, peer_addr_len);
    else
        mdns_server_process_query(server, data, data_len, peer_addr, peer_addr_len);
}


void mdns_server_run(mdns_server_t *server) {
    bool running = true;
    bool paused = true;
    while (running) {
        mdns_command_t command;
        while (xQueueReceive(server->queue, &command, 0)) {
            LOG_DEBUG("Processing command %s", mdns_command_name(command.type));

            switch (command.type) {
                case mdns_command_set_addr4: {
                    #if MDNS_ENABLE_IP4
                    server->addr4 = command.addr4;
                    // TODO: check if addr is all empty?
                    server->has_addr4 = true;
                    if (server->state == mdns_state_waiting_ip) {
                        server->state = mdns_state_tentative;
                        mdns_announce(server);
                    }
                    #endif
                    break;
                }
                case mdns_command_set_addr6: {
                    #if MDNS_ENABLE_IP6
                    server->addr6 = command.addr6;
                    // TODO: check if addr is all empty?
                    server->has_addr6 = true;
                    if (server->state == mdns_state_waiting_ip) {
                        server->state = mdns_state_tentative;
                        mdns_announce(server);
                    }
                    #endif
                    break;
                }
                case mdns_command_set_port: {
                    server->service_port = command.port;
                    break;
                }
                case mdns_command_set_ttl: {
                    server->service_ttl = command.ttl;
                    break;
                }
                case mdns_command_set_name: {
                    strncpy(server->name, command.name, sizeof(server->name));
                    server->name_len = server->base_name_len = strlen(command.name);
                    free(command.name);
                    server->state = mdns_state_tentative;
                    // TODO: mdns_load_name_suffix(server);
                    break;
                }
                case mdns_command_set_txt: {
                    memcpy(server->txt, command.txt, sizeof(server->txt));
                    server->txt_len = strlen(command.txt);
                    free(command.txt);
                    break;
                }
                case mdns_command_clear_txt: {
                    server->txt[0] = 0;
                    server->txt_len = 0;
                    break;
                }
                case mdns_command_add_txt: {
                    uint8_t extra_len = strlen(command.txt);
                    if (!extra_len)
                        break;

                    LOG_DEBUG("add TXT: %s", command.txt);

                    if (server->txt_len + 1 + extra_len >= sizeof(server->txt)) {
                        LOG_ERROR("No room for more TXT records");
                        break;
                    }

                    server->txt[server->txt_len++] = extra_len;
                    memcpy(&server->txt[server->txt_len], command.txt, extra_len);
                    server->txt_len += extra_len;
                    // ???
                    server->txt[server->txt_len] = 0;

                    free(command.txt);
                    break;
                }
                case mdns_command_probe: {
                    if (paused)
                        break;

                    if (!server->has_addr4 && !server->has_addr6) {
                        LOG_INFO("Delaying probe until IP is acquired");
                        server->state = mdns_state_waiting_ip;
                        break;
                    }

                    if (server->probe_count >= 15) {
                        server->state = mdns_state_probe_delay;
                        xTimerChangePeriod(server->timer, pdMS_TO_TICKS(5000), portMAX_DELAY);
                        break;
                    }

                    LOG_INFO("Probing 1 %s", server->name);
                    mdns_build_probe(server);
                    mdns_broadcast(server);

                    server->probe_count++;
                    server->state = mdns_state_probe1;

                    xTimerChangePeriod(server->timer, pdMS_TO_TICKS(250), portMAX_DELAY);
                    server->timer_token++;
                    break;
                }
                case mdns_command_announce: {
                    if (paused)
                        break;

                    if (server->state == mdns_state_tentative) {
                        mdns_probe(server);
                        break;
                    }

                    if (server->state != mdns_state_normal)
                        break;

                    mdns_build_announcement(server);
                    mdns_broadcast(server);

                    server->state = mdns_state_announcement1;
                    server->probe_count = 0;
                    xTimerChangePeriod(server->timer, pdMS_TO_TICKS(1000), portMAX_DELAY);
                    server->timer_token++;
                    break;
                }
                case mdns_command_timer: {
                    if (command.timer_token != server->timer_token) {
                        // outdated timeout event
                        LOG_DEBUG("Skipping outdated timeout notification");
                        break;
                    }

                    if (paused)
                        break;

                    switch (server->state) {
                        case mdns_state_probe_delay:
                        case mdns_state_probe1:
                        case mdns_state_probe2: {
                            if (!server->has_addr4 && !server->has_addr6) {
                                LOG_INFO("Delaying probe until IP is acquired");
                                server->state = mdns_state_waiting_ip;
                                break;
                            }

                            LOG_INFO("Probing %d %s", server->state - mdns_state_probe_delay + 1, server->name);
                            mdns_build_probe(server);
                            mdns_broadcast(server);

                            server->state++;
                            xTimerChangePeriod(server->timer, pdMS_TO_TICKS(250), portMAX_DELAY);
                            server->timer_token++;
                            break;
                        }
                        case mdns_state_probe3: {
                            /*
                            if (server->base_name_len != server->name_len) {
                                mdns_save_name_suffix(server);
                            }
                            */

                            LOG_INFO_("Probe successful, announcing %s TXT ", server->name);
                            mdns_print_pstr((uint8_t*)server->txt, server->txt_len);
                            LOG("\n");

                            mdns_build_announcement(server);
                            mdns_broadcast(server);

                            server->state = mdns_state_announcement1;
                            server->probe_count = 0;
                            xTimerChangePeriod(server->timer, pdMS_TO_TICKS(1000), portMAX_DELAY);
                            server->timer_token++;
                            break;
                        }
                        case mdns_state_announcement1:
                        case mdns_state_announcement2:
                        case mdns_state_announcement3: {
                            LOG_INFO("Announcing %d %s", server->state - mdns_state_announcement1 + 1, server->name);
                            mdns_build_announcement(server);
                            mdns_broadcast(server);

                            server->state++;

                            TickType_t delay = pdMS_TO_TICKS(1000 * (1 << (server->state - mdns_state_announcement1)));
                            xTimerChangePeriod(server->timer, delay, portMAX_DELAY);
                            server->timer_token++;

                            break;
                        }
                        case mdns_state_announcement4: {
                            LOG_INFO("Announcing 4 %s", server->name);
                            mdns_build_announcement(server);
                            mdns_broadcast(server);

                            xTimerStop(server->timer, portMAX_DELAY);
                            server->state = mdns_state_normal;
                            break;
                        }
                        case mdns_state_normal: {
                            if (!server->questioned)
                                break;

                            mdns_build_reply(server, server->questioned);

                            // LOG_DEBUG("Multicasting response");
                            // mdns_print_packet(server->buffer, server->buffer_len);

                            mdns_broadcast(server);

                            server->questioned = 0;

                            break;
                        }
                        case mdns_state_tentative: {
                            break;
                        }
                    }
                    break;
                }
                case mdns_command_pause: {
                    paused = true;
                    xTimerStop(server->timer, portMAX_DELAY);
                    break;
                }
                case mdns_command_resume: {
                    paused = false;
                    server->state = mdns_state_tentative;
                    break;
                }
                case mdns_command_stop: {
                    running = false;
                    break;
                }
            }
        }

        struct sockaddr peer_addr;
        socklen_t peer_addr_len;

        int len = recvfrom(server->fd, server->buffer, server->buffer_size, 0, &peer_addr, &peer_addr_len);
        if (len < 0) {
            if (errno != EAGAIN && errno != EINTR) {
                LOG_ERROR("Failed to receive packet (code %d)", errno);
            }
            continue;
        }
        server->buffer_len = len;

        /*
        if (peer_addr.sa_family == AF_INET) {
            LOG_DEBUG("Processing packet from %s", inet_ntoa(((struct sockaddr_in*)&peer_addr)->sin_addr));
        }
        */
        // ignore our own queries
        #if MDNS_ENABLE_IP4
        if (peer_addr.sa_family == AF_INET &&
            server->has_addr4 &&
            memcmp(&server->addr4, &((struct sockaddr_in*)&peer_addr)->sin_addr, sizeof(server->addr4)) == 0)
        {
            // LOG_DEBUG("Skipping our own mDNS");
            continue;
        }
        #endif
        #if MDNS_ENABLE_IP6
        if (peer_addr.sa_family == AF_INET6 &&
            server->has_addr6 &&
            memcmp(&server->addr6, &((struct sockaddr_in6*)&peer_addr)->sin6_addr, sizeof(server->addr6)) == 0)
        {
            // LOG_DEBUG("Skipping our own mDNS");
            continue;
        }
        #endif

        if (!paused) {
            mdns_server_process_packet(
                server, server->buffer, server->buffer_len,
                (struct sockaddr*)&peer_addr, peer_addr_len
            );
        }
    }
}


#ifndef IP4_ADDR
#define IP4_ADDR(a, b, c, d) \
    (struct in_addr) {((((((((uint32_t)d) << 8) | c) << 8) | b) << 8) | a)}
#endif


void mdns_task(void *arg) {
    // mdns_server_t *server = (mdns_server_t*) arg;
    mdns_server_t server;
    if (mdns_server_init(&server)) {
        return;
    }

    mdns_server_run(&server);
}


mdns_server_t *mdns_server_new() {
    mdns_server_t *server = (mdns_server_t *) malloc(sizeof(mdns_server_t));
    if (!server)
        return NULL;

    mdns_server_init(server);

    return server;
}


void mdns_server_free(mdns_server_t *server) {
    if (!server)
        return;

    mdns_server_done(server);
    free(server);
}


static void mdns_server_task(void *arg) {
    mdns_server_t *server = (mdns_server_t *) arg;
    mdns_server_run(server);
    vTaskDelete(NULL);
}


int mdns_server_start(mdns_server_t *server) {
    if (!server)
        return -1;

    if (xTaskCreate(mdns_server_task, "mDNS server", 512, server, 1, NULL) != pdTRUE)
        return -2;

    return 0;
}


int mdns_server_stop(mdns_server_t *server) {
    if (!server)
        return -1;

    mdns_send_command(server, (mdns_command_t){.type=mdns_command_stop});
    return 0;
}
