#include <stdint.h>
#include <stdio.h>

#include "homekit_mdns_private.h"


const char *mdns_rr_type_name(uint16_t rr_type) {
    static char buffer[32];
    switch(rr_type) {
    case DNS_RRTYPE_A: return "A";
    case DNS_RRTYPE_AAAA: return "AAAA";
    case DNS_RRTYPE_PTR: return "PTR";
    case DNS_RRTYPE_SRV: return "SRV";
    case DNS_RRTYPE_TXT: return "TXT";
    case DNS_RRTYPE_ANY: return "ANY";
    default:
        snprintf(buffer, sizeof(buffer), "Unknown(%d)", rr_type);
        return buffer;
    }
}


const char *mdns_rr_class_name(uint16_t rr_class) {
    static char buffer[32];
    switch(rr_class) {
    case DNS_RRCLASS_IN: return "In";
    case DNS_RRCLASS_ANY: return "ANY";
    default:
        snprintf(buffer, sizeof(buffer), "Unknown(%d)", rr_class);
        return buffer;
    }
}


void mdns_print_hex(uint8_t *data, uint16_t len) {
    for (uint16_t i=0; i<len; i++) {
        if (data[i] >= 32) {
            printf("%02X(%c) ", data[i], data[i]);
        } else {
            printf("%02X    ", data[i]);
        }
        if (i % 16 == 7)
            printf("  ");
        else if (i % 16 == 15)
            printf("\n");
    }
    printf("\n");
}


void mdns_print_pstr(uint8_t *data, uint16_t size) {
    int i = 0;
    while (i < size) {
        int n = *data++;

        if (n > (size - i))
            n = size - i;
        for (int j=0; j < n; j++) {
            printf("%c", *data++);
        }
        printf(" ");
        i += n + 1;
    }
}


uint8_t *mdns_print_name(uint8_t *data, uint8_t *payload) {
    while (1) {
        int n = *data++;
        if (n == 0)
            break;

        if ((n & 0xC0) == 0xC0) {
            n = ((n & 0x3F) << 8) + *data++;
            // recurse here so you do not loose were original name ends (value of "data")
            mdns_print_name(payload + n, payload);
            break;
        } else {
            for (int j=0; j < n; j++) {
                printf("%c", *data++);
            }
            printf(".");
        }
    }

    return data;
}


uint8_t *mdns_print_question(uint8_t *data, uint8_t *payload) {
    data = mdns_print_name(data, payload);

    uint16_t query_type = mdns_read_u16(data);
    uint16_t query_class = mdns_read_u16(data+2);
    data += 4;

    printf(" TYPE=%s CLASS=%s %s",
           mdns_rr_type_name(query_type), mdns_rr_class_name(query_class & 0x3F),
           query_class & 0x8000 ? "unicast" : "");

    printf("\n");
    return data;
}


uint8_t *mdns_print_answer(uint8_t *data, uint8_t *payload) {
    data = mdns_print_name(data, payload);

    uint16_t answer_type  = mdns_read_u16(data + 0);
    uint16_t answer_class = mdns_read_u16(data + 2);
    uint32_t answer_ttl   = mdns_read_u32(data + 4);
    uint16_t answer_len   = mdns_read_u16(data + 8);
    data += 10;

    printf(" TYPE=%s CLASS=%s %s",
           mdns_rr_type_name(answer_type), mdns_rr_class_name(answer_class & 0x3F),
           answer_class & 0x8000 ? "cache-flush " : "");

    if (answer_type == DNS_RRTYPE_A && answer_len == 4) {
        printf("%d.%d.%d.%d", data[0], data[1], data[2], data[3]);
    } else if (answer_type == DNS_RRTYPE_AAAA && answer_len == 16) {
        printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
               data[0], data[1], data[ 2], data[ 3], data[ 4], data[ 5], data[ 6], data[ 7],
               data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
    } else if (answer_type == DNS_RRTYPE_PTR) {
        mdns_print_name(data, payload);
    } else if (answer_type == DNS_RRTYPE_TXT) {
        mdns_print_pstr(data, answer_len);
    } else if (answer_type == DNS_RRTYPE_SRV) {
        uint16_t srv_priority = mdns_read_u16(data);
        uint16_t srv_weight = mdns_read_u16(data+2);
        uint16_t srv_port = mdns_read_u16(data+4);
        printf("priority=%d weight=%d port=%d ", srv_priority, srv_weight, srv_port);
        mdns_print_name(data+6, payload);
    } else {
        mdns_print_hex(data, answer_len);
    }

    printf("\n");

    data += answer_len;
    return data;
}


void mdns_print_packet(uint8_t *data, uint16_t size) {
    uint8_t *p = data;

    uint16_t packet_id = mdns_read_u16(p);
    uint8_t packet_flags1 = p[2];
    uint8_t packet_flags2 = p[3];
    uint16_t packet_numquestions = mdns_read_u16(p+4);
    uint16_t packet_numanswers = mdns_read_u16(p+6);
    uint16_t packet_numauthrr = mdns_read_u16(p+8);
    uint16_t packet_numextrarr = mdns_read_u16(p+10);

    printf("mDNS %s ID=%d flags1=%d flags2=%d %s ",
           packet_flags1 & MDNS_FLAGS1_RESPONSE ? "RESPONSE" : "QUERY",
           packet_id, packet_flags1, packet_flags2,
           packet_flags1 & MDNS_FLAGS1_AUTH ? "auth" : "non-auth");

    if (packet_numquestions > 0)
        printf("questions=%d ", packet_numquestions);
    if (packet_numanswers > 0)
        printf("answers=%d ", packet_numanswers);
    if (packet_numauthrr > 0)
        printf("authrr=%d ", packet_numauthrr);
    if (packet_numextrarr > 0)
        printf("extrarr=%d ", packet_numextrarr);
    printf("\n");

    p += MDNS_HEADER_SIZE;

    int i;
    for (i=0; i < packet_numquestions; i++) {
        printf("  Question: ");
        p = mdns_print_question(p, data);
    }

    for (i=0; i < packet_numanswers; i++) {
        printf("  Answer: ");
        p = mdns_print_answer(p, data);
    }

    for (i=0; i < packet_numauthrr; i++) {
        printf("  AuthRR: ");
        p = mdns_print_answer(p, data);
    }

    for (i=0; i < packet_numextrarr; i++) {
        printf("  ExtraRR: ");
        p = mdns_print_answer(p, data);
    }
}


