#pragma once


#define MDNS_HEADER_SIZE    12
#define MDNS_QUERY_SIZE     4
#define MDNS_ANSWER_SIZE    10

#define MDNS_FLAGS1_RESPONSE 0x80
#define MDNS_FLAGS1_AUTH     0x04
#define MDNS_FLAGS1_TRUNCATE 0x02
#define MDNS_FLAGS1_RD       0x01


#define DNS_RRTYPE_A        1
#define DNS_RRTYPE_AAAA     28
#define DNS_RRTYPE_PTR      12
#define DNS_RRTYPE_SRV      33
#define DNS_RRTYPE_TXT      16
#define DNS_RRTYPE_ANY      255


#define DNS_RRCLASS_IN      1
#define DNS_RRCLASS_ANY     255

#define DNS_CACHE_FLUSH_RRCLASS_FLAG 0x8000


#define DNS_UNICAST_RESPONSE_FLAG   0x8000


#define QUESTIONED_A       0x01
#define QUESTIONED_AAAA    0x01
#define QUESTIONED_PTR     0x02
#define QUESTIONED_SRV     0x04
#define QUESTIONED_TXT     0x08


static inline uint16_t mdns_read_u16(const uint8_t *data) {
    return (((uint16_t)data[0]) << 8) | data[1];
}


static inline uint32_t mdns_read_u32(const uint8_t *data) {
    return (((((((uint32_t)data[0]) << 8) | data[1]) << 8) | data[2]) << 8) | data[3];
}


