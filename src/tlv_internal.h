#pragma once

#include <stdint.h>


typedef void (*tlv_flush_callback)(uint8_t *buffer, size_t size, void *context);


typedef struct {
    uint8_t *buffer;
    size_t size;
    size_t pos;

    tlv_flush_callback on_flush;
    void *context;
} tlv_stream_t;


int tlv_stream_init(tlv_stream_t *tlv, byte *buffer, size_t size, tlv_flush_callback on_flush, void *context);
tlv_stream_t *tlv_stream_new(size_t size, tlv_flush_callback on_flush, void *context);
void tlv_stream_free(tlv_stream_t *tlv);
void tlv_stream_set_context(tlv_stream_t *tlv, void *context);

void tlv_stream_flush(tlv_stream_t *tlv);
void tlv_stream_reset(tlv_stream_t *tlv);

int tlv_stream_add_value(tlv_stream_t *tlv, byte type, const byte *data, size_t size);
int tlv_stream_add_string_value(tlv_stream_t *tlv, byte type, const char *value);
int tlv_stream_add_integer_value(tlv_stream_t *tlv, byte type, size_t size, int value);
int tlv_stream_add_tlv_value(tlv_stream_t *tlv, byte type, tlv_values_t *value);
