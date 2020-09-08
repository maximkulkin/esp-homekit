#pragma once

#include <stdbool.h>
#include <stdint.h>

#define JSON_MAX_DEPTH 30

typedef enum {
    JSON_STATE_START = 1,
    JSON_STATE_END,
    JSON_STATE_OBJECT,
    JSON_STATE_OBJECT_KEY,
    JSON_STATE_OBJECT_VALUE,
    JSON_STATE_ARRAY,
    JSON_STATE_ARRAY_ITEM,
    JSON_STATE_ERROR,
} json_state;

typedef enum {
    JSON_NESTING_OBJECT,
    JSON_NESTING_ARRAY,
} json_nesting;

typedef void (*json_flush_callback)(uint8_t *buffer, size_t size, void *context);

typedef struct json_stream {
    uint8_t *buffer;
    size_t size;
    size_t pos;

    json_state state;

    uint8_t nesting_idx;
    json_nesting nesting[JSON_MAX_DEPTH];

    json_flush_callback on_flush;
    void *context;
} json_stream;


void json_init(json_stream *json, uint8_t *buffer, size_t size, json_flush_callback on_flush, void *context);

json_stream *json_new(size_t size, json_flush_callback on_flush, void *context);
void json_free(json_stream *json);

void json_set_context(json_stream *json, void *context);

void json_reset(json_stream *json);
void json_flush(json_stream *json);

void json_object_start(json_stream *json);
void json_object_end(json_stream *json);

void json_array_start(json_stream *json);
void json_array_end(json_stream *json);

void json_integer(json_stream *json, int x);
void json_uint8(json_stream *json, uint8_t x);
void json_uint16(json_stream *json, uint16_t x);
void json_uint32(json_stream *json, uint32_t x);
void json_uint64(json_stream *json, uint64_t x);
void json_float(json_stream *json, float x);
void json_string(json_stream *json, const char *x);
void json_boolean(json_stream *json, bool x);
void json_null(json_stream *json);

