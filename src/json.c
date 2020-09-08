#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json.h"
#include "debug.h"

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define DEBUG_STATE(json) \
    DEBUG("State = %d, last JSON output: %s", \
          json->state, json->buffer + MAX(0, (long int)json->pos - 20));


void json_init(json_stream *json, uint8_t *buffer, size_t size, json_flush_callback on_flush, void *context) {
    json->size = size;
    json->pos = 0;
    json->buffer = buffer;
    json->state = JSON_STATE_START;
    json->nesting_idx = 0;
    json->on_flush = on_flush;
    json->context = context;
}

json_stream *json_new(size_t size, json_flush_callback on_flush, void *context) {
    json_stream *json = malloc(sizeof(json_stream) + size);
    if (!json) {
        return NULL;
    }

    json_init(json, ((uint8_t*)json) + sizeof(json_stream), size, on_flush, context);

    return json;
}

void json_free(json_stream *json) {
    free(json);
}

void json_set_context(json_stream *json, void *context) {
    json->context = context;
}


void json_reset(json_stream *json) {
    json->pos = 0;
    json->state = JSON_STATE_START;
    json->nesting_idx = 0;
}


void json_flush(json_stream *json) {
    if (!json->pos)
        return;

    if (json->on_flush)
        json->on_flush(json->buffer, json->pos, json->context);
    json->pos = 0;
}

void json_put(json_stream *json, char c) {
    json->buffer[json->pos++] = c;
    if (json->pos >= json->size - 1)
        json_flush(json);
}

void json_write(json_stream *json, const char *data, size_t size) {
    while (size) {
        size_t chunk_size = size;
        if (size > json->size - json->pos)
            chunk_size = json->size - json->pos;

        memcpy((char *)json->buffer + json->pos, data, chunk_size);

        json->pos += chunk_size;
        if (json->pos >= json->size - 1)
            json_flush(json);

        data += chunk_size;
        size -= chunk_size;
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"

void json_object_start(json_stream *json) {
    if (json->state == JSON_STATE_ERROR)
        return;

    switch (json->state) {
        case JSON_STATE_ARRAY_ITEM:
            json_put(json, ',');
        case JSON_STATE_START:
        case JSON_STATE_OBJECT_KEY:
        case JSON_STATE_ARRAY:
            json_put(json, '{');

            json->state = JSON_STATE_OBJECT;
            json->nesting[json->nesting_idx++] = JSON_NESTING_OBJECT;
            break;
        default:
            ERROR("Unexpected object start");
            DEBUG_STATE(json);
            json->state = JSON_STATE_ERROR;
    }
}

void json_object_end(json_stream *json) {
    if (json->state == JSON_STATE_ERROR)
        return;

    switch (json->state) {
        case JSON_STATE_OBJECT:
        case JSON_STATE_OBJECT_VALUE:
            json_put(json, '}');

            json->nesting_idx--;
            if (!json->nesting_idx) {
                json->state = JSON_STATE_END;
            } else {
                switch (json->nesting[json->nesting_idx-1]) {
                    case JSON_NESTING_OBJECT:
                        json->state = JSON_STATE_OBJECT_VALUE;
                        break;
                    case JSON_NESTING_ARRAY:
                        json->state = JSON_STATE_ARRAY_ITEM;
                        break;
                }
            }
            break;
        default:
            ERROR("Unexpected object end");
            DEBUG_STATE(json);
            json->state = JSON_STATE_ERROR;
    }
}

void json_array_start(json_stream *json) {
    if (json->state == JSON_STATE_ERROR)
        return;

    switch (json->state) {
        case JSON_STATE_ARRAY_ITEM:
            json_put(json, ',');
        case JSON_STATE_START:
        case JSON_STATE_OBJECT_KEY:
        case JSON_STATE_ARRAY:
            json_put(json, '[');

            json->state = JSON_STATE_ARRAY;
            json->nesting[json->nesting_idx++] = JSON_NESTING_ARRAY;
            break;
        default:
            ERROR("Unexpected array start");
            DEBUG_STATE(json);
            json->state = JSON_STATE_ERROR;
    }
}

void json_array_end(json_stream *json) {
    if (json->state == JSON_STATE_ERROR)
        return;

    switch (json->state) {
        case JSON_STATE_ARRAY:
        case JSON_STATE_ARRAY_ITEM:
            json_put(json, ']');

            json->nesting_idx--;
            if (!json->nesting_idx) {
                json->state = JSON_STATE_END;
            } else {
                switch (json->nesting[json->nesting_idx-1]) {
                    case JSON_NESTING_OBJECT:
                        json->state = JSON_STATE_OBJECT_VALUE;
                        break;
                    case JSON_NESTING_ARRAY:
                        json->state = JSON_STATE_ARRAY_ITEM;
                        break;
                }
            }
            break;
        default:
            ERROR("Unexpected array end");
            DEBUG_STATE(json);
            json->state = JSON_STATE_ERROR;
    }
}

void _json_number(json_stream *json, const char *value, size_t len) {
    if (json->state == JSON_STATE_ERROR)
        return;

    void _do_write() {
        json_write(json, value, len);
    }

    switch (json->state) {
        case JSON_STATE_START:
            _do_write();
            json->state = JSON_STATE_END;
            break;
        case JSON_STATE_ARRAY_ITEM:
            json_put(json, ',');
        case JSON_STATE_ARRAY:
            _do_write();
            json->state = JSON_STATE_ARRAY_ITEM;
            break;
        case JSON_STATE_OBJECT_KEY:
            _do_write();
            json->state = JSON_STATE_OBJECT_VALUE;
            break;
        default:
            ERROR("Unexpected integer");
            DEBUG_STATE(json);
            json->state = JSON_STATE_ERROR;
    }
}


void json_uint8(json_stream *json, uint8_t x) {
    char buffer[4];
    size_t len = snprintf(buffer, sizeof(buffer), "%u", x);

    _json_number(json, buffer, len);
}

void json_uint16(json_stream *json, uint16_t x) {
    char buffer[6];
    size_t len = snprintf(buffer, sizeof(buffer), "%u", x);

    _json_number(json, buffer, len);
}

void json_uint32(json_stream *json, uint32_t x) {
    char buffer[11];
    size_t len = snprintf(buffer, sizeof(buffer), "%u", x);

    _json_number(json, buffer, len);
}

void json_uint64(json_stream *json, uint64_t x) {
    char buffer[21];
    buffer[20] = 0;

    char *b = &buffer[20];
    do {
        *(--b) = '0' + (x % 10);
    } while (x /= 10);

    _json_number(json, b, b - &buffer[20]);
}

void json_integer(json_stream *json, int x) {
    char buffer[7];
    size_t len = snprintf(buffer, sizeof(buffer), "%d", x);

    _json_number(json, buffer, len);
}

void json_float(json_stream *json, float x) {
    char buffer[32];
    size_t len = snprintf(buffer, sizeof(buffer), "%1.15g", x);

    _json_number(json, buffer, len);
}

void json_string(json_stream *json, const char *x) {
    if (json->state == JSON_STATE_ERROR)
        return;

    void _do_write() {
        // TODO: escape string
        json_put(json, '"');
        json_write(json, x, strlen(x));
        json_put(json, '"');
    }

    switch (json->state) {
        case JSON_STATE_START:
            _do_write();
            json->state = JSON_STATE_END;
            break;
        case JSON_STATE_ARRAY_ITEM:
            json_put(json, ',');
        case JSON_STATE_ARRAY:
            _do_write();
            json->state = JSON_STATE_ARRAY_ITEM;
            break;
        case JSON_STATE_OBJECT_VALUE:
            json_put(json, ',');
        case JSON_STATE_OBJECT:
            _do_write();
            json_put(json, ':');
            json->state = JSON_STATE_OBJECT_KEY;
            break;
        case JSON_STATE_OBJECT_KEY:
            _do_write();
            json->state = JSON_STATE_OBJECT_VALUE;
            break;
        default:
            ERROR("Unexpected string");
            DEBUG_STATE(json);
            json->state = JSON_STATE_ERROR;
    }
}

void json_boolean(json_stream *json, bool x) {
    if (json->state == JSON_STATE_ERROR)
        return;

    void _do_write() {
        if (x)
            json_write(json, "true", 4);
        else
            json_write(json, "false", 5);
    }

    switch (json->state) {
        case JSON_STATE_START:
            _do_write();
            json->state = JSON_STATE_END;
            break;
        case JSON_STATE_ARRAY_ITEM:
            json_put(json, ',');
        case JSON_STATE_ARRAY:
            _do_write();
            json->state = JSON_STATE_ARRAY_ITEM;
            break;
        case JSON_STATE_OBJECT_KEY:
            _do_write();
            json->state = JSON_STATE_OBJECT_VALUE;
            break;
        default:
            ERROR("Unexpected boolean");
            DEBUG_STATE(json);
            json->state = JSON_STATE_ERROR;
    }
}

void json_null(json_stream *json) {
    if (json->state == JSON_STATE_ERROR)
        return;

    void _do_write() {
        json_write(json, "null", 4);
    }

    switch (json->state) {
        case JSON_STATE_START:
            _do_write();
            json->state = JSON_STATE_END;
            break;
        case JSON_STATE_ARRAY_ITEM:
            json_put(json, ',');
        case JSON_STATE_ARRAY:
            _do_write();
            json->state = JSON_STATE_ARRAY_ITEM;
            break;
        case JSON_STATE_OBJECT_KEY:
            _do_write();
            json->state = JSON_STATE_OBJECT_VALUE;
            break;
        default:
            ERROR("Unexpected null");
            DEBUG_STATE(json);
            json->state = JSON_STATE_ERROR;
    }
}
#pragma GCC diagnostic pop
