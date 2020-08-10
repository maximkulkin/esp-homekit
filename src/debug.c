#include <stdlib.h>
#include <stdio.h>
#include "debug.h"


char *binary_to_string(const byte *data, size_t size) {
    return binary_to_stringv(1, (const byte*[]){ data }, (size_t[]){ size });
}


char *binary_to_stringv(uint8_t n, const byte **datas, size_t *sizes) {
    int i, j;

    size_t buffer_size = 1; // 1 char for eos
    for (j=0; j<n; j++) {
        const byte *data = datas[j];
        for (i=0; i<sizes[j]; i++)
            buffer_size += (data[i] == '\\') ? 2 : ((data[i] >= 32 && data[i] < 128) ? 1 : 4);
    }

    char *buffer = malloc(buffer_size);
    if (!buffer)
        return NULL;

    int pos = 0;
    for (j=0; j<n; j++) {
        const byte *data = datas[j];
        size_t size = sizes[j];
        for (i=0; i<size; i++) {
            if (data[i] == '\\') {
                buffer[pos++] = '\\';
                buffer[pos++] = '\\';
            } else if (data[i] < 32 || data[i] >= 128) {
                size_t printed = snprintf(&buffer[pos], buffer_size - pos, "\\x%02X", data[i]);
                if (printed > 0) {
                    pos += printed;
                }
            } else {
                buffer[pos++] = data[i];
            }
        }
    }
    buffer[pos] = 0;

    return buffer;
}


void print_binary(const char *prompt, const byte *data, size_t size) {
#ifdef HOMEKIT_DEBUG
    char *buffer = binary_to_string(data, size);
    printf("%s (%d bytes): \"%s\"\n", prompt, (int)size, buffer);
    free(buffer);
#endif
}
