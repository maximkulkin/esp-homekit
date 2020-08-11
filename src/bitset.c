#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


typedef struct _bitset {
    uint16_t size;
    uint8_t *data;
} bitset_t;


bitset_t *bitset_new(uint16_t size) {
    bitset_t *bs = malloc(sizeof(bitset_t) + (size + 7 / 8));
    bs->data = ((uint8_t*)bs) + sizeof(bitset_t);
    bs->size = size;
    memset(bs->data, 0, (size + 7) / 8);
    return bs;
}


void bitset_free(bitset_t *bs) {
    free(bs);
}


void bitset_clear_all(bitset_t *bs) {
    memset(bs->data, 0, (bs->size + 7) / 8);
}


bool bitset_isset(bitset_t *bs, uint16_t index) {
    return (bs->data[index / 8] & (1 << (index % 8))) != 0;
}


void bitset_set(bitset_t *bs, uint16_t index) {
    if (index >= bs->size)
        return;

    bs->data[index / 8] |= (1 << (index % 8));
}


void bitset_clear(bitset_t *bs, uint16_t index) {
    if (index >= bs->size)
        return;

    bs->data[index / 8] &= ~(1 << (index % 8));
}
