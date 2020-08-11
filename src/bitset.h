#pragma once

#include <stdint.h>

typedef struct _bitset bitset_t;

bitset_t *bitset_new(uint16_t size);
void bitset_free(bitset_t *bs);
void bitset_clear_all(bitset_t *bs);

bool bitset_isset(bitset_t *bs, uint16_t index);
void bitset_set(bitset_t *bs, uint16_t index);
void bitset_clear(bitset_t *bs, uint16_t index);
