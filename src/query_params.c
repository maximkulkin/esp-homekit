#include <stdlib.h>
#include <string.h>
#include "query_params.h"
#include "debug.h"


int query_param_iterator_init(query_param_iterator_t *it, const char *s, size_t len) {
    it->data = (char *)s;
    it->len = len;
    it->pos = 0;

    return 0;
}

void query_param_iterator_done(query_param_iterator_t *it) {
}

bool query_param_iterator_next(query_param_iterator_t *it, query_param_t *param) {
    if (it->pos >= it->len || it->data[it->pos] == '#')
        return false;

    int pos = it->pos;
    while (it->pos < it->len &&
           it->data[it->pos] != '=' &&
           it->data[it->pos] != '&' &&
           it->data[it->pos] != '#')
        it->pos++;

    if (it->pos == pos) {
        return false;
    }

    param->name = &it->data[pos];
    param->name_len = it->pos - pos;

    param->value = NULL;
    param->value_len = 0;

    if (it->pos < it->len && it->data[it->pos] == '=') {
        it->pos++;
        pos = it->pos;
        while (it->pos < it->len &&
               it->data[it->pos] != '&' &&
               it->data[it->pos] != '#')
            it->pos++;

        if (it->pos != pos) {
            param->value = &it->data[pos];
            param->value_len = it->pos - pos;
        }
    }

    return true;
}
