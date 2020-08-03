#ifndef __HOMEKIT_QUERY_PARAMS__
#define __HOMEKIT_QUERY_PARAMS__

#include <stdbool.h>

typedef struct {
    char *data;
    size_t len;
    size_t pos;
} query_param_iterator_t;


typedef struct {
    char *name;
    size_t name_len;

    char *value;
    size_t value_len;
} query_param_t;

int query_param_iterator_init(query_param_iterator_t *it, const char *s, size_t len);
void query_param_iterator_done(query_param_iterator_t *it);
bool query_param_iterator_next(query_param_iterator_t *it, query_param_t *param);

#endif // __HOMEKIT_QUERY_PARAMS__
