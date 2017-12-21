#include <stdlib.h>
#include <string.h>
#include <homekit/types.h>


void homekit_value_copy(homekit_value_t *dst, homekit_value_t *src) {
    memset(dst, 0, sizeof(*dst));

    dst->format = src->format;
    dst->is_null = src->is_null;

    if (!src->is_null) {
        switch (src->format) {
            case homekit_format_bool:
                dst->bool_value = src->bool_value;
                break;
            case homekit_format_uint8:
            case homekit_format_uint16:
            case homekit_format_uint32:
            case homekit_format_uint64:
            case homekit_format_int:
                dst->int_value = src->int_value;
                break;
            case homekit_format_float:
                dst->float_value = src->float_value;
                break;
            case homekit_format_string:
                if (src->is_static) {
                    dst->string_value = src->string_value;
                    dst->is_static = true;
                } else {
                    dst->string_value = strdup(src->string_value);
                }
                break;
            case homekit_format_tlv:
            case homekit_format_data:
                // TODO:
                break;
            default:
                // unknown format
                break;
        }
    }
}


homekit_value_t *homekit_value_clone(homekit_value_t *value) {
    homekit_value_t *copy = malloc(sizeof(homekit_value_t));
    homekit_value_copy(copy, value);
    return copy;
}

void homekit_value_destruct(homekit_value_t *value) {
    if (!value->is_null) {
        switch (value->format) {
            case homekit_format_string:
                if (!value->is_static && value->string_value)
                    free(value->string_value);
                break;
            case homekit_format_tlv:
            case homekit_format_data:
                // TODO:
                break;
            default:
                // unknown format
                break;
        }
    }
}

void homekit_value_free(homekit_value_t *value) {
    homekit_value_destruct(value);
    free(value);
}

void homekit_accessories_init(homekit_accessory_t **accessories) {
    int aid = 1;
    for (homekit_accessory_t **accessory_it = accessories; *accessory_it; accessory_it++) {
        homekit_accessory_t *accessory = *accessory_it;
        if (accessory->id) {
            if (accessory->id >= aid)
                aid = accessory->id+1;
        } else {
            accessory->id = aid++;
        }

        int iid = 1;
        for (homekit_service_t **service_it = accessory->services; *service_it; service_it++) {
            homekit_service_t *service = *service_it;
            service->accessory = accessory;
            if (service->id) {
                if (service->id >= iid)
                    iid = service->id+1;
            } else {
                service->id = iid++;
            }

            for (homekit_characteristic_t **ch_it = service->characteristics; *ch_it; ch_it++) {
                homekit_characteristic_t *ch = *ch_it;
                ch->service = service;
                if (ch->id) {
                    if (ch->id >= iid)
                        iid = ch->id+1;
                } else {
                    ch->id = iid++;
                }

                ch->value.format = ch->format;
            }
        }
    }
}

homekit_accessory_t *homekit_accessory_by_id(homekit_accessory_t **accessories, int aid) {
    for (homekit_accessory_t **accessory_it = accessories; *accessory_it; accessory_it++) {
        homekit_accessory_t *accessory = *accessory_it;

        if (accessory->id == aid)
            return accessory;
    }

    return NULL;
}

homekit_service_t *homekit_service_by_type(homekit_accessory_t *accessory, const char *type) {
    for (homekit_service_t **service_it = accessory->services; *service_it; service_it++) {
        homekit_service_t *service = *service_it;

        if (!strcmp(service->type, type))
            return service;
    }

    return NULL;
}

homekit_characteristic_t *homekit_service_characteristic_by_type(homekit_service_t *service, const char *type) {
    for (homekit_characteristic_t **ch_it = service->characteristics; *ch_it; ch_it++) {
        homekit_characteristic_t *ch = *ch_it;

        if (!strcmp(ch->type, type))
            return ch;
    }

    return NULL;
}

homekit_characteristic_t *homekit_characteristic_by_aid_and_iid(homekit_accessory_t **accessories, int aid, int iid) {
    for (homekit_accessory_t **accessory_it = accessories; *accessory_it; accessory_it++) {
        homekit_accessory_t *accessory = *accessory_it;

        if (accessory->id != aid)
            continue;

        for (homekit_service_t **service_it = accessory->services; *service_it; service_it++) {
            homekit_service_t *service = *service_it;

            for (homekit_characteristic_t **ch_it = service->characteristics; *ch_it; ch_it++) {
                homekit_characteristic_t *ch = *ch_it;

                if (ch->id == iid)
                    return ch;
            }
        }
    }

    return NULL;
}


homekit_characteristic_t *homekit_characteristic_find_by_type(homekit_accessory_t **accessories, int aid, const char *type) {
    for (homekit_accessory_t **accessory_it = accessories; *accessory_it; accessory_it++) {
        homekit_accessory_t *accessory = *accessory_it;

        if (accessory->id != aid)
            continue;

        for (homekit_service_t **service_it = accessory->services; *service_it; service_it++) {
            homekit_service_t *service = *service_it;

            for (homekit_characteristic_t **ch_it = service->characteristics; *ch_it; ch_it++) {
                homekit_characteristic_t *ch = *ch_it;

                if (!strcmp(ch->type, type))
                    return ch;
            }
        }
    }

    return NULL;
}


void homekit_characteristic_notify(homekit_characteristic_t *ch, homekit_value_t value) {
    homekit_characteristic_change_callback_t *callback = ch->callback;
    while (callback) {
        callback->function(ch, value, callback->context);
        callback = callback->next;
    }
}


void homekit_characteristic_add_notify_callback(
    homekit_characteristic_t *ch,
    homekit_characteristic_change_callback_fn function,
    void *context
) {
    homekit_characteristic_change_callback_t *new_callback = malloc(sizeof(homekit_characteristic_change_callback_t));
    new_callback->function = function;
    new_callback->context = context;
    new_callback->next = NULL;

    if (!ch->callback) {
        ch->callback = new_callback;
    } else {
        homekit_characteristic_change_callback_t *callback = ch->callback;
        if (callback->function == function && callback->context == context) {
            free(new_callback);
            return;
        }

        while (callback->next) {
            if (callback->next->function == function && callback->next->context == context) {
                free(new_callback);
                return;
            }
            callback = callback->next;
        }

        callback->next = new_callback;
    }
}


void homekit_characteristic_remove_notify_callback(
    homekit_characteristic_t *ch,
    homekit_characteristic_change_callback_fn function,
    void *context
) {
    while (ch->callback) {
        if (ch->callback->function != function || ch->callback->context != context) {
            break;
        }

        homekit_characteristic_change_callback_t *c = ch->callback->next;
        ch->callback = ch->callback->next;
        free(c);
    }

    if (!ch->callback)
        return;

    homekit_characteristic_change_callback_t *callback = ch->callback;
    while (callback->next) {
        if (callback->next->function == function && callback->next->context == context) {
            homekit_characteristic_change_callback_t *c = callback->next;
            callback->next = callback->next->next;
            free(c);
        } else {
            callback = callback->next;
        }
    }
}


void homekit_accessories_clear_notify_callbacks(
    homekit_accessory_t **accessories,
    homekit_characteristic_change_callback_fn function,
    void *context
) {
    for (homekit_accessory_t **accessory_it = accessories; *accessory_it; accessory_it++) {
        homekit_accessory_t *accessory = *accessory_it;

        for (homekit_service_t **service_it = accessory->services; *service_it; service_it++) {
            homekit_service_t *service = *service_it;

            for (homekit_characteristic_t **ch_it = service->characteristics; *ch_it; ch_it++) {
                homekit_characteristic_t *ch = *ch_it;

                homekit_characteristic_remove_notify_callback(ch, function, context);
            }
        }
    }
}


bool homekit_characteristic_has_notify_callback(
    const homekit_characteristic_t *ch,
    homekit_characteristic_change_callback_fn function,
    void *context
) {
    homekit_characteristic_change_callback_t *callback = ch->callback;
    while (callback) {
        if (callback->function == function && callback->context == context)
            return true;

        callback = callback->next;
    }

    return false;
}

