#include <stdlib.h>
#include <string.h>
#include <homekit/types.h>


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
            }
        }
    }
}

homekit_characteristic_t *homekit_characteristic_find_by_id(homekit_accessory_t **accessories, int aid, int iid) {
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


void homekit_characteristic_notify(homekit_characteristic_t *ch) {
    homekit_characteristic_change_callback_t *callback = ch->callbacks;
    while (callback) {
        callback->function(ch, callback->context);
        callback = callback->next;
    }
}


void homekit_characteristic_add_notify_callback(
    homekit_characteristic_t *ch,
    void (*function)(homekit_characteristic_t *, void *),
    void *context
) {
    homekit_characteristic_change_callback_t *new_callback = malloc(sizeof(homekit_characteristic_change_callback_t));
    new_callback->function = function;
    new_callback->context = context;
    new_callback->next = NULL;

    if (!ch->callbacks) {
        ch->callbacks = new_callback;
    } else {
        homekit_characteristic_change_callback_t *callback = ch->callbacks;
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
    void (*function)(homekit_characteristic_t *, void *),
    void *context
) {
    while (ch->callbacks) {
        if (ch->callbacks->function != function || ch->callbacks->context != context) {
            break;
        }

        homekit_characteristic_change_callback_t *c = ch->callbacks->next;
        ch->callbacks = ch->callbacks->next;
        free(c);
    }

    if (!ch->callbacks)
        return;

    homekit_characteristic_change_callback_t *callback = ch->callbacks;
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
    void (*function)(homekit_characteristic_t *, void *),
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
    homekit_characteristic_t *ch,
    void (*function)(homekit_characteristic_t *, void *),
    void *context
) {
    homekit_characteristic_change_callback_t *callback = ch->callbacks;
    while (callback) {
        if (callback->function == function && callback->context == context)
            return true;

        callback = callback->next;
    }

    return false;
}

