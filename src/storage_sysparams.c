#include <string.h>
#include <ctype.h>
#include "constants.h"
#include "debug.h"
#include "crypto.h"
#include "pairing.h"
#include "port.h"

#include "storage.h"
#include <sysparam.h>


#define ACCESSORY_ID_KEY "hk_accessory_id"
#define ACCESSORY_KEY_KEY "hk_accessory_key"
#define PAIRING_KEY_PREFIX "hk_pairing_"


int homekit_storage_init() {
    return 0;
}


int homekit_storage_reset() {
    // TODO: delete all
    sysparam_status_t s;

    s = sysparam_set_data(ACCESSORY_ID_KEY, NULL, 0, true);
    if (s != SYSPARAM_OK && s != SYSPARAM_NOTFOUND) {
        ERROR("Failed to reset HomeKit: error removing accessory ID data (code %d)", s);
        // return -1;
    }

    s = sysparam_set_data(ACCESSORY_KEY_KEY, NULL, 0, true);
    if (s != SYSPARAM_OK && s != SYSPARAM_NOTFOUND) {
        ERROR("Failed to reset HomeKit: error removing accessory key data (code %d)", s);
        // return -2;
    }

    sysparam_iter_t iter;
    s = sysparam_iter_start(&iter);
    if (s != SYSPARAM_OK) {
        ERROR("Failed to reset HomeKit: failed to iterate over pairings (code %d)", s);
        return -3;
    }
    while (sysparam_iter_next(&iter) == SYSPARAM_OK) {
        if (strncmp(iter.key, PAIRING_KEY_PREFIX, sizeof(PAIRING_KEY_PREFIX)-1) != 0)
            continue;

        s = sysparam_set_data(iter.key, NULL, 0, true);
        if (s != SYSPARAM_OK) {
            ERROR("Failed to reset HomeKit: failed to remove pairing %s (code %d)", iter.key, s);
        }
    }
    sysparam_iter_end(&iter);

    return 0;
}

static char ishex(unsigned char c) {
    c = toupper(c);
    return isdigit(c) || (c >= 'A' && c <= 'F');
}

void homekit_storage_save_accessory_id(const char *accessory_id) {
    sysparam_status_t s;

    s = sysparam_set_string(ACCESSORY_ID_KEY, accessory_id);
    if (s != SYSPARAM_OK) {
        ERROR("Failed to write accessory ID to HomeKit storage (code %d)", s);
    }
}

int homekit_storage_load_accessory_id(char *data) {
    char *key = NULL;
    sysparam_status_t s;

    s = sysparam_get_string(ACCESSORY_ID_KEY, &key);
    if (s != SYSPARAM_OK) {
        ERROR("Failed to read accessory ID from HomeKit storage (code %d)", s);
        return -1;
    }

    if (strlen(key) != ACCESSORY_ID_SIZE) {
        free(key);
        return -2;
    }

    for (int i=0; i < ACCESSORY_ID_SIZE; i++) {
        if (i % 3 == 2) {
           if (key[i] != ':') {
               free(key);
               return -3;
           }
        } else if (!ishex(key[i])) {
            free(key);
            return -4;
        }
    }

    strcpy(data, key);
    free(key);

    return 0;
}

void homekit_storage_save_accessory_key(const ed25519_key *key) {
    byte key_data[ACCESSORY_KEY_SIZE];
    size_t key_data_size = sizeof(key_data);
    int r = crypto_ed25519_export_key(key, key_data, &key_data_size);
    if (r) {
        ERROR("Failed to export accessory key (code %d)", r);
        return;
    }

    sysparam_status_t s;
    s = sysparam_set_data(ACCESSORY_KEY_KEY, key_data, key_data_size, true);
    if (s != SYSPARAM_OK) {
        ERROR("Failed to write accessory key to HomeKit storage (code %d)", s);
        return;
    }
}

int homekit_storage_load_accessory_key(ed25519_key *key) {
    byte *key_data = NULL;
    size_t key_data_size = 0;

    sysparam_status_t s;
    s = sysparam_get_data(ACCESSORY_KEY_KEY, &key_data,&key_data_size, NULL);
    if (s != SYSPARAM_OK) {
        ERROR("Failed to read accessory key from HomeKit storage (code %d)", s);
        return -1;
    }

    crypto_ed25519_init(key);
    int r = crypto_ed25519_import_key(key, key_data, key_data_size);
    free(key_data);
    if (r) {
        ERROR("Failed to import accessory key (code %d)", r);
        return -2;
    }

    return 0;
}

typedef struct {
    byte device_public_key[32];
    byte permissions;
} pairing_data_t;


bool homekit_storage_can_add_pairing() {
    return true;
}

int homekit_storage_add_pairing(const char *device_id, const ed25519_key *device_key, byte permissions) {

    pairing_data_t data;

    data.permissions = permissions;
    size_t device_public_key_size = sizeof(data.device_public_key);
    int r = crypto_ed25519_export_public_key(
        device_key, data.device_public_key, &device_public_key_size
    );
    if (r) {
        ERROR("Failed to export device public key (code %d)", r);
        return -1;
    }

    char sysparam_key[48];
    snprintf(sysparam_key, sizeof(sysparam_key), PAIRING_KEY_PREFIX "%s", device_id);

    sysparam_status_t s;
    s = sysparam_set_data(sysparam_key, (byte *)&data, sizeof(data), true);
    if (s != SYSPARAM_OK) {
        ERROR("Failed to write pairing info to HomeKit storage (code %d)", s);
        return -1;
    }

    return 0;
}

int homekit_storage_update_pairing(const char *device_id, byte permissions) {
    char sysparam_key[48];
    snprintf(sysparam_key, sizeof(sysparam_key), PAIRING_KEY_PREFIX "%s", device_id);

    sysparam_status_t s;
    pairing_data_t data;
    size_t data_size;
    s = sysparam_get_data_static(sysparam_key, (uint8_t*)&data, sizeof(data), &data_size, NULL);
    if (s != SYSPARAM_OK) {
        ERROR("Failed to update pairing: pairing does not exist (code %d)", s);
        return -2;
    }

    data.permissions = permissions;

    s = sysparam_set_data(sysparam_key, (uint8_t*)&data, sizeof(data), true);
    if (s != SYSPARAM_OK) {
        ERROR("Failed to update pairing: error writing updated pairing data (code %d)", s);
        return -1;
    }

    return 0;
}


int homekit_storage_remove_pairing(const char *device_id) {
    char sysparam_key[48];
    snprintf(sysparam_key, sizeof(sysparam_key), PAIRING_KEY_PREFIX "%s", device_id);

    sysparam_status_t s;
    s = sysparam_set_data(sysparam_key, NULL, 0, true);
    if (s != SYSPARAM_OK) {
        ERROR("Failed to remove pairing from HomeKit storage (code %d)", s);
        return -2;
    }

    return 0;
}


int homekit_storage_find_pairing(const char *device_id, pairing_t *pairing) {
    char sysparam_key[48];
    snprintf(sysparam_key, sizeof(sysparam_key), PAIRING_KEY_PREFIX "%s", device_id);

    sysparam_status_t s;

    pairing_data_t data;
    size_t data_size;
    s = sysparam_get_data_static(sysparam_key, (uint8_t*)&data, sizeof(data), &data_size, NULL);
    if (s == SYSPARAM_NOTFOUND)
        return -1;

    if (s != SYSPARAM_OK) {
        ERROR("Failed to find pairing (code %d)", s);
        return -1;
    }

    crypto_ed25519_init(&pairing->device_key);
    int r = crypto_ed25519_import_public_key(&pairing->device_key, data.device_public_key, sizeof(data.device_public_key));
    if (r) {
        ERROR("Failed to import device public key (code %d)", r);
        return -2;
    }

    strncpy(pairing->device_id, device_id, DEVICE_ID_SIZE);
    pairing->device_id[DEVICE_ID_SIZE] = 0;
    pairing->permissions = data.permissions;

    return 0;
}


void homekit_storage_pairing_iterator_init(pairing_iterator_t *it) {
    sysparam_iter_t *iter = (sysparam_iter_t *)malloc(sizeof(sysparam_iter_t));
    if (sysparam_iter_start(iter) != SYSPARAM_OK) {
        free(iter);
        it->context = NULL;
        return;
    }

    it->context = iter;
}


void homekit_storage_pairing_iterator_done(pairing_iterator_t *it) {
    if (it->context) {
        sysparam_iter_end((sysparam_iter_t *)it->context);
        free(it->context);
        it->context = NULL;
    }
}


int homekit_storage_next_pairing(pairing_iterator_t *it, pairing_t *pairing) {
    if (!it->context)
        return -1;

    sysparam_iter_t *iter = (sysparam_iter_t *)it->context;
    while (sysparam_iter_next(iter) == SYSPARAM_OK) {
        if (strncmp(iter->key, PAIRING_KEY_PREFIX, sizeof(PAIRING_KEY_PREFIX)-1) != 0 ||
                strlen(iter->key) != (sizeof(PAIRING_KEY_PREFIX) - 1 + DEVICE_ID_SIZE))
            continue;

        pairing_data_t data;

        crypto_ed25519_init(&pairing->device_key);
        int r = crypto_ed25519_import_public_key(&pairing->device_key, data.device_public_key, sizeof(data.device_public_key));
        if (r) {
            ERROR("Failed to import device public key (code %d)", r);
            continue;
        }

        strncpy(pairing->device_id, iter->key + sizeof(PAIRING_KEY_PREFIX) - 1, DEVICE_ID_SIZE);
        pairing->device_id[DEVICE_ID_SIZE] = 0;
        pairing->permissions = data.permissions;

        return 0;
    }

    return -1;
}

