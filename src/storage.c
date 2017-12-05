#include <string.h>
#include <ctype.h>
#include <spiflash.h>
#include "debug.h"
#include "crypto.h"
#include "pairing.h"

#ifndef SPIFLASH_BASE_ADDR
#define SPIFLASH_BASE_ADDR 0x200000
#endif


#define MAGIC_ADDR           (SPIFLASH_BASE_ADDR + 0)
#define ACCESSORY_ID_ADDR    (SPIFLASH_BASE_ADDR + 4)
#define ACCESSORY_KEY_ADDR   (SPIFLASH_BASE_ADDR + 32)
#define PAIRINGS_ADDR        (SPIFLASH_BASE_ADDR + 128)

#define MAX_PAIRINGS 16

const char magic1[] = "HAP";

int homekit_storage_reset() {
    if (!spiflash_erase_sector(MAGIC_ADDR)) {
        DEBUG("Failed to erase flash");
        return -1;
    }

    return 0;
}

int homekit_storage_init() {
    char magic[4];
    memset(magic, 0, sizeof(magic));

    if (!spiflash_read(MAGIC_ADDR, (byte *)magic, sizeof(magic))) {
        DEBUG("Failed to read flash magic");
    }

    if (strncmp(magic, magic1, sizeof(magic1))) {
        DEBUG("Formatting flash at 0x%x", MAGIC_ADDR);
        if (!spiflash_erase_sector(MAGIC_ADDR)) {
            DEBUG("Failed to erase flash");
            return -1;
        }

        if (!spiflash_read(MAGIC_ADDR, (byte *)magic, sizeof(magic))) {
            DEBUG("Failed to read flash magic");
            return -1;
        }

        strncpy(magic, magic1, sizeof(magic1));
        if (!spiflash_write(MAGIC_ADDR, (byte *)magic, sizeof(magic))) {
            DEBUG("Failed to initialize flash");
            return -1;
        }

        memset(magic, 0, sizeof(magic));
        if (!spiflash_read(MAGIC_ADDR, (byte *)magic, sizeof(magic))) {
            DEBUG("Failed to read flash magic");
            return -1;
        }

        return 1;
    }

    return 0;
}


void homekit_storage_save_accessory_id(const char *accessory_id) {
    if (!spiflash_write(ACCESSORY_ID_ADDR, (byte *)accessory_id, strlen(accessory_id))) {
        DEBUG("Failed to write accessory ID to flash");
    }
}


static char ishex(unsigned char c) {
    c = toupper(c);
    return isdigit(c) || (c >= 'A' && c <= 'F');
}

char *homekit_storage_load_accessory_id() {
    byte data[18];
    if (!spiflash_read(ACCESSORY_ID_ADDR, data, sizeof(data))) {
        DEBUG("Failed to read accessory ID from flash");
        return NULL;
    }
    if (!data[0])
        return NULL;
    data[sizeof(data)-1] = 0;

    for (int i=0; i<17; i++) {
        if (i % 3 == 2) {
           if (data[i] != ':')
               return NULL;
        } else if (!ishex(data[i]))
            return NULL;
    }

    return strndup((char *)data, sizeof(data));
}

void homekit_storage_save_accessory_key(const ed25519_key *key) {
    byte key_data[64];
    size_t key_data_size = sizeof(key_data);
    int r = crypto_ed25519_export_key(key, key_data, &key_data_size);
    if (r) {
        DEBUG("Failed to export accessory key (code %d)", r);
        return;
    }

    if (!spiflash_write(ACCESSORY_KEY_ADDR, key_data, key_data_size)) {
        DEBUG("Failed to write accessory key to flash");
        return;
    }
}

ed25519_key *homekit_storage_load_accessory_key() {
    byte key_data[64];
    if (!spiflash_read(ACCESSORY_KEY_ADDR, key_data, sizeof(key_data))) {
        DEBUG("Failed to read accessory key from flash");
        return NULL;
    }

    ed25519_key *key = crypto_ed25519_new();
    int r = crypto_ed25519_import_key(key, key_data, sizeof(key_data));
    if (r) {
        DEBUG("Failed to import accessory key (code %d)", r);
        crypto_ed25519_free(key);
        return NULL;
    }

    return key;
}

// TODO: figure out alignment issues
typedef struct {
    char magic[sizeof(magic1)];
    byte permissions;
    char device_id[36];
    byte device_public_key[32];
} pairing_data_t;


bool homekit_storage_can_add_pairing() {
    pairing_data_t data;
    for (int i=0; i<MAX_PAIRINGS; i++) {
        spiflash_read(PAIRINGS_ADDR + sizeof(data)*i, (byte *)&data, sizeof(data));
        if (strncmp(data.magic, magic1, sizeof(magic1)))
            return true;
    }
    return false;
}


int homekit_storage_add_pairing(const char *device_id, const ed25519_key *device_key, byte permissions) {
    pairing_data_t data;

    for (int i=0; i<MAX_PAIRINGS; i++) {
        spiflash_read(PAIRINGS_ADDR + sizeof(data)*i, (byte *)&data, sizeof(data));
        if (!strncmp(data.magic, magic1, sizeof(magic1)))
            continue;

        memset(&data, 0, sizeof(data));
        strncpy(data.magic, magic1, sizeof(magic1));
        data.permissions = permissions;
        strncpy(data.device_id, device_id, sizeof(data.device_id));
        size_t device_public_key_size = sizeof(data.device_public_key);
        int r = crypto_ed25519_export_public_key(device_key, data.device_public_key, &device_public_key_size);
        if (r) {
            DEBUG("Failed to export device public key (code %d)", r);
            return -1;
        }

        byte *buffer = malloc(sizeof(data));
        memcpy(buffer, &data, sizeof(data));
        if (!spiflash_write(PAIRINGS_ADDR + sizeof(data)*i, buffer, sizeof(data))) {
            DEBUG("Failed to write pairing info to flash");
            free(buffer);
            return -1;
        }
        free(buffer);

        return 0;
    }

    DEBUG("Failed to write pairing info to flash: max number of pairings");

    return -2;
}


int homekit_storage_update_pairing(const char *device_id, byte permissions) {
    pairing_data_t data;
    for (int i=0; i<MAX_PAIRINGS; i++) {
        spiflash_read(PAIRINGS_ADDR + sizeof(data)*i, (byte *)&data, sizeof(data));
        if (strncmp(data.magic, magic1, sizeof(magic1)))
            continue;

        if (!strncmp(data.device_id, device_id, sizeof(data.device_id))) {
            data.permissions = permissions;
            if (!spiflash_write(PAIRINGS_ADDR + sizeof(data)*i, (byte *)&data, sizeof(data))) {
                DEBUG("Failed to update pairing");
                return -2;
            }

            return 0;
        }
    }
    return -1;
}


int homekit_storage_remove_pairing(const char *device_id) {
    pairing_data_t data;
    for (int i=0; i<MAX_PAIRINGS; i++) {
        spiflash_read(PAIRINGS_ADDR + sizeof(data)*i, (byte *)&data, sizeof(data));
        if (strncmp(data.magic, magic1, sizeof(magic1)))
            continue;

        if (!strncmp(data.device_id, device_id, sizeof(data.device_id))) {
            memset(&data, 0, sizeof(data));
            if (!spiflash_write(PAIRINGS_ADDR + sizeof(data)*i, (byte *)&data, sizeof(data))) {
                DEBUG("Failed to remove pairing from flash");
                return -2;
            }

            return 0;
        }
    }
    return 0;
}


pairing_t *homekit_storage_find_pairing(const char *device_id) {
    pairing_data_t data;
    for (int i=0; i<MAX_PAIRINGS; i++) {
        spiflash_read(PAIRINGS_ADDR + sizeof(data)*i, (byte *)&data, sizeof(data));
        if (strncmp(data.magic, magic1, sizeof(magic1)))
            continue;

        if (!strncmp(data.device_id, device_id, sizeof(data.device_id))) {
            ed25519_key *device_key = crypto_ed25519_new();
            int r = crypto_ed25519_import_public_key(device_key, data.device_public_key, sizeof(data.device_public_key));
            if (r) {
                DEBUG("Failed to import device public key (code %d)", r);
                return NULL;
            }

            pairing_t *pairing = pairing_new();
            pairing->id = i;
            pairing->device_id = strndup(data.device_id, sizeof(data.device_id));
            pairing->device_key = device_key;
            pairing->permissions = data.permissions;

            return pairing;
        }
    }

    return NULL;
}


typedef struct {
    int idx;
} pairing_iterator_t;


pairing_iterator_t *homekit_storage_pairing_iterator() {
    pairing_iterator_t *it = malloc(sizeof(pairing_iterator_t));
    it->idx = 0;
    return it;
}


void homekit_storage_pairing_iterator_free(pairing_iterator_t *iterator) {
    free(iterator);
}


pairing_t *homekit_storage_next_pairing(pairing_iterator_t *it) {
    pairing_data_t data;
    while(it->idx < MAX_PAIRINGS) {
        int id = it->idx++;

        spiflash_read(PAIRINGS_ADDR + sizeof(data)*id, (byte *)&data, sizeof(data));
        if (!strncmp(data.magic, magic1, sizeof(magic1))) {
            ed25519_key *device_key = crypto_ed25519_new();
            int r = crypto_ed25519_import_public_key(device_key, data.device_public_key, sizeof(data.device_public_key));
            if (r) {
                DEBUG("Failed to import device public key (code %d)", r);
                crypto_ed25519_free(device_key);
                it->idx++;
                continue;
            }

            pairing_t *pairing = pairing_new();
            pairing->id = id;
            pairing->device_id = strndup(data.device_id, sizeof(data.device_id));
            pairing->device_key = device_key;
            pairing->permissions = data.permissions;

            return pairing;
        }
    }

    return NULL;
}

