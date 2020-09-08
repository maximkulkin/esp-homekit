#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#include <lwip/sockets.h>

#include <unistd.h>

#if defined(ESP_IDF)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#elif defined(ESP_OPEN_RTOS)
#include <FreeRTOS.h>
#include <task.h>
#include <queue.h>
#include <semphr.h>
#else
#error "Unknown target platform"
#endif

#include <http-parser/http_parser.h>
#include <cJSON.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/coding.h>

#include "constants.h"
#include "base64.h"
#include "bitset.h"
#include "crypto.h"
#include "pairing.h"
#include "storage.h"
#include "query_params.h"
#include "json.h"
#include "debug.h"
#include "port.h"

#include <homekit/homekit.h>
#include <homekit/characteristics.h>
#include <homekit/tlv.h>
#include "tlv_internal.h"


#define PORT 5556

#ifndef HOMEKIT_MAX_CLIENTS
#define HOMEKIT_MAX_CLIENTS 16
#endif

struct _client_context_t;
typedef struct _client_context_t client_context_t;


#define HOMEKIT_NOTIFY_EVENT(server, event) \
  if ((server)->config->on_event) \
      (server)->config->on_event(event);


#define countof(items) (sizeof(items) / sizeof(items[0]))


typedef enum {
    HOMEKIT_ENDPOINT_UNKNOWN = 0,
    HOMEKIT_ENDPOINT_PAIR_SETUP,
    HOMEKIT_ENDPOINT_PAIR_VERIFY,
    HOMEKIT_ENDPOINT_IDENTIFY,
    HOMEKIT_ENDPOINT_GET_ACCESSORIES,
    HOMEKIT_ENDPOINT_GET_CHARACTERISTICS,
    HOMEKIT_ENDPOINT_UPDATE_CHARACTERISTICS,
    HOMEKIT_ENDPOINT_PAIRINGS,
    HOMEKIT_ENDPOINT_RESOURCE,
} homekit_endpoint_t;


typedef enum {
    characteristic_format_type   = (1 << 1),
    characteristic_format_meta   = (1 << 2),
    characteristic_format_perms  = (1 << 3),
    characteristic_format_events = (1 << 4),
} characteristic_format_t;


typedef struct {
    Srp *srp;
    byte *public_key;
    size_t public_key_size;

    client_context_t *client;
} pairing_context_t;


typedef struct {
    byte *secret;
    size_t secret_size;
    byte *session_key;
    size_t session_key_size;
    byte *device_public_key;
    size_t device_public_key_size;
    byte *accessory_public_key;
    size_t accessory_public_key_size;
} pair_verify_context_t;


typedef struct {
    homekit_accessory_t *accessory;
    uint16_t aid;
} accessory_info_t;


typedef struct {
    homekit_service_t *service;
    uint16_t iid;
} service_info_t;


typedef struct {
    homekit_characteristic_t *ch;
    uint16_t aid;
    uint16_t iid;
    uint16_t notification_id;
} characteristic_info_t;


typedef struct {
    homekit_characteristic_t *ch;
    homekit_value_t value;
} characteristic_notification_info_t;


typedef struct {
    char accessory_id[ACCESSORY_ID_SIZE + 1];
    ed25519_key accessory_key;

    homekit_server_config_t *config;

    bool paired;
    pairing_context_t *pairing_context;

    int listen_fd;
    fd_set fds;
    int max_fd;

    homekit_endpoint_t endpoint;
    struct {
        struct {
            uint16_t aid;
            uint16_t iid;
        } ids[25];
        characteristic_format_t format;
    } endpoint_params;

    byte data[1024 + 18];
    byte output_buffer[1024];

    char *body;
    size_t body_length;
    bool body_static;
    http_parser parser;

    bool request_completed;

    json_stream json;
    tlv_stream_t tlv_stream;

    SemaphoreHandle_t notification_lock;

    uint16_t accessory_count;
    accessory_info_t *accessory_infos;

    uint16_t service_count;
    service_info_t *service_infos;

    uint16_t characteristic_count;
    characteristic_info_t *characteristic_infos;

    uint16_t notify_count;
    characteristic_notification_info_t *notifications;

    bitset_t *subscriptions;
    bool has_notifications;
    bitset_t *has_notification;

    int client_count;
    client_context_t *clients;
    bitset_t *client_ids;
} homekit_server_t;


static homekit_server_t *server = NULL;


struct _client_context_t {
    homekit_server_t *server;

    uint8_t id;
    int socket;

    int pairing_id;
    byte permissions;

    bool disconnect;

    bool encrypted;
    byte read_key[32];
    byte write_key[32];
    int count_reads;
    int count_writes;

    pair_verify_context_t *verify_context;

    struct _client_context_t *next;
};


void client_context_free(client_context_t *c);
void pairing_context_free(pairing_context_t *context);
void client_send_chunk(byte *data, size_t size, void *arg);


homekit_server_t *server_new() {
    homekit_server_t *server = malloc(sizeof(homekit_server_t));
    if (!server) {
        return NULL;
    }

    FD_ZERO(&server->fds);
    server->max_fd = 0;
    server->client_count = 0;
    server->config = NULL;
    server->paired = false;
    server->pairing_context = NULL;
    server->clients = NULL;

    memset(&server->endpoint_params, 0, sizeof(server->endpoint_params));

    server->body = NULL;
    server->body_length = 0;
    server->body_static = false;
    http_parser_init(&server->parser, HTTP_REQUEST);

    json_init(&server->json, server->output_buffer, sizeof(server->output_buffer),
              client_send_chunk, NULL);
    tlv_stream_init(
        &server->tlv_stream,
        server->output_buffer, sizeof(server->output_buffer), client_send_chunk, NULL
    );

    server->accessory_count = 0;
    server->accessory_infos = NULL;
    server->service_count = 0;
    server->service_infos = NULL;
    server->characteristic_count = 0;
    server->characteristic_infos = NULL;

    server->client_ids = bitset_new(HOMEKIT_MAX_CLIENTS);

    server->notification_lock = xSemaphoreCreateBinary();
    if (!server->notification_lock) {
        bitset_free(server->client_ids);
        free(server);
        return NULL;
    }

    xSemaphoreGive(server->notification_lock);

    server->has_notifications = false;
    server->subscriptions = NULL;
    server->notifications = NULL;
    server->has_notification = NULL;

    return server;
}


void server_free(homekit_server_t *server) {
    if (server->client_ids) {
        bitset_free(server->client_ids);
    }

    if (server->has_notification) {
        bitset_free(server->has_notification);
    }

    if (server->notifications) {
        free(server->notifications);
    }

    if (server->subscriptions) {
        bitset_free(server->subscriptions);
    }

    if (server->notification_lock) {
        vSemaphoreDelete(server->notification_lock);
    }

    if (server->characteristic_infos) {
        free(server->characteristic_infos);
    }

    if (server->service_infos) {
        free(server->service_infos);
    }

    if (server->accessory_infos) {
        free(server->accessory_infos);
    }

    if (server->body)
        free(server->body);

    if (server->pairing_context)
        pairing_context_free(server->pairing_context);

    if (server->clients) {
        client_context_t *client = server->clients;
        while (client) {
            client_context_t *next = client->next;
            client_context_free(client);
            client = next;
        }
    }

    free(server);
}

#ifdef HOMEKIT_DEBUG
#define TLV_DEBUG(values) tlv_debug(values)
#else
#define TLV_DEBUG(values)
#endif

#define CLIENT_DEBUG(client, message, ...) DEBUG("[Client%2d] " message, client->id+1, ##__VA_ARGS__)
#define CLIENT_INFO(client, message, ...) INFO("[Client%2d] " message, client->id+1, ##__VA_ARGS__)
#define CLIENT_ERROR(client, message, ...) ERROR("[Client%2d] " message, client->id+1, ##__VA_ARGS__)

void tlv_debug(const tlv_values_t *values) {
    DEBUG("Got following TLV values:");
    for (tlv_t *t=values->head; t; t=t->next) {
        char *escaped_payload = binary_to_string(t->value, t->size);
        DEBUG("Type %d value (%d bytes): %s", t->type, t->size, escaped_payload);
        free(escaped_payload);
    }
}


typedef enum {
    TLVType_Method = 0,        // (integer) Method to use for pairing. See PairMethod
    TLVType_Identifier = 1,    // (UTF-8) Identifier for authentication
    TLVType_Salt = 2,          // (bytes) 16+ bytes of random salt
    TLVType_PublicKey = 3,     // (bytes) Curve25519, SRP public key or signed Ed25519 key
    TLVType_Proof = 4,         // (bytes) Ed25519 or SRP proof
    TLVType_EncryptedData = 5, // (bytes) Encrypted data with auth tag at end
    TLVType_State = 6,         // (integer) State of the pairing process. 1=M1, 2=M2, etc.
    TLVType_Error = 7,         // (integer) Error code. Must only be present if error code is
                               // not 0. See TLVError
    TLVType_RetryDelay = 8,    // (integer) Seconds to delay until retrying a setup code
    TLVType_Certificate = 9,   // (bytes) X.509 Certificate
    TLVType_Signature = 10,    // (bytes) Ed25519
    TLVType_Permissions = 11,  // (integer) Bit value describing permissions of the controller
                               // being added.
                               // None (0x00): Regular user
                               // Bit 1 (0x01): Admin that is able to add and remove
                               // pairings against the accessory
    TLVType_FragmentData = 13, // (bytes) Non-last fragment of data. If length is 0,
                               // it's an ACK.
    TLVType_FragmentLast = 14, // (bytes) Last fragment of data
    TLVType_Separator = 0xff,
} TLVType;


typedef enum {
  TLVMethod_PairSetup = 1,
  TLVMethod_PairVerify = 2,
  TLVMethod_AddPairing = 3,
  TLVMethod_RemovePairing = 4,
  TLVMethod_ListPairings = 5,
} TLVMethod;


typedef enum {
  TLVError_Unknown = 1,         // Generic error to handle unexpected errors
  TLVError_Authentication = 2,  // Setup code or signature verification failed
  TLVError_Backoff = 3,         // Client must look at the retry delay TLV item and
                                // wait that many seconds before retrying
  TLVError_MaxPeers = 4,        // Server cannot accept any more pairings
  TLVError_MaxTries = 5,        // Server reached its maximum number of
                                // authentication attempts
  TLVError_Unavailable = 6,     // Server pairing method is unavailable
  TLVError_Busy = 7,            // Server is busy and cannot accept a pairing
                                // request at this time
} TLVError;


typedef enum {
    // This specifies a success for the request
    HAPStatus_Success = 0,
    // Request denied due to insufficient privileges
    HAPStatus_InsufficientPrivileges = -70401,
    // Unable to communicate with requested services,
    // e.g. the power to the accessory was turned off
    HAPStatus_NoAccessoryConnection = -70402,
    // Resource is busy, try again
    HAPStatus_ResourceBusy = -70403,
    // Cannot write to read only characteristic
    HAPStatus_ReadOnly = -70404,
    // Cannot read from a write only characteristic
    HAPStatus_WriteOnly = -70405,
    // Notification is not supported for characteristic
    HAPStatus_NotificationsUnsupported = -70406,
    // Out of resources to process request
    HAPStatus_OutOfResources = -70407,
    // Operation timed out
    HAPStatus_Timeout = -70408,
    // Resource does not exist
    HAPStatus_NoResource = -70409,
    // Accessory received an invalid value in a write request
    HAPStatus_InvalidValue = -70410,
    // Insufficient Authorization
    HAPStatus_InsufficientAuthorization = -70411,
} HAPStatus;


pair_verify_context_t *pair_verify_context_new() {
    pair_verify_context_t *context = malloc(sizeof(pair_verify_context_t));
    if (!context) {
        return NULL;
    }

    context->secret = NULL;
    context->secret_size = 0;

    context->session_key = NULL;
    context->session_key_size = 0;
    context->device_public_key = NULL;
    context->device_public_key_size = 0;
    context->accessory_public_key = NULL;
    context->accessory_public_key_size = 0;

    return context;
}

void pair_verify_context_free(pair_verify_context_t *context) {
    if (context->secret)
        free(context->secret);

    if (context->session_key)
        free(context->session_key);

    if (context->device_public_key)
        free(context->device_public_key);

    if (context->accessory_public_key)
        free(context->accessory_public_key);

    free(context);
}


client_context_t *client_context_new() {
    client_context_t *c = malloc(sizeof(client_context_t));
    if (!c) {
        return NULL;
    }

    c->server = NULL;
    c->id = 0;

    c->pairing_id = -1;
    c->encrypted = false;
    c->count_reads = 0;
    c->count_writes = 0;

    c->disconnect = false;
    c->verify_context = NULL;
    c->next = NULL;

    return c;
}


void client_context_free(client_context_t *c) {
    if (c->verify_context)
        pair_verify_context_free(c->verify_context);

    free(c);
}




pairing_context_t *pairing_context_new() {
    pairing_context_t *context = malloc(sizeof(pairing_context_t));
    if (!context) {
        return NULL;
    }

    context->srp = crypto_srp_new();
    context->client = NULL;
    context->public_key = NULL;
    context->public_key_size = 0;
    return context;
}

void pairing_context_free(pairing_context_t *context) {
    if (context->srp) {
        crypto_srp_free(context->srp);
    }
    if (context->public_key) {
        free(context->public_key);
    }
    free(context);
}

accessory_info_t *find_accessory_info(const homekit_server_t *server, const homekit_accessory_t *accessory) {
    uint16_t l = 0, r = server->accessory_count;
    while (l < r) {
        uint16_t m = l + (r - l) / 2;
        if (server->accessory_infos[m].accessory == accessory) {
            l = m;
            break;
        }

        if (server->accessory_infos[m].accessory < accessory) {
            l = m + 1;
        } else {
            r = m;
        }
    }
    if (l >= server->accessory_count)
        return NULL;

    return &server->accessory_infos[l];
}

service_info_t *find_service_info(const homekit_server_t *server, const homekit_service_t *service) {
    uint16_t l = 0, r = server->service_count;
    while (l < r) {
        uint16_t m = l + (r - l) / 2;
        if (server->service_infos[m].service == service) {
            l = m;
            break;
        }

        if (server->service_infos[m].service < service) {
            l = m + 1;
        } else {
            r = m;
        }
    }
    if (l >= server->service_count)
        return NULL;

    return &server->service_infos[l];
}

characteristic_info_t *find_characteristic_info_by_characteristic(
    const homekit_server_t *server, const homekit_characteristic_t *ch
) {
    uint16_t l = 0, r = server->characteristic_count;
    while (l < r) {
        uint16_t m = l + (r - l) / 2;
        if (server->characteristic_infos[m].ch == ch) {
            l = m;
            break;
        }

        if (server->characteristic_infos[m].ch < ch) {
            l = m + 1;
        } else {
            r = m;
        }
    }
    if (l >= server->characteristic_count)
        return NULL;

    return &server->characteristic_infos[l];
}


// TODO: deprecate accessories argument
homekit_accessory_t *homekit_accessory_by_id(homekit_accessory_t **accessories, int aid) {
    for (uint16_t i=0; i < server->accessory_count; i++) {
        if (server->accessory_infos[i].aid == aid)
            return server->accessory_infos[i].accessory;
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

// TODO: deprecate accessories argument
homekit_characteristic_t *homekit_characteristic_by_aid_and_iid(homekit_accessory_t **accessories, int aid, int iid) {
    for (uint16_t i=0; i < server->characteristic_count; i++) {
        characteristic_info_t *ch_info = &server->characteristic_infos[i];
        if (ch_info->aid == aid && ch_info->iid == iid)
            return ch_info->ch;
    }

    return NULL;
}


homekit_characteristic_t *homekit_characteristic_find_by_type(homekit_accessory_t **accessories, int aid, const char *type) {
    for (uint16_t i=0; i < server->characteristic_count; i++) {
        characteristic_info_t *ch_info = &server->characteristic_infos[i];
        if (ch_info->aid == aid && !strcmp(ch_info->ch->type, type))
            return ch_info->ch;
    }

    return NULL;
}


bool client_has_subscribed_to_characteristic_events(client_context_t *client, const homekit_characteristic_t *ch) {
    homekit_server_t *server = client->server;

    characteristic_info_t *info = find_characteristic_info_by_characteristic(server, ch);
    if (!info)
        return false;

    return bitset_isset(server->subscriptions, info->notification_id * HOMEKIT_MAX_CLIENTS + client->id);
}

void client_subscribe_to_characteristic_events(client_context_t *client, const homekit_characteristic_t *ch) {
    characteristic_info_t *info = find_characteristic_info_by_characteristic(server, ch);
    if (!info)
        return;

    bitset_set(client->server->subscriptions, info->notification_id * HOMEKIT_MAX_CLIENTS + client->id);
}

void client_unsubscribe_from_characteristic_events(client_context_t *client, const homekit_characteristic_t *ch) {
    characteristic_info_t *info = find_characteristic_info_by_characteristic(server, ch);
    if (!info)
        return;

    bitset_clear(client->server->subscriptions, info->notification_id * HOMEKIT_MAX_CLIENTS + client->id);
}

void write_characteristic_json(json_stream *json, client_context_t *client, const homekit_characteristic_t *ch, characteristic_format_t format, const homekit_value_t *v) {
    characteristic_info_t *ch_info = find_characteristic_info_by_characteristic(client->server, ch);
    if (!ch_info) {
        ERROR("Failed to lookup characteristic info for characteristic \"%s\"", ch->description);
        return;
    }

    json_string(json, "aid"); json_uint32(json, ch_info->aid);
    json_string(json, "iid"); json_uint32(json, ch_info->iid);

    if (format & characteristic_format_type) {
        json_string(json, "type"); json_string(json, ch->type);
    }

    if (format & characteristic_format_perms) {
        json_string(json, "perms"); json_array_start(json);
        if (ch->permissions & homekit_permissions_paired_read)
            json_string(json, "pr");
        if (ch->permissions & homekit_permissions_paired_write)
            json_string(json, "pw");
        if (ch->permissions & homekit_permissions_notify)
            json_string(json, "ev");
        if (ch->permissions & homekit_permissions_additional_authorization)
            json_string(json, "aa");
        if (ch->permissions & homekit_permissions_timed_write)
            json_string(json, "tw");
        if (ch->permissions & homekit_permissions_hidden)
            json_string(json, "hd");
        json_array_end(json);
    }

    if ((format & characteristic_format_events) && (ch->permissions & homekit_permissions_notify)) {
        bool events = client_has_subscribed_to_characteristic_events(client, ch);
        json_string(json, "ev"); json_boolean(json, events);
    }

    if (format & characteristic_format_meta) {
        if (ch->description) {
            json_string(json, "description"); json_string(json, ch->description);
        }

        const char *format_str = NULL;
        switch(ch->format) {
            case homekit_format_bool: format_str = "bool"; break;
            case homekit_format_uint8: format_str = "uint8"; break;
            case homekit_format_uint16: format_str = "uint16"; break;
            case homekit_format_uint32: format_str = "uint32"; break;
            case homekit_format_uint64: format_str = "uint64"; break;
            case homekit_format_int: format_str = "int"; break;
            case homekit_format_float: format_str = "float"; break;
            case homekit_format_string: format_str = "string"; break;
            case homekit_format_tlv: format_str = "tlv8"; break;
            case homekit_format_data: format_str = "data"; break;
        }
        if (format_str) {
            json_string(json, "format"); json_string(json, format_str);
        }

        const char *unit_str = NULL;
        switch(ch->unit) {
            case homekit_unit_none: break;
            case homekit_unit_celsius: unit_str = "celsius"; break;
            case homekit_unit_percentage: unit_str = "percentage"; break;
            case homekit_unit_arcdegrees: unit_str = "arcdegrees"; break;
            case homekit_unit_lux: unit_str = "lux"; break;
            case homekit_unit_seconds: unit_str = "seconds"; break;
        }
        if (unit_str) {
            json_string(json, "unit"); json_string(json, unit_str);
        }

        if (ch->min_value) {
            json_string(json, "minValue"); json_float(json, *ch->min_value);
        }

        if (ch->max_value) {
            json_string(json, "maxValue"); json_float(json, *ch->max_value);
        }

        if (ch->min_step) {
            json_string(json, "minStep"); json_float(json, *ch->min_step);
        }

        if (ch->max_len) {
            json_string(json, "maxLen"); json_uint32(json, *ch->max_len);
        }

        if (ch->max_data_len) {
            json_string(json, "maxDataLen"); json_uint32(json, *ch->max_data_len);
        }

        if (ch->valid_values.count) {
            json_string(json, "valid-values"); json_array_start(json);

            for (int i=0; i<ch->valid_values.count; i++) {
                json_uint16(json, ch->valid_values.values[i]);
            }

            json_array_end(json);
        }

        if (ch->valid_values_ranges.count) {
            json_string(json, "valid-values-range"); json_array_start(json);

            for (int i=0; i<ch->valid_values_ranges.count; i++) {
                json_array_start(json);

                json_integer(json, ch->valid_values_ranges.ranges[i].start);
                json_integer(json, ch->valid_values_ranges.ranges[i].end);

                json_array_end(json);
            }

            json_array_end(json);
        }
    }

    if (ch->permissions & homekit_permissions_paired_read) {
        if (v->is_null) {
            // json_string(json, "value"); json_null(json);
        } else if (v->format != ch->format) {
            ERROR("Characteristic value format is different from characteristic format");
        } else {
            switch(v->format) {
                case homekit_format_bool: {
                    json_string(json, "value"); json_boolean(json, v->bool_value);
                    break;
                }
                case homekit_format_uint8: {
                    json_string(json, "value"); json_uint8(json, v->uint8_value);
                    break;
                }
                case homekit_format_uint16: {
                    json_string(json, "value"); json_uint16(json, v->uint16_value);
                    break;
                }
                case homekit_format_uint32: {
                    json_string(json, "value"); json_uint32(json, v->uint32_value);
                    break;
                }
                case homekit_format_uint64: {
                    json_string(json, "value"); json_uint64(json, v->uint64_value);
                    break;
                }
                case homekit_format_int: {
                    json_string(json, "value"); json_integer(json, v->int_value);
                    break;
                }
                case homekit_format_float: {
                    json_string(json, "value"); json_float(json, v->float_value);
                    break;
                }
                case homekit_format_string: {
                    json_string(json, "value"); json_string(json, v->string_value);
                    break;
                }
                case homekit_format_tlv: {
                    json_string(json, "value");
                    if (!v->tlv_values) {
                        json_string(json, "");
                    } else {
                        size_t tlv_size = 0;
                        tlv_format(v->tlv_values, NULL, &tlv_size);
                        if (tlv_size == 0) {
                            json_string(json, "");
                        } else {
                            byte *tlv_data = malloc(tlv_size);
                            if (!tlv_data) {
                                CLIENT_ERROR(client, "Failed to allocate %d bytes for characteristic TLV data", tlv_size);
                                json_string(json, "");
                                break;
                            }
                            if (tlv_format(v->tlv_values, tlv_data, &tlv_size)) {
                                CLIENT_ERROR(client, "Failed to format TLV characteristic data");
                                json_string(json, "");
                                break;
                            }

                            size_t encoded_tlv_size = base64_encoded_size(tlv_data, tlv_size);
                            byte *encoded_tlv_data = malloc(encoded_tlv_size + 1);
                            if (!encoded_tlv_data) {
                                CLIENT_ERROR(client, "Failed to allocate %d bytes for encoding characteristic TLV data", encoded_tlv_size + 1);
                                free(tlv_data);
                                json_string(json, "");
                                break;
                            }
                            base64_encode(tlv_data, tlv_size, encoded_tlv_data);
                            encoded_tlv_data[encoded_tlv_size] = 0;

                            json_string(json, (char*) encoded_tlv_data);

                            free(encoded_tlv_data);
                            free(tlv_data);
                        }
                    }
                    break;
                }
                case homekit_format_data: {
                    json_string(json, "value");
                    if (!v->data_value || v->data_size == 0) {
                        json_string(json, "");
                    } else {
                        size_t encoded_data_size = base64_encoded_size(v->data_value, v->data_size);
                        byte *encoded_data = malloc(encoded_data_size + 1);
                        if (!encoded_data) {
                            CLIENT_ERROR(client, "Failed to allocate %d bytes for encoding characteristic data", encoded_data_size + 1);
                            json_string(json, "");
                            break;
                        }
                        base64_encode(v->data_value, v->data_size, encoded_data);
                        encoded_data[encoded_data_size] = 0;

                        json_string(json, (char*) encoded_data);

                        free(encoded_data);
                    }

                    break;
                }
            }
        }
    }
}


int client_send_encryptedv(
    client_context_t *context,
    uint8_t n, const byte **part_data, size_t *part_sizes
) {
    if (!context || !context->encrypted)
        return -1;

    byte nonce[12];
    memset(nonce, 0, sizeof(nonce));

    byte encrypted[1024 + 18];

    uint8_t part_index = 0;
    size_t part_offset = 0;

    byte *aead = encrypted;

    while (part_index < n) {
        size_t chunk_size = 0;
        while (part_index < n && chunk_size < 1024) {
            size_t extra_size = part_sizes[part_index] - part_offset;
            if (chunk_size + extra_size > 1024) {
                extra_size = 1024 - chunk_size;
            }

            memcpy(encrypted+2+chunk_size, part_data[part_index]+part_offset, extra_size);

            chunk_size += extra_size;
            part_offset += extra_size;
            if (part_offset >= part_sizes[part_index]) {
                part_index++;
                part_offset = 0;
            }
        }

        aead[0] = chunk_size & 0xff;
        aead[1] = chunk_size >> 8;

        byte i = 4;
        int x = context->count_reads++;
        while (x) {
            nonce[i++] = x % 256;
            x /= 256;
        }

        size_t available = sizeof(encrypted) - 2;
        int r = crypto_chacha20poly1305_encrypt(
            context->read_key, nonce, aead, 2,
            encrypted+2, chunk_size,
            encrypted+2, &available
        );
        if (r) {
            ERROR("Failed to chacha encrypt payload (code %d)", r);
            return -1;
        }

        write(context->socket, encrypted, available + 2);
    }

    return 0;
}


int client_decrypt(
    client_context_t *context,
    byte *payload, size_t payload_size,
    byte *decrypted, size_t *decrypted_size
) {
    if (!context || !context->encrypted)
        return -1;

    const size_t block_size = 1024 + 16 + 2;
    size_t required_decrypted_size = payload_size / block_size * 1024;
    if (payload_size % block_size > 0)
       required_decrypted_size += payload_size % block_size - 16 - 2;

    if (*decrypted_size < required_decrypted_size) {
        *decrypted_size = required_decrypted_size;
        return -2;
    }

    *decrypted_size = required_decrypted_size;

    byte nonce[12];
    memset(nonce, 0, sizeof(nonce));

    int payload_offset = 0;
    int decrypted_offset = 0;

    while (payload_offset < payload_size) {
        size_t chunk_size = payload[payload_offset] + payload[payload_offset+1]*256;
        if (chunk_size+18 > payload_size-payload_offset) {
            // Unfinished chunk
            break;
        }

        byte i = 4;
        int x = context->count_writes++;
        while (x) {
            nonce[i++] = x % 256;
            x /= 256;
        }

        size_t decrypted_len = *decrypted_size - decrypted_offset;
        int r = crypto_chacha20poly1305_decrypt(
            context->write_key, nonce, payload+payload_offset, 2,
            payload+payload_offset+2, chunk_size + 16,
            decrypted, &decrypted_len
        );
        if (r) {
            ERROR("Failed to chacha decrypt payload (code %d)", r);
            return -1;
        }

        decrypted_offset += decrypted_len;
        payload_offset += chunk_size + 18;
    }

    return payload_offset;
}


void homekit_setup_mdns(homekit_server_t *server);


void client_sendv(client_context_t *context, uint8_t n, const byte **data, size_t *data_sizes) {
#if HOMEKIT_DEBUG
    size_t data_size = 0;
    for (uint8_t i=0; i < n; i++)
        data_size += data_sizes[i];

    if (data_size < 4096) {
        char *payload = binary_to_stringv(n, data, data_sizes);
        if (payload) {
            CLIENT_DEBUG(context, "Sending payload: %s", payload);
            free(payload);
        } else {
            CLIENT_DEBUG(context, "Sending payload of size %d", data_size);
        }
    }
#endif

    if (context->encrypted) {
        int r = client_send_encryptedv(context, n, data, data_sizes);
        if (r) {
            CLIENT_ERROR(context, "Failed to encrypt response (code %d)", r);
            return;
        }
    } else {
        // 5 parts should be enough to send everything at one go in all existing
        // cases, but just in case implementing chunked sending
        struct iovec parts[5];
        for (uint8_t i=0; i < n;) {
            uint8_t _n = (n - i > 4) ? 4 : n - i;
            for (uint8_t j=0; j < _n; i++, j++) {
                parts[j].iov_base = (void *)data[i];
                parts[j].iov_len = data_sizes[i];
            }

            lwip_writev(context->socket, parts, _n);
        }
    }
}


void client_send(client_context_t *context, byte *data, size_t data_size) {
    client_sendv(context, 1, (const byte*[]){ data }, (size_t[]){ data_size });
}


void client_send_chunk(byte *data, size_t size, void *arg) {
    client_context_t *context = arg;

    byte chunk_header[8];
    size_t chunk_header_size = snprintf((char *)chunk_header, sizeof(chunk_header), "%x\r\n", size);

    client_sendv(context, 3,
                 (const byte*[]){chunk_header, data, (byte*)"\r\n"},
                 (size_t[]){chunk_header_size, size, 2});
}


void send_204_response(client_context_t *context) {
    static char response[] = "HTTP/1.1 204 No Content\r\n\r\n";
    client_send(context, (byte *)response, sizeof(response)-1);
}

void send_404_response(client_context_t *context) {
    static char response[] = "HTTP/1.1 404 Not Found\r\n\r\n";
    client_send(context, (byte *)response, sizeof(response)-1);
}


typedef struct _client_event {
    const homekit_characteristic_t *characteristic;
    homekit_value_t value;
} client_event_t;


static byte tlv_200_response_headers[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/pairing+tlv8\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n\r\n";


tlv_stream_t *client_start_tlv_response(client_context_t *context) {
    client_send(context, tlv_200_response_headers, sizeof(tlv_200_response_headers)-1);

    tlv_stream_t *tlv = &context->server->tlv_stream;
    tlv_stream_set_context(tlv, context);
    tlv_stream_reset(tlv);

    return tlv;
}

void client_finish_tlv_response(client_context_t *context) {
    tlv_stream_flush(&context->server->tlv_stream);
    client_send_chunk(NULL, 0, context);
}

void send_tlv_error_response(client_context_t *context, int state, TLVError error) {
    tlv_stream_t *tlv = client_start_tlv_response(context);

    tlv_stream_add_integer_value(tlv, TLVType_State, 1, state);
    tlv_stream_add_integer_value(tlv, TLVType_Error, 1, error);

    client_finish_tlv_response(context);
}


static byte json_200_response_headers[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/hap+json\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n\r\n";


static byte json_207_response_headers[] =
    "HTTP/1.1 207 Multi-Status\r\n"
    "Content-Type: application/hap+json\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n\r\n";


void send_json_response(client_context_t *context, int status_code, byte *payload, size_t payload_size) {
    CLIENT_DEBUG(context, "Sending JSON response");
    DEBUG_HEAP();

    static char *http_headers =
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/hap+json\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n\r\n";

    CLIENT_DEBUG(context, "Payload: %s", payload);

    const char *status_text = "OK";
    switch (status_code) {
        case 204: status_text = "No Content"; break;
        case 207: status_text = "Multi-Status"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        case 422: status_text = "Unprocessable Entity"; break;
        case 500: status_text = "Internal Server Error"; break;
        case 503: status_text = "Service Unavailable"; break;
    }

    int response_size = strlen(http_headers) + payload_size + strlen(status_text) + 32;
    char *response = malloc(response_size);
    if (!response) {
        CLIENT_ERROR(context, "Failed to allocate %d bytes for response buffer", response_size);
        return;
    }
    int response_len = snprintf(response, response_size, http_headers, status_code, status_text, payload_size);

    if (response_size - response_len < payload_size + 1) {
        CLIENT_ERROR(context, "Incorrect response buffer size %d: headers took %d, payload size %d", response_size, response_len, payload_size);
        free(response);
        return;
    }
    memcpy(response+response_len, payload, payload_size);
    response_len += payload_size;
    response[response_len] = 0;  // required for debug output

    CLIENT_DEBUG(context, "Sending HTTP response: %s", response);

    client_send(context, (byte *)response, response_len);

    free(response);
}


void send_json_error_response(client_context_t *context, int status_code, HAPStatus status) {
    byte buffer[32];
    int size = snprintf((char *)buffer, sizeof(buffer), "{\"status\": %d}", status);

    send_json_response(context, status_code, buffer, size);
}


static client_context_t *current_client_context = NULL;

homekit_client_id_t homekit_get_client_id() {
    return (homekit_client_id_t)current_client_context;
}

bool homekit_client_is_admin() {
    if (!current_client_context)
        return false;

    return current_client_context->permissions & pairing_permissions_admin;
}

int homekit_client_send(unsigned char *data, size_t size) {
    if (!current_client_context)
        return -1;

    client_send(current_client_context, data, size);

    return 0;
}


void homekit_server_on_identify(client_context_t *context) {
    CLIENT_INFO(context, "Identify");
    DEBUG_HEAP();

    if (context->server->paired) {
        // Already paired
        send_json_error_response(context, 400, HAPStatus_InsufficientPrivileges);
        return;
    }

    send_204_response(context);

    homekit_accessory_t *accessory =
        homekit_accessory_by_id(context->server->config->accessories, 1);
    if (!accessory) {
        return;
    }

    homekit_service_t *accessory_info =
        homekit_service_by_type(accessory, HOMEKIT_SERVICE_ACCESSORY_INFORMATION);
    if (!accessory_info) {
        return;
    }

    homekit_characteristic_t *ch_identify =
        homekit_service_characteristic_by_type(accessory_info, HOMEKIT_CHARACTERISTIC_IDENTIFY);
    if (!ch_identify) {
        return;
    }

    if (ch_identify->setter_ex) {
        ch_identify->setter_ex(ch_identify, HOMEKIT_BOOL(true));
    }
}

void homekit_server_on_pair_setup(client_context_t *context, const byte *data, size_t size) {
    DEBUG("Pair Setup");
    DEBUG_HEAP();

#ifdef HOMEKIT_OVERCLOCK_PAIR_SETUP
    homekit_overclock_start();
#endif

    tlv_values_t *message = tlv_new();
    if (!message) {
        CLIENT_ERROR(context, "Failed to allocate memory for TLV payload");
        send_tlv_error_response(context, 2, TLVError_Unknown);
        return;
    }
    if (tlv_parse(data, size, message)) {
        CLIENT_ERROR(context, "Failed to parse TLV payload");
        tlv_free(message);
        send_tlv_error_response(context, 2, TLVError_Unknown);
        return;
    }

    TLV_DEBUG(message);

    switch(tlv_get_integer_value(message, TLVType_State, -1)) {
        case 1: {
            CLIENT_INFO(context, "Pair Setup Step 1/3");
            DEBUG_HEAP();
            if (context->server->paired) {
                CLIENT_INFO(context, "Refusing to pair: already paired");
                send_tlv_error_response(context, 2, TLVError_Unavailable);
                break;
            }

            if (context->server->pairing_context) {
                if (context->server->pairing_context->client != context) {
                    CLIENT_INFO(context, "Refusing to pair: another pairing in progress");
                    send_tlv_error_response(context, 2, TLVError_Busy);
                    break;
                }
            } else {
                context->server->pairing_context = pairing_context_new();
                if (!context->server->pairing_context) {
                    CLIENT_ERROR(context, "Refusing to pair: failed to allocate memory for pairing context");
                    send_tlv_error_response(context, 2, TLVError_Unknown);
                    break;
                }
                context->server->pairing_context->client = context;
            }

            CLIENT_DEBUG(context, "Initializing crypto");
            DEBUG_HEAP();

            char password[11];
            if (context->server->config->password) {
                strncpy(password, context->server->config->password, sizeof(password));
                CLIENT_DEBUG(context, "Using user-specified password: %s", password);
            } else {
                for (int i=0; i<10; i++) {
                    password[i] = homekit_random() % 10 + '0';
                }
                password[3] = password[6] = '-';
                password[10] = 0;
                CLIENT_DEBUG(context, "Using random password: %s", password);
            }

            if (context->server->config->password_callback) {
                context->server->config->password_callback(password);
            }

            crypto_srp_init(
                context->server->pairing_context->srp,
                "Pair-Setup", password
            );

            if (context->server->pairing_context->public_key) {
                free(context->server->pairing_context->public_key);
                context->server->pairing_context->public_key = NULL;
            }
            context->server->pairing_context->public_key_size = 0;
            crypto_srp_get_public_key(context->server->pairing_context->srp, NULL, &context->server->pairing_context->public_key_size);

            context->server->pairing_context->public_key = malloc(context->server->pairing_context->public_key_size);
            if (!context->server->pairing_context->public_key) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for dumping SPR public key",
                             context->server->pairing_context->public_key_size);

                pairing_context_free(context->server->pairing_context);
                context->server->pairing_context = NULL;

                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            int r = crypto_srp_get_public_key(context->server->pairing_context->srp, context->server->pairing_context->public_key, &context->server->pairing_context->public_key_size);
            if (r) {
                CLIENT_ERROR(context, "Failed to dump SPR public key (code %d)", r);

                pairing_context_free(context->server->pairing_context);
                context->server->pairing_context = NULL;

                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            size_t salt_size = 0;
            crypto_srp_get_salt(context->server->pairing_context->srp, NULL, &salt_size);

            byte *salt = malloc(salt_size);
            if (!salt) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for salt", salt_size);

                pairing_context_free(context->server->pairing_context);
                context->server->pairing_context = NULL;

                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            r = crypto_srp_get_salt(context->server->pairing_context->srp, salt, &salt_size);
            if (r) {
                CLIENT_ERROR(context, "Failed to get salt (code %d)", r);

                free(salt);
                pairing_context_free(context->server->pairing_context);
                context->server->pairing_context = NULL;

                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            tlv_stream_t *tlv = client_start_tlv_response(context);

            tlv_stream_add_value(tlv, TLVType_PublicKey, context->server->pairing_context->public_key, context->server->pairing_context->public_key_size);
            tlv_stream_add_value(tlv, TLVType_Salt, salt, salt_size);
            tlv_stream_add_integer_value(tlv, TLVType_State, 1, 2);

            client_finish_tlv_response(context);

            free(salt);

            break;
        }
        case 3: {
            CLIENT_INFO(context, "Pair Setup Step 2/3");
            DEBUG_HEAP();
            tlv_t *device_public_key = tlv_get_value(message, TLVType_PublicKey);
            if (!device_public_key) {
                CLIENT_ERROR(context, "Invalid payload: no device public key");
                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            tlv_t *proof = tlv_get_value(message, TLVType_Proof);
            if (!proof) {
                CLIENT_ERROR(context, "Invalid payload: no device proof");
                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            CLIENT_DEBUG(context, "Computing SRP shared secret");
            DEBUG_HEAP();
            int r = crypto_srp_compute_key(
                context->server->pairing_context->srp,
                device_public_key->value, device_public_key->size,
                context->server->pairing_context->public_key,
                context->server->pairing_context->public_key_size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to compute SRP shared secret (code %d)", r);
                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            free(context->server->pairing_context->public_key);
            context->server->pairing_context->public_key = NULL;
            context->server->pairing_context->public_key_size = 0;

            CLIENT_DEBUG(context, "Verifying peer's proof");
            DEBUG_HEAP();
            r = crypto_srp_verify(context->server->pairing_context->srp, proof->value, proof->size);
            if (r) {
                CLIENT_ERROR(context, "Failed to verify peer's proof (code %d)", r);
                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            CLIENT_DEBUG(context, "Generating own proof");
            size_t server_proof_size = 0;
            crypto_srp_get_proof(context->server->pairing_context->srp, NULL, &server_proof_size);

            byte *server_proof = malloc(server_proof_size);
            if (!server_proof) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for own proof", server_proof_size);
                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            r = crypto_srp_get_proof(context->server->pairing_context->srp, server_proof, &server_proof_size);

            tlv_stream_t *tlv = client_start_tlv_response(context);

            tlv_stream_add_integer_value(tlv, TLVType_State, 1, 4);
            tlv_stream_add_value(tlv, TLVType_Proof, server_proof, server_proof_size);

            client_finish_tlv_response(context);

            free(server_proof);

            break;
        }
        case 5: {
            CLIENT_INFO(context, "Pair Setup Step 3/3");
            DEBUG_HEAP();

            int r;

            byte shared_secret[HKDF_HASH_SIZE];
            size_t shared_secret_size = sizeof(shared_secret);

            CLIENT_DEBUG(context, "Calculating shared secret");
            const char salt1[] = "Pair-Setup-Encrypt-Salt";
            const char info1[] = "Pair-Setup-Encrypt-Info";
            r = crypto_srp_hkdf(
                context->server->pairing_context->srp,
                (byte *)salt1, sizeof(salt1)-1,
                (byte *)info1, sizeof(info1)-1,
                shared_secret, &shared_secret_size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to generate shared secret (code %d)", r);
                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            tlv_t *tlv_encrypted_data = tlv_get_value(message, TLVType_EncryptedData);
            if (!tlv_encrypted_data) {
                CLIENT_ERROR(context, "Invalid payload: no encrypted data");
                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            CLIENT_DEBUG(context, "Decrypting payload");
            size_t decrypted_data_size = 0;
            crypto_chacha20poly1305_decrypt(
                shared_secret, (byte *)"\x0\x0\x0\x0PS-Msg05", NULL, 0,
                tlv_encrypted_data->value, tlv_encrypted_data->size,
                NULL, &decrypted_data_size
            );

            byte *decrypted_data = malloc(decrypted_data_size);
            if (!decrypted_data) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for decrypting data",
                             decrypted_data_size);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            r = crypto_chacha20poly1305_decrypt(
                shared_secret, (byte *)"\x0\x0\x0\x0PS-Msg05", NULL, 0,
                tlv_encrypted_data->value, tlv_encrypted_data->size,
                decrypted_data, &decrypted_data_size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to decrypt data (code %d)", r);

                free(decrypted_data);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            tlv_values_t *decrypted_message = tlv_new();
            if (!decrypted_message) {
                CLIENT_ERROR(context, "Failed to allocate memory for decrypted TLV");

                free(decrypted_data);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            r = tlv_parse(decrypted_data, decrypted_data_size, decrypted_message);
            if (r) {
                CLIENT_ERROR(context, "Failed to parse decrypted TLV (code %d)", r);

                tlv_free(decrypted_message);
                free(decrypted_data);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            free(decrypted_data);

            tlv_t *tlv_device_id = tlv_get_value(decrypted_message, TLVType_Identifier);
            if (!tlv_device_id) {
                CLIENT_ERROR(context, "Invalid encrypted payload: no device identifier");

                tlv_free(decrypted_message);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            // TODO: check that tlv_device_id->size == 36

            tlv_t *tlv_device_public_key = tlv_get_value(decrypted_message, TLVType_PublicKey);
            if (!tlv_device_public_key) {
                CLIENT_ERROR(context, "Invalid encrypted payload: no device public key");

                tlv_free(decrypted_message);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            tlv_t *tlv_device_signature = tlv_get_value(decrypted_message, TLVType_Signature);
            if (!tlv_device_signature) {
                CLIENT_ERROR(context, "Invalid encrypted payload: no device signature");

                tlv_free(decrypted_message);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            CLIENT_DEBUG(context, "Importing device public key");

            ed25519_key device_key;
            crypto_ed25519_init(&device_key);
            r = crypto_ed25519_import_public_key(
                &device_key,
                tlv_device_public_key->value, tlv_device_public_key->size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to import device public Key (code %d)", r);

                tlv_free(decrypted_message);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            byte device_x[HKDF_HASH_SIZE];
            size_t device_x_size = sizeof(device_x);

            CLIENT_DEBUG(context, "Calculating DeviceX");
            const char salt2[] = "Pair-Setup-Controller-Sign-Salt";
            const char info2[] = "Pair-Setup-Controller-Sign-Info";
            r = crypto_srp_hkdf(
                context->server->pairing_context->srp,
                (byte *)salt2, sizeof(salt2)-1,
                (byte *)info2, sizeof(info2)-1,
                device_x, &device_x_size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to generate DeviceX (code %d)", r);

                tlv_free(decrypted_message);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            size_t device_info_size = device_x_size + tlv_device_id->size + tlv_device_public_key->size;
            byte *device_info = malloc(device_info_size);
            if (!device_info) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for DeviceX", device_info_size);

                tlv_free(decrypted_message);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            memcpy(device_info,
                   device_x,
                   device_x_size);
            memcpy(device_info + device_x_size,
                   tlv_device_id->value,
                   tlv_device_id->size);
            memcpy(device_info + device_x_size + tlv_device_id->size,
                   tlv_device_public_key->value,
                   tlv_device_public_key->size);

            CLIENT_DEBUG(context, "Verifying device signature");
            r = crypto_ed25519_verify(
                &device_key,
                device_info, device_info_size,
                tlv_device_signature->value, tlv_device_signature->size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to generate DeviceX (code %d)", r);

                free(device_info);
                tlv_free(decrypted_message);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            free(device_info);

            r = homekit_storage_add_pairing(
                (const char *)tlv_device_id->value, &device_key, pairing_permissions_admin
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to store pairing (code %d)", r);

                tlv_free(decrypted_message);
                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            INFO("Added pairing with %.*s", tlv_device_id->size, (char *)tlv_device_id->value);

            tlv_free(decrypted_message);

            HOMEKIT_NOTIFY_EVENT(context->server, HOMEKIT_EVENT_PAIRING_ADDED);

            CLIENT_DEBUG(context, "Exporting accessory public key");
            size_t accessory_public_key_size = 0;
            crypto_ed25519_export_public_key(&context->server->accessory_key, NULL, &accessory_public_key_size);

            byte *accessory_public_key = malloc(accessory_public_key_size);
            if (!accessory_public_key) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for accessory public key",
                             accessory_public_key_size);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            r = crypto_ed25519_export_public_key(&context->server->accessory_key, accessory_public_key, &accessory_public_key_size);
            if (r) {
                CLIENT_ERROR(context, "Failed to export accessory public key (code %d)", r);

                free(accessory_public_key);

                send_tlv_error_response(context, 6, TLVError_Authentication);
                break;
            }

            size_t accessory_id_size = sizeof(context->server->accessory_id) - 1;
            size_t accessory_info_size = HKDF_HASH_SIZE + accessory_id_size + accessory_public_key_size;
            byte *accessory_info = malloc(accessory_info_size);
            if (!accessory_info) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for AccessoryX",
                             accessory_info_size);

                free(accessory_public_key);

                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            CLIENT_DEBUG(context, "Calculating AccessoryX");
            size_t accessory_x_size = accessory_info_size;
            const char salt3[] = "Pair-Setup-Accessory-Sign-Salt";
            const char info3[] = "Pair-Setup-Accessory-Sign-Info";
            r = crypto_srp_hkdf(
                context->server->pairing_context->srp,
                (byte *)salt3, sizeof(salt3)-1,
                (byte *)info3, sizeof(info3)-1,
                accessory_info, &accessory_x_size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to generate AccessoryX (code %d)", r);

                free(accessory_info);
                free(accessory_public_key);

                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            memcpy(accessory_info + accessory_x_size,
                   context->server->accessory_id, accessory_id_size);
            memcpy(accessory_info + accessory_x_size + accessory_id_size,
                   accessory_public_key, accessory_public_key_size);

            CLIENT_DEBUG(context, "Generating accessory signature");
            DEBUG_HEAP();
            size_t accessory_signature_size = 0;
            crypto_ed25519_sign(
                &context->server->accessory_key,
                accessory_info, accessory_info_size,
                NULL, &accessory_signature_size
            );

            byte *accessory_signature = malloc(accessory_signature_size);
            if (!accessory_signature) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for accessory signature",
                             accessory_signature_size);

                free(accessory_public_key);
                free(accessory_info);

                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            r = crypto_ed25519_sign(
                &context->server->accessory_key,
                accessory_info, accessory_info_size,
                accessory_signature, &accessory_signature_size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to generate accessory signature (code %d)", r);

                free(accessory_signature);
                free(accessory_public_key);
                free(accessory_info);

                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            free(accessory_info);

            tlv_values_t *response_message = tlv_new();
            if (!response_message) {
                CLIENT_ERROR(context, "Failed to allocate memory for TLV response");

                free(accessory_signature);
                free(accessory_public_key);

                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            tlv_add_value(response_message, TLVType_Identifier,
                          (byte *)context->server->accessory_id, accessory_id_size);
            tlv_add_value(response_message, TLVType_PublicKey,
                          accessory_public_key, accessory_public_key_size);
            tlv_add_value(response_message, TLVType_Signature,
                          accessory_signature, accessory_signature_size);

            free(accessory_public_key);
            free(accessory_signature);

            size_t response_data_size = 0;
            TLV_DEBUG(response_message);

            tlv_format(response_message, NULL, &response_data_size);

            byte *response_data = malloc(response_data_size);
            if (!response_data) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for TLV response",
                             response_data_size);

                tlv_free(response_message);

                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            r = tlv_format(response_message, response_data, &response_data_size);
            if (r) {
                CLIENT_ERROR(context, "Failed to format TLV response (code %d)", r);

                free(response_data);
                tlv_free(response_message);

                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            tlv_free(response_message);

            CLIENT_DEBUG(context, "Encrypting response");
            size_t encrypted_response_data_size = 0;
            crypto_chacha20poly1305_encrypt(
                shared_secret, (byte *)"\x0\x0\x0\x0PS-Msg06", NULL, 0,
                response_data, response_data_size,
                NULL, &encrypted_response_data_size
            );

            byte *encrypted_response_data = malloc(encrypted_response_data_size);
            if (!encrypted_response_data) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for encrypted response data",
                             encrypted_response_data_size);

                free(response_data);

                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            r = crypto_chacha20poly1305_encrypt(
                shared_secret, (byte *)"\x0\x0\x0\x0PS-Msg06", NULL, 0,
                response_data, response_data_size,
                encrypted_response_data, &encrypted_response_data_size
            );

            free(response_data);

            if (r) {
                CLIENT_ERROR(context, "Failed to encrypt response data (code %d)", r);

                free(encrypted_response_data);

                send_tlv_error_response(context, 6, TLVError_Unknown);
                break;
            }

            tlv_stream_t *tlv = client_start_tlv_response(context);

            tlv_stream_add_integer_value(tlv, TLVType_State, 1, 6);
            tlv_stream_add_value(tlv, TLVType_EncryptedData,
                                 encrypted_response_data,
                                 encrypted_response_data_size);

            client_finish_tlv_response(context);

            free(encrypted_response_data);

            pairing_context_free(context->server->pairing_context);
            context->server->pairing_context = NULL;

            context->server->paired = 1;
            homekit_setup_mdns(context->server);

            CLIENT_INFO(context, "Successfully paired");

            break;
        }
        default: {
            CLIENT_ERROR(context, "Unknown state: %d",
                  tlv_get_integer_value(message, TLVType_State, -1));
        }
    }

    tlv_free(message);

#ifdef HOMEKIT_OVERCLOCK_PAIR_SETUP
    homekit_overclock_end();
#endif
}

void homekit_server_on_pair_verify(client_context_t *context, const byte *data, size_t size) {
    DEBUG("HomeKit Pair Verify");
    DEBUG_HEAP();

#ifdef HOMEKIT_OVERCLOCK_PAIR_VERIFY
    homekit_overclock_start();
#endif

    int r;

    tlv_values_t *message = tlv_new();
    if (!message) {
        CLIENT_ERROR(context, "Failed to allocate memory for TLV payload");
        return;
    }

    r = tlv_parse(data, size, message);
    if (r) {
        CLIENT_ERROR(context, "Failed to parse TLV payload (code %d)", r);
        tlv_free(message);
        return;
    }

    TLV_DEBUG(message);

    switch(tlv_get_integer_value(message, TLVType_State, -1)) {
        case 1: {
            CLIENT_INFO(context, "Pair Verify Step 1/2");

            CLIENT_DEBUG(context, "Importing device Curve25519 public key");
            tlv_t *tlv_device_public_key = tlv_get_value(message, TLVType_PublicKey);
            if (!tlv_device_public_key) {
                CLIENT_ERROR(context, "Device Curve25519 public key not found");
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }
            curve25519_key device_key;
            r = crypto_curve25519_init(&device_key);
            if (r) {
                CLIENT_ERROR(context, "Failed to initialize device Curve25519 public key (code %d)", r);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            r = crypto_curve25519_import_public(
                &device_key,
                tlv_device_public_key->value, tlv_device_public_key->size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to import device Curve25519 public key (code %d)", r);
                crypto_curve25519_done(&device_key);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            CLIENT_DEBUG(context, "Generating accessory Curve25519 key");

            curve25519_key my_key;
            r = crypto_curve25519_generate(&my_key);
            if (r) {
                CLIENT_ERROR(context, "Failed to generate accessory Curve25519 key (code %d)", r);
                crypto_curve25519_done(&device_key);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            CLIENT_DEBUG(context, "Exporting accessory Curve25519 public key");
            size_t my_key_public_size = 0;
            crypto_curve25519_export_public(&my_key, NULL, &my_key_public_size);

            byte *my_key_public = malloc(my_key_public_size);
            if (!my_key_public) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for exporting accessory Curve25519 public key",
                             my_key_public_size);
                crypto_curve25519_done(&my_key);
                crypto_curve25519_done(&device_key);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            r = crypto_curve25519_export_public(&my_key, my_key_public, &my_key_public_size);
            if (r) {
                CLIENT_ERROR(context, "Failed to export accessory Curve25519 public key (code %d)", r);
                free(my_key_public);
                crypto_curve25519_done(&my_key);
                crypto_curve25519_done(&device_key);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            CLIENT_DEBUG(context, "Generating Curve25519 shared secret");
            size_t shared_secret_size = 0;
            crypto_curve25519_shared_secret(&my_key, &device_key, NULL, &shared_secret_size);

            byte *shared_secret = malloc(shared_secret_size);
            if (!shared_secret) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for Curve25519 shared secret",
                             shared_secret_size);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            r = crypto_curve25519_shared_secret(&my_key, &device_key, shared_secret, &shared_secret_size);
            crypto_curve25519_done(&my_key);
            crypto_curve25519_done(&device_key);

            if (r) {
                CLIENT_ERROR(context, "Failed to generate Curve25519 shared secret (code %d)", r);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            CLIENT_DEBUG(context, "Generating signature");
            size_t accessory_id_size = sizeof(context->server->accessory_id) - 1;
            size_t accessory_info_size = my_key_public_size + accessory_id_size + tlv_device_public_key->size;

            byte *accessory_info = malloc(accessory_info_size);
            if (!accessory_info) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for accessory info",
                             accessory_info_size);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            memcpy(accessory_info,
                   my_key_public, my_key_public_size);
            memcpy(accessory_info + my_key_public_size,
                   context->server->accessory_id, accessory_id_size);
            memcpy(accessory_info + my_key_public_size + accessory_id_size,
                   tlv_device_public_key->value, tlv_device_public_key->size);

            size_t accessory_signature_size = 0;
            crypto_ed25519_sign(
                &context->server->accessory_key,
                accessory_info, accessory_info_size,
                NULL, &accessory_signature_size
            );

            byte *accessory_signature = malloc(accessory_signature_size);
            if (!accessory_signature) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for accessory signature",
                             accessory_signature_size);
                free(accessory_info);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            r = crypto_ed25519_sign(
                &context->server->accessory_key,
                accessory_info, accessory_info_size,
                accessory_signature, &accessory_signature_size
            );
            free(accessory_info);
            if (r) {
                CLIENT_ERROR(context, "Failed to generate signature (code %d)", r);
                free(accessory_signature);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            tlv_values_t *sub_response = tlv_new();
            if (!sub_response) {
                CLIENT_ERROR(context, "Failed to allocate memory for TLV sub response");
                free(accessory_signature);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }
            tlv_add_value(sub_response, TLVType_Identifier,
                          (const byte *)context->server->accessory_id, accessory_id_size);
            tlv_add_value(sub_response, TLVType_Signature,
                          accessory_signature, accessory_signature_size);

            free(accessory_signature);

            size_t sub_response_data_size = 0;
            tlv_format(sub_response, NULL, &sub_response_data_size);

            byte *sub_response_data = malloc(sub_response_data_size);
            if (!sub_response_data) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for sub-TLV message",
                             sub_response_data_size);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            r = tlv_format(sub_response, sub_response_data, &sub_response_data_size);
            tlv_free(sub_response);

            if (r) {
                CLIENT_ERROR(context, "Failed to format sub-TLV message (code %d)", r);
                free(sub_response_data);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            CLIENT_DEBUG(context, "Generating proof");
            size_t session_key_size = 0;
            const byte salt[] = "Pair-Verify-Encrypt-Salt";
            const byte info[] = "Pair-Verify-Encrypt-Info";
            crypto_hkdf(
                shared_secret, shared_secret_size,
                salt, sizeof(salt)-1,
                info, sizeof(info)-1,
                NULL, &session_key_size
            );

            byte *session_key = malloc(session_key_size);
            if (!session_key) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for session key",
                             session_key_size);
                free(sub_response_data);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            r = crypto_hkdf(
                shared_secret, shared_secret_size,
                salt, sizeof(salt)-1,
                info, sizeof(info)-1,
                session_key, &session_key_size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to derive session key (code %d)", r);
                free(session_key);
                free(sub_response_data);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            CLIENT_DEBUG(context, "Encrypting response");
            size_t encrypted_response_data_size = 0;
            crypto_chacha20poly1305_encrypt(
                session_key, (byte *)"\x0\x0\x0\x0PV-Msg02", NULL, 0,
                sub_response_data, sub_response_data_size,
                NULL, &encrypted_response_data_size
            );

            byte *encrypted_response_data = malloc(encrypted_response_data_size);
            if (!encrypted_response_data) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for encrypting sub response data",
                             encrypted_response_data_size);
                free(sub_response_data);
                free(session_key);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            r = crypto_chacha20poly1305_encrypt(
                session_key, (byte *)"\x0\x0\x0\x0PV-Msg02", NULL, 0,
                sub_response_data, sub_response_data_size,
                encrypted_response_data, &encrypted_response_data_size
            );
            free(sub_response_data);

            if (r) {
                CLIENT_ERROR(context, "Failed to encrypt sub response data (code %d)", r);
                free(encrypted_response_data);
                free(session_key);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            tlv_stream_t *tlv = client_start_tlv_response(context);

            tlv_stream_add_integer_value(tlv, TLVType_State, 1, 2);
            tlv_stream_add_value(tlv, TLVType_PublicKey,
                                 my_key_public, my_key_public_size);
            tlv_stream_add_value(tlv, TLVType_EncryptedData,
                                 encrypted_response_data,
                                 encrypted_response_data_size);

            client_finish_tlv_response(context);

            free(encrypted_response_data);

            if (context->verify_context)
                pair_verify_context_free(context->verify_context);

            context->verify_context = pair_verify_context_new();
            if (!context->verify_context) {
                CLIENT_ERROR(context, "Failed to allocate memory for verify context");
                free(session_key);
                free(shared_secret);
                free(my_key_public);
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }
            context->verify_context->secret = shared_secret;
            context->verify_context->secret_size = shared_secret_size;

            context->verify_context->session_key = session_key;
            context->verify_context->session_key_size = session_key_size;

            context->verify_context->accessory_public_key = my_key_public;
            context->verify_context->accessory_public_key_size = my_key_public_size;

            context->verify_context->device_public_key = malloc(tlv_device_public_key->size);
            if (!context->verify_context->device_public_key) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for device public key",
                             tlv_device_public_key->size);
                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }
            memcpy(context->verify_context->device_public_key,
                   tlv_device_public_key->value, tlv_device_public_key->size);
            context->verify_context->device_public_key_size = tlv_device_public_key->size;

            break;
        }
        case 3: {
            CLIENT_INFO(context, "Pair Verify Step 2/2");

            if (!context->verify_context) {
                CLIENT_ERROR(context, "Failed to verify: no state 1 data");
                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            tlv_t *tlv_encrypted_data = tlv_get_value(message, TLVType_EncryptedData);
            if (!tlv_encrypted_data) {
                CLIENT_ERROR(context, "Failed to verify: no encrypted data");

                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            CLIENT_DEBUG(context, "Decrypting payload");
            size_t decrypted_data_size = 0;
            crypto_chacha20poly1305_decrypt(
                context->verify_context->session_key, (byte *)"\x0\x0\x0\x0PV-Msg03", NULL, 0,
                tlv_encrypted_data->value, tlv_encrypted_data->size,
                NULL, &decrypted_data_size
            );

            byte *decrypted_data = malloc(decrypted_data_size);
            if (!decrypted_data) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for decrypt data",
                             decrypted_data_size);

                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            r = crypto_chacha20poly1305_decrypt(
                context->verify_context->session_key, (byte *)"\x0\x0\x0\x0PV-Msg03", NULL, 0,
                tlv_encrypted_data->value, tlv_encrypted_data->size,
                decrypted_data, &decrypted_data_size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to decrypt data (code %d)", r);

                free(decrypted_data);
                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            tlv_values_t *decrypted_message = tlv_new();
            if (!decrypted_message) {
                CLIENT_ERROR(context, "Failed to allocate memory for decrypted message");

                free(decrypted_data);
                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }
            r = tlv_parse(decrypted_data, decrypted_data_size, decrypted_message);
            free(decrypted_data);

            if (r) {
                CLIENT_ERROR(context, "Failed to parse decrypted TLV (code %d)", r);

                tlv_free(decrypted_message);
                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            tlv_t *tlv_device_id = tlv_get_value(decrypted_message, TLVType_Identifier);
            if (!tlv_device_id) {
                CLIENT_ERROR(context, "Invalid encrypted payload: no device identifier");

                tlv_free(decrypted_message);
                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            tlv_t *tlv_device_signature = tlv_get_value(decrypted_message, TLVType_Signature);
            if (!tlv_device_signature) {
                CLIENT_ERROR(context, "Invalid encrypted payload: no device identifier");

                tlv_free(decrypted_message);
                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            CLIENT_DEBUG(context, "Searching pairing with %.*s", tlv_device_id->size, tlv_device_id->value);
            pairing_t pairing;
            if (homekit_storage_find_pairing((const char *)tlv_device_id->value, &pairing)) {
                CLIENT_ERROR(context, "No pairing for %.*s found", tlv_device_id->size, tlv_device_id->value);

                tlv_free(decrypted_message);
                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            CLIENT_INFO(context, "Found pairing with %.*s", tlv_device_id->size, tlv_device_id->value);

            byte permissions = pairing.permissions;
            int pairing_id = pairing.id;

            size_t device_info_size =
                context->verify_context->device_public_key_size +
                context->verify_context->accessory_public_key_size +
                tlv_device_id->size;

            byte *device_info = malloc(device_info_size);
            if (!device_info) {
                CLIENT_ERROR(context, "Failed to allocate %d bytes for device info",
                             device_info_size);

                tlv_free(decrypted_message);
                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            memcpy(device_info,
                   context->verify_context->device_public_key, context->verify_context->device_public_key_size);
            memcpy(device_info + context->verify_context->device_public_key_size,
                   tlv_device_id->value, tlv_device_id->size);
            memcpy(device_info + context->verify_context->device_public_key_size + tlv_device_id->size,
                   context->verify_context->accessory_public_key, context->verify_context->accessory_public_key_size);

            CLIENT_DEBUG(context, "Verifying device signature");
            r = crypto_ed25519_verify(
                &pairing.device_key,
                device_info, device_info_size,
                tlv_device_signature->value, tlv_device_signature->size
            );
            free(device_info);
            tlv_free(decrypted_message);

            if (r) {
                CLIENT_ERROR(context, "Failed to verify device signature (code %d)", r);

                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Authentication);
                break;
            }

            const byte salt[] = "Control-Salt";

            size_t read_key_size = sizeof(context->read_key);
            const byte read_info[] = "Control-Read-Encryption-Key";
            r = crypto_hkdf(
                context->verify_context->secret, context->verify_context->secret_size,
                salt, sizeof(salt)-1,
                read_info, sizeof(read_info)-1,
                context->read_key, &read_key_size
            );

            if (r) {
                CLIENT_ERROR(context, "Failed to derive read encryption key (code %d)", r);

                pair_verify_context_free(context->verify_context);
                context->verify_context = NULL;

                send_tlv_error_response(context, 4, TLVError_Unknown);
                break;
            }

            size_t write_key_size = sizeof(context->write_key);
            const byte write_info[] = "Control-Write-Encryption-Key";
            r = crypto_hkdf(
                context->verify_context->secret, context->verify_context->secret_size,
                salt, sizeof(salt)-1,
                write_info, sizeof(write_info)-1,
                context->write_key, &write_key_size
            );

            pair_verify_context_free(context->verify_context);
            context->verify_context = NULL;

            if (r) {
                CLIENT_ERROR(context, "Failed to derive write encryption key (code %d)", r);

                send_tlv_error_response(context, 4, TLVError_Unknown);
                break;
            }

            tlv_stream_t *tlv = client_start_tlv_response(context);

            tlv_stream_add_integer_value(tlv, TLVType_State, 1, 4);

            client_finish_tlv_response(context);

            context->pairing_id = pairing_id;
            context->permissions = permissions;
            context->encrypted = true;

            HOMEKIT_NOTIFY_EVENT(context->server, HOMEKIT_EVENT_CLIENT_VERIFIED);

            CLIENT_INFO(context, "Verification successful, secure session established");

            break;
        }
        default: {
            CLIENT_ERROR(context, "Unknown state: %d",
                  tlv_get_integer_value(message, TLVType_State, -1));
        }
    }

    tlv_free(message);

#ifdef HOMEKIT_OVERCLOCK_PAIR_VERIFY
    homekit_overclock_end();
#endif
}


void homekit_server_on_get_accessories(client_context_t *context) {
    CLIENT_INFO(context, "Get Accessories");
    DEBUG_HEAP();

    client_send(context, json_200_response_headers, sizeof(json_200_response_headers)-1);

    json_stream *json = &context->server->json;
    json_set_context(json, context);
    json_reset(json);

    json_object_start(json);
    json_string(json, "accessories"); json_array_start(json);

    for (homekit_accessory_t **accessory_it = context->server->config->accessories; *accessory_it; accessory_it++) {
        homekit_accessory_t *accessory = *accessory_it;

        json_object_start(json);

        accessory_info_t *a_info = find_accessory_info(context->server, accessory);
        if (!a_info) {
            ERROR("Failed to lookup accessory info, skipping");
            continue;
        }

        json_string(json, "aid"); json_uint32(json, a_info->aid);
        json_string(json, "services"); json_array_start(json);

        for (homekit_service_t **service_it = accessory->services; *service_it; service_it++) {
            homekit_service_t *service = *service_it;

            json_object_start(json);

            service_info_t *s_info = find_service_info(context->server, service);
            if (!s_info) {
                ERROR("Failed to lookup service info for service type \"%s\", skipping", service->type);
                continue;
            }

            json_string(json, "iid"); json_uint32(json, s_info->iid);
            json_string(json, "type"); json_string(json, service->type);
            json_string(json, "hidden"); json_boolean(json, service->hidden);
            json_string(json, "primary"); json_boolean(json, service->primary);
            if (service->linked) {
                json_string(json, "linked"); json_array_start(json);
                for (homekit_service_t **linked=service->linked; *linked; linked++) {
                    service_info_t *linked_info = find_service_info(context->server, *linked);
                    if (!linked_info) {
                        ERROR("Failed to lookup service info for linked service of type \"%s\", skipping", (*linked)->type);
                        continue;
                    }
                    json_uint32(json, linked_info->iid);
                }
                json_array_end(json);
            }

            json_string(json, "characteristics"); json_array_start(json);

            for (homekit_characteristic_t **ch_it = service->characteristics; *ch_it; ch_it++) {
                homekit_characteristic_t *ch = *ch_it;

                json_object_start(json);

                homekit_value_t value = ch->getter_ex(ch);
                write_characteristic_json(
                    json, context, ch,
                      characteristic_format_type
                    | characteristic_format_meta
                    | characteristic_format_perms
                    | characteristic_format_events,
                    &value
                );
                homekit_value_destruct(&value);

                json_object_end(json);
            }

            json_array_end(json);
            json_object_end(json); // service
        }

        json_array_end(json);
        json_object_end(json); // accessory
    }

    json_array_end(json);
    json_object_end(json); // response

    json_flush(json);

    client_send_chunk(NULL, 0, context);
}

void homekit_server_on_get_characteristics(client_context_t *context) {
    CLIENT_INFO(context, "Get Characteristics");
    DEBUG_HEAP();

    if (context->server->endpoint_params.ids[0].aid == 0) {
        CLIENT_ERROR(context, "Invalid get characteristics request: missing ID parameter");
        send_json_error_response(context, 400, HAPStatus_InvalidValue);
        return;
    }


    bool success = true;

    int id_index = 0;
    while (id_index < countof(context->server->endpoint_params.ids) &&
           context->server->endpoint_params.ids[id_index].aid != 0) {
        uint16_t aid = context->server->endpoint_params.ids[id_index].aid;
        uint16_t iid = context->server->endpoint_params.ids[id_index].iid;

        id_index++;

        CLIENT_DEBUG(context, "Requested characteristic info for %d.%d", aid, iid);
        homekit_characteristic_t *ch = homekit_characteristic_by_aid_and_iid(context->server->config->accessories, aid, iid);
        if (!ch) {
            success = false;
            continue;
        }

        if (!(ch->permissions & homekit_permissions_paired_read)) {
            success = false;
            continue;
        }
    }

    if (success) {
        client_send(context, json_200_response_headers, sizeof(json_200_response_headers)-1);
    } else {
        client_send(context, json_207_response_headers, sizeof(json_207_response_headers)-1);
    }

    json_stream *json = &context->server->json;
    json_set_context(json, context);
    json_reset(json);

    json_object_start(json);
    json_string(json, "characteristics"); json_array_start(json);

    void write_characteristic_error(json_stream *json, int aid, int iid, int status) {
        json_object_start(json);
        json_string(json, "aid"); json_uint32(json, aid);
        json_string(json, "iid"); json_uint32(json, iid);
        json_string(json, "status"); json_uint8(json, status);
        json_object_end(json);
    }

    id_index = 0;
    while (id_index < countof(context->server->endpoint_params.ids) &&
           context->server->endpoint_params.ids[id_index].aid != 0) {
        uint16_t aid = context->server->endpoint_params.ids[id_index].aid;
        uint16_t iid = context->server->endpoint_params.ids[id_index].iid;

        homekit_characteristic_t *ch = homekit_characteristic_by_aid_and_iid(context->server->config->accessories, aid, iid);
        if (!ch) {
            CLIENT_ERROR(context, "Requested characteristic %d.%d not found", aid, iid);
            write_characteristic_error(json, aid, iid, HAPStatus_NoResource);
            continue;
        }

        if (!(ch->permissions & homekit_permissions_paired_read)) {
            CLIENT_ERROR(context, "Requested characteristic %d.%d is not readable", aid, iid);
            write_characteristic_error(json, aid, iid, HAPStatus_WriteOnly);
            continue;
        }

        CLIENT_INFO(context, "Requested characteristic info for %d.%d (\"%s\")", aid, iid, ch->description);

        json_object_start(json);

        homekit_value_t value = ch->getter_ex(ch);
        write_characteristic_json(json, context, ch, context->server->endpoint_params.format, &value);
        homekit_value_destruct(&value);

        if (!success) {
            json_string(json, "status"); json_uint8(json, HAPStatus_Success);
        }
        json_object_end(json);

        id_index++;
    }

    json_array_end(json);
    json_object_end(json); // response

    json_flush(json);

    client_send_chunk(NULL, 0, context);
}

void homekit_server_on_update_characteristics(client_context_t *context, const byte *data, size_t size) {
    CLIENT_INFO(context, "Update Characteristics");
    DEBUG_HEAP();

    cJSON *json = cJSON_Parse((char *)data);

    if (!json) {
        CLIENT_ERROR(context, "Failed to parse request JSON");
        send_json_error_response(context, 400, HAPStatus_InvalidValue);
        return;
    }

    cJSON *characteristics = cJSON_GetObjectItem(json, "characteristics");
    if (!characteristics) {
        CLIENT_ERROR(context, "Failed to parse request: no \"characteristics\" field");
        cJSON_Delete(json);
        send_json_error_response(context, 400, HAPStatus_InvalidValue);
        return;
    }
    if (characteristics->type != cJSON_Array) {
        CLIENT_ERROR(context, "Failed to parse request: \"characteristics\" field is not an list");
        cJSON_Delete(json);
        send_json_error_response(context, 400, HAPStatus_InvalidValue);
        return;
    }

    HAPStatus process_characteristics_update(const cJSON *j_ch) {
        cJSON *j_aid = cJSON_GetObjectItem(j_ch, "aid");
        if (!j_aid) {
            CLIENT_ERROR(context, "Failed to process request: no \"aid\" field");
            return HAPStatus_NoResource;
        }
        if (j_aid->type != cJSON_Number) {
            CLIENT_ERROR(context, "Failed to process request: \"aid\" field is not a number");
            return HAPStatus_NoResource;
        }

        cJSON *j_iid = cJSON_GetObjectItem(j_ch, "iid");
        if (!j_iid) {
            CLIENT_ERROR(context, "Failed to process request: no \"iid\" field");
            return HAPStatus_NoResource;
        }
        if (j_iid->type != cJSON_Number) {
            CLIENT_ERROR(context, "Failed to process request: \"iid\" field is not a number");
            return HAPStatus_NoResource;
        }

        int aid = j_aid->valueint;
        int iid = j_iid->valueint;

        homekit_characteristic_t *ch = homekit_characteristic_by_aid_and_iid(
            context->server->config->accessories, aid, iid
        );
        if (!ch) {
            CLIENT_ERROR(context, "Failed to process request to update %d.%d: "
                  "no such characteristic", aid, iid);
            return HAPStatus_NoResource;
        }

        cJSON *j_value = cJSON_GetObjectItem(j_ch, "value");
        if (j_value) {
            homekit_value_t h_value = HOMEKIT_NULL();

            if (!(ch->permissions & homekit_permissions_paired_write)) {
                CLIENT_ERROR(context, "Failed to update %d.%d: no write permission", aid, iid);
                return HAPStatus_ReadOnly;
            }

            switch (ch->format) {
                case homekit_format_bool: {
                    bool value = false;
                    if (j_value->type == cJSON_True) {
                        value = true;
                    } else if (j_value->type == cJSON_False) {
                        value = false;
                    } else if (j_value->type == cJSON_Number &&
                            (j_value->valueint == 0 || j_value->valueint == 1)) {
                        value = j_value->valueint == 1;
                    } else {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is not a boolean or 0/1", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    CLIENT_INFO(context, "Updating characteristic %d.%d (\"%s\") with boolean %s", aid, iid, ch->description, value ? "true" : "false");

                    h_value = HOMEKIT_BOOL(value);

                    break;
                }
                case homekit_format_uint8:
                case homekit_format_uint16:
                case homekit_format_uint32:
                case homekit_format_uint64:
                case homekit_format_int: {
                    // We accept boolean values here in order to fix a bug in HomeKit. HomeKit sometimes sends a boolean instead of an integer of value 0 or 1.
                    if (j_value->type != cJSON_Number && j_value->type != cJSON_False && j_value->type != cJSON_True) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is not a number", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    double min_value = 0;
                    double max_value = 0;

                    switch (ch->format) {
                        case homekit_format_uint8: {
                            min_value = 0;
                            max_value = 255;
                            break;
                        }
                        case homekit_format_uint16: {
                            min_value = 0;
                            max_value = 65535;
                            break;
                        }
                        case homekit_format_uint32: {
                            min_value = 0;
                            max_value = 4294967295;
                            break;
                        }
                        case homekit_format_uint64: {
                            min_value = 0;
                            max_value = 18446744073709551615ULL;
                            break;
                        }
                        case homekit_format_int: {
                            min_value = -2147483648;
                            max_value = 2147483647;
                            break;
                        }
                        default: {
                            // Impossible, keeping to make compiler happy
                            break;
                        }
                    }

                    if (ch->min_value)
                        min_value = *ch->min_value;
                    if (ch->max_value)
                        max_value = *ch->max_value;

                    double value = j_value->valuedouble;
                    if (j_value->type == cJSON_True) {
                        value = 1;
                    } else if (j_value->type == cJSON_False) {
                        value = 0;
                    }

                    if (value < min_value || value > max_value) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value %g is not in range %g..%g",
                                     aid, iid, value, min_value, max_value);
                        return HAPStatus_InvalidValue;
                    }

                    if (ch->valid_values.count) {
                        bool matches = false;
                        int v = (int)value;
                        for (int i=0; i<ch->valid_values.count; i++) {
                            if (v == ch->valid_values.values[i]) {
                                matches = true;
                                break;
                            }
                        }

                        if (!matches) {
                            CLIENT_ERROR(context, "Failed to update %d.%d: value is not one of valid values", aid, iid);
                            return HAPStatus_InvalidValue;
                        }
                    }

                    if (ch->valid_values_ranges.count) {
                        bool matches = false;
                        for (int i=0; i<ch->valid_values_ranges.count; i++) {
                            if (value >= ch->valid_values_ranges.ranges[i].start &&
                                    value <= ch->valid_values_ranges.ranges[i].end) {
                                matches = true;
                                break;
                            }
                        }

                        if (!matches) {
                            CLIENT_ERROR(context, "Failed to update %d.%d: value is not in valid values range", aid, iid);
                            return HAPStatus_InvalidValue;
                        }
                    }

                    CLIENT_INFO(context, "Updating characteristic %d.%d (\"%s\") with integer %g", aid, iid, ch->description, value);

                    switch (ch->format) {
                        case homekit_format_uint8:
                            h_value = HOMEKIT_UINT8(value);
                            break;
                        case homekit_format_uint16:
                            h_value = HOMEKIT_UINT16(value);
                            break;
                        case homekit_format_uint32:
                            h_value = HOMEKIT_UINT32(value);
                            break;
                        case homekit_format_uint64:
                            h_value = HOMEKIT_UINT64(value);
                            break;
                        case homekit_format_int:
                            h_value = HOMEKIT_INT(value);
                            break;

                        default:
                            CLIENT_ERROR(context, "Unexpected format when updating numeric value: %d", ch->format);
                            return HAPStatus_InvalidValue;
                    }

                    break;
                }
                case homekit_format_float: {
                    if (j_value->type != cJSON_Number) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is not a number", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    float value = j_value->valuedouble;
                    if ((ch->min_value && value < *ch->min_value) ||
                            (ch->max_value && value > *ch->max_value)) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is not in range", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    CLIENT_INFO(context, "Updating characteristic %d.%d (\"%s\") with %g", aid, iid, ch->description, value);

                    h_value = HOMEKIT_FLOAT(value);

                    break;
                }
                case homekit_format_string: {
                    if (j_value->type != cJSON_String) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is not a string", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    int max_len = (ch->max_len) ? *ch->max_len : 64;

                    char *value = j_value->valuestring;
                    if (strlen(value) > max_len) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is too long", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    CLIENT_INFO(context, "Updating characteristic %d.%d (\"%s\") with \"%s\"", aid, iid, ch->description, value);

                    h_value = HOMEKIT_STRING(value);

                    break;
                }
                case homekit_format_tlv: {
                    if (j_value->type != cJSON_String) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is not a string", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    int max_len = (ch->max_len) ? *ch->max_len : 256;

                    char *value = j_value->valuestring;
                    size_t value_len = strlen(value);
                    if (value_len > max_len) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is too long", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    size_t tlv_size = base64_decoded_size((unsigned char*)value, value_len);
                    byte *tlv_data = malloc(tlv_size);
                    if (!tlv_data) {
                        CLIENT_ERROR(context,
                                     "Failed to update %d.%d: "
                                     "error allocating %d bytes for Base64 decoding",
                                     aid, iid, tlv_size);
                        return HAPStatus_InvalidValue;
                    }
                    if (base64_decode((byte*) value, value_len, tlv_data) < 0) {
                        free(tlv_data);
                        CLIENT_ERROR(context, "Failed to update %d.%d: error Base64 decoding", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    tlv_values_t *tlv_values = tlv_new();
                    if (!tlv_values) {
                        free(tlv_data);
                        CLIENT_ERROR(context, "Failed to update %d.%d: error allocating memory for TLV values", aid, iid);
                        return HAPStatus_InvalidValue;
                    }
                    int r = tlv_parse(tlv_data, tlv_size, tlv_values);
                    free(tlv_data);

                    if (r) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: error parsing TLV", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    CLIENT_INFO(context, "Updating characteristic %d.%d (\"%s\") with TLV:", aid, iid, ch->description);
                    for (tlv_t *t=tlv_values->head; t; t=t->next) {
                        char *escaped_payload = binary_to_string(t->value, t->size);
                        CLIENT_DEBUG(context, "  Type %d value (%d bytes): %s", t->type, t->size, escaped_payload);
                        free(escaped_payload);
                    }

                    h_value = HOMEKIT_TLV(tlv_values);

                    tlv_free(tlv_values);
                    break;
                }
                case homekit_format_data: {
                    if (j_value->type != cJSON_String) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is not a string", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    // Default max data len = 2,097,152 but that does not make sense
                    // for this accessory
                    int max_len = (ch->max_data_len) ? *ch->max_data_len : 4096;

                    char *value = j_value->valuestring;
                    size_t value_len = strlen(value);
                    if (value_len > max_len) {
                        CLIENT_ERROR(context, "Failed to update %d.%d: value is too long", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    size_t data_size = base64_decoded_size((unsigned char*)value, value_len);
                    byte *data = malloc(data_size);
                    if (!data) {
                        CLIENT_ERROR(context,
                                     "Failed to update %d.%d: "
                                     "error allocating %d bytes for Base64 decoding",
                                     aid, iid, data_size);
                        return HAPStatus_InvalidValue;
                    }

                    if (base64_decode((byte*) value, value_len, data) < 0) {
                        free(data);
                        CLIENT_ERROR(context, "Failed to update %d.%d: error Base64 decoding", aid, iid);
                        return HAPStatus_InvalidValue;
                    }

                    CLIENT_INFO(context, "Updating characteristic %d.%d (\"%s\") with Data:", aid, iid, ch->description);

                    h_value = HOMEKIT_DATA(data, data_size);

                    break;
                }
                default: {
                    CLIENT_ERROR(context, "Failed to update %d.%d: unknown characteristic format %d", aid, iid, ch->format);
                    return HAPStatus_InvalidValue;
                }
            }

            ch->setter_ex(ch, h_value);
            homekit_characteristic_notify(ch, h_value);
        }

        cJSON *j_events = cJSON_GetObjectItem(j_ch, "ev");
        if (j_events) {
            if (!(ch->permissions && homekit_permissions_notify)) {
                CLIENT_ERROR(context, "Failed to set notification state for %d.%d: "
                      "notifications are not supported", aid, iid);
                return HAPStatus_NotificationsUnsupported;
            }

            if ((j_events->type != cJSON_True) && (j_events->type != cJSON_False)) {
                CLIENT_ERROR(context, "Failed to set notification state for %d.%d: "
                      "invalid state value", aid, iid);
            }

            if (j_events->type == cJSON_True) {
                client_subscribe_to_characteristic_events(context, ch);
                CLIENT_INFO(context, "Subscribed to notifications of characteristic %d.%d (\"%s\")", aid, iid, ch->description);
            } else {
                client_unsubscribe_from_characteristic_events(context, ch);
                CLIENT_INFO(context, "Unsubscribed from notifications of characteristic %d.%d (\"%s\")", aid, iid, ch->description);
            }
        }

        return HAPStatus_Success;
    }

    HAPStatus *statuses = malloc(sizeof(HAPStatus) * cJSON_GetArraySize(characteristics));
    if (!statuses) {
        CLIENT_ERROR(context, "Failed to allocate %d bytes for characteristic update statuses",
                     sizeof(HAPStatus) * cJSON_GetArraySize(characteristics));

        send_json_error_response(context, 500, HAPStatus_OutOfResources);
        cJSON_Delete(json);
        return;
    }
    bool has_errors = false;
    for (int i=0; i < cJSON_GetArraySize(characteristics); i++) {
        cJSON *j_ch = cJSON_GetArrayItem(characteristics, i);

        char *s = cJSON_Print(j_ch);
        CLIENT_DEBUG(context, "Processing element %s", s);
        free(s);

        statuses[i] = process_characteristics_update(j_ch);

        if (statuses[i] != HAPStatus_Success)
            has_errors = true;
    }

    if (!has_errors) {
        CLIENT_DEBUG(context, "There were no processing errors, sending No Content response");

        send_204_response(context);
    } else {
        json_stream *json1 = &context->server->json;
        json_set_context(json1, context);
        json_reset(json1);

        CLIENT_DEBUG(context, "There were processing errors, sending Multi-Status response");
        client_send(context, json_207_response_headers, sizeof(json_207_response_headers)-1);

        json_object_start(json1);
        json_string(json1, "characteristics"); json_array_start(json1);

        for (int i=0; i < cJSON_GetArraySize(characteristics); i++) {
            cJSON *j_ch = cJSON_GetArrayItem(characteristics, i);

            json_object_start(json1);
            json_string(json1, "aid"); json_uint32(json1, cJSON_GetObjectItem(j_ch, "aid")->valueint);
            json_string(json1, "iid"); json_uint32(json1, cJSON_GetObjectItem(j_ch, "iid")->valueint);
            json_string(json1, "status"); json_uint8(json1, statuses[i]);
            json_object_end(json1);
        }

        json_array_end(json1);
        json_object_end(json1); // response

        json_flush(json1);

        client_send_chunk(NULL, 0, context);
    }

    free(statuses);
    cJSON_Delete(json);
}

void homekit_server_on_pairings(client_context_t *context, const byte *data, size_t size) {
    DEBUG("HomeKit Pairings");
    DEBUG_HEAP();

    tlv_values_t *message = tlv_new();
    if (!message) {
        CLIENT_ERROR(context, "Failed to allocate memory for TLV payload");
        send_tlv_error_response(context, 2, TLVError_Unknown);
        return;
    }
    if (tlv_parse(data, size, message)) {
        CLIENT_ERROR(context, "Failed to parse TLV payload");
        tlv_free(message);
        send_tlv_error_response(context, 2, TLVError_Unknown);
        return;
    }

    TLV_DEBUG(message);

    int r;

    if (tlv_get_integer_value(message, TLVType_State, -1) != 1) {
        send_tlv_error_response(context, 2, TLVError_Unknown);
        tlv_free(message);
        return;
    }

    switch(tlv_get_integer_value(message, TLVType_Method, -1)) {
        case TLVMethod_AddPairing: {
            CLIENT_INFO(context, "Add Pairing");

            if (!(context->permissions & pairing_permissions_admin)) {
                CLIENT_ERROR(context, "Refusing to add pairing to non-admin controller");
                send_tlv_error_response(context, 2, TLVError_Authentication);
                break;
            }

            tlv_t *tlv_device_identifier = tlv_get_value(message, TLVType_Identifier);
            if (!tlv_device_identifier) {
                CLIENT_ERROR(context, "Invalid add pairing request: no device identifier");
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }
            tlv_t *tlv_device_public_key = tlv_get_value(message, TLVType_PublicKey);
            if (!tlv_device_public_key) {
                CLIENT_ERROR(context, "Invalid add pairing request: no device public key");
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }
            int device_permissions = tlv_get_integer_value(message, TLVType_Permissions, -1);
            if (device_permissions == -1) {
                CLIENT_ERROR(context, "Invalid add pairing request: no device permissions");
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            ed25519_key device_key;
            crypto_ed25519_init(&device_key);
            r = crypto_ed25519_import_public_key(
                &device_key, tlv_device_public_key->value, tlv_device_public_key->size
            );
            if (r) {
                CLIENT_ERROR(context, "Failed to import device public key");
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            pairing_t pairing;
            if (!homekit_storage_find_pairing((const char *)tlv_device_identifier->value, &pairing)) {
                size_t pairing_public_key_size = 0;
                crypto_ed25519_export_public_key(&pairing.device_key, NULL, &pairing_public_key_size);

                byte *pairing_public_key = malloc(pairing_public_key_size);
                if (!pairing_public_key) {
                    CLIENT_ERROR(context, "Failed to allocate %d bytes for pairing public key",
                                 pairing_public_key_size);
                    send_tlv_error_response(context, 2, TLVError_Unknown);
                    break;
                }

                r = crypto_ed25519_export_public_key(&pairing.device_key, pairing_public_key, &pairing_public_key_size);
                if (r) {
                    CLIENT_ERROR(context, "Failed to add pairing: error exporting pairing public key (code %d)", r);
                    free(pairing_public_key);
                    send_tlv_error_response(context, 2, TLVError_Unknown);
                    break;
                }

                if (pairing_public_key_size != tlv_device_public_key->size ||
                        memcmp(tlv_device_public_key->value, pairing_public_key, pairing_public_key_size)) {
                    CLIENT_ERROR(context, "Failed to add pairing: pairing public key differs from given one");
                    free(pairing_public_key);
                    send_tlv_error_response(context, 2, TLVError_Unknown);
                    break;
                }

                free(pairing_public_key);

                r = homekit_storage_update_pairing((const char *)tlv_device_identifier->value, device_permissions);
                if (r) {
                    CLIENT_ERROR(context, "Failed to add pairing: storage error (code %d)", r);
                    send_tlv_error_response(context, 2, TLVError_Unknown);
                    break;
                }

                INFO("Updated pairing with %.*s", tlv_device_identifier->size, tlv_device_identifier->value);
            } else {
                if (!homekit_storage_can_add_pairing()) {
                    CLIENT_ERROR(context, "Failed to add pairing: max peers");
                    send_tlv_error_response(context, 2, TLVError_MaxPeers);
                    break;
                }

                r = homekit_storage_add_pairing(
                    (const char *)tlv_device_identifier->value, &device_key, device_permissions
                );
                if (r) {
                    CLIENT_ERROR(context, "Failed to add pairing: storage error (code %d)", r);
                    send_tlv_error_response(context, 2, TLVError_Unknown);
                    break;
                }

                INFO("Added pairing with %.*s", tlv_device_identifier->size, tlv_device_identifier->value);

                HOMEKIT_NOTIFY_EVENT(context->server, HOMEKIT_EVENT_PAIRING_ADDED);
            }

            tlv_stream_t *tlv = client_start_tlv_response(context);

            tlv_stream_add_integer_value(tlv, TLVType_State, 1, 2);

            client_finish_tlv_response(context);

            break;
        }
        case TLVMethod_RemovePairing: {
            CLIENT_INFO(context, "Remove Pairing");

            if (!(context->permissions & pairing_permissions_admin)) {
                CLIENT_ERROR(context, "Refusing to remove pairing to non-admin controller");
                send_tlv_error_response(context, 2, TLVError_Authentication);
                break;
            }

            tlv_t *tlv_device_identifier = tlv_get_value(message, TLVType_Identifier);
            if (!tlv_device_identifier) {
                CLIENT_ERROR(context, "Invalid remove pairing request: no device identifier");
                send_tlv_error_response(context, 2, TLVError_Unknown);
                break;
            }

            pairing_t pairing;
            if (!homekit_storage_find_pairing((const char *)tlv_device_identifier->value, &pairing)) {
                bool is_admin = pairing.permissions & pairing_permissions_admin;

                r = homekit_storage_remove_pairing((const char *)tlv_device_identifier->value);
                if (r) {
                    CLIENT_ERROR(context, "Failed to remove pairing: storage error (code %d)", r);
                    send_tlv_error_response(context, 2, TLVError_Unknown);
                    break;
                }

                INFO("Removed pairing with %.*s", tlv_device_identifier->size, tlv_device_identifier->value);

                HOMEKIT_NOTIFY_EVENT(context->server, HOMEKIT_EVENT_PAIRING_REMOVED);

                client_context_t *c = context->server->clients;
                while (c) {
                    if (c->pairing_id == pairing.id)
                        c->disconnect = true;
                    c = c->next;
                }

                if (is_admin) {
                    // Removed pairing was admin,
                    // check if there any other admins left.
                    // If no admins left, enable pairing again
                    bool admin_found = false;

                    pairing_iterator_t pairing_it;
                    homekit_storage_pairing_iterator_init(&pairing_it);
                    while ((!homekit_storage_next_pairing(&pairing_it, &pairing))) {
                        if (pairing.permissions & pairing_permissions_admin) {
                            admin_found = true;
                            break;
                        }
                    };
                    homekit_storage_pairing_iterator_done(&pairing_it);

                    if (!admin_found) {
                        // No admins left, enable pairing again
                        INFO("Last admin pairing was removed, enabling pair setup");

                        context->server->paired = false;
                        homekit_setup_mdns(context->server);
                    }
                }
            }

            tlv_stream_t *tlv = client_start_tlv_response(context);

            tlv_stream_add_integer_value(tlv, TLVType_State, 1, 2);

            client_finish_tlv_response(context);

            break;
        }
        case TLVMethod_ListPairings: {
            CLIENT_INFO(context, "List Pairings");

            if (!(context->permissions & pairing_permissions_admin)) {
                CLIENT_INFO(context, "Refusing to list pairings to non-admin controller");
                send_tlv_error_response(context, 2, TLVError_Authentication);
                break;
            }

            tlv_stream_t *tlv = client_start_tlv_response(context);

            tlv_stream_add_integer_value(tlv, TLVType_State, 1, 2);

            bool first = true;

            pairing_iterator_t it;
            homekit_storage_pairing_iterator_init(&it);

            pairing_t pairing;

            byte public_key[32];

            while (!homekit_storage_next_pairing(&it, &pairing)) {
                if (!first) {
                    tlv_stream_add_value(tlv, TLVType_Separator, NULL, 0);
                }
                size_t public_key_size = sizeof(public_key);
                r = crypto_ed25519_export_public_key(&pairing.device_key, public_key, &public_key_size);

                tlv_stream_add_string_value(tlv, TLVType_Identifier, pairing.device_id);
                tlv_stream_add_value(tlv, TLVType_PublicKey, public_key, public_key_size);
                tlv_stream_add_integer_value(tlv, TLVType_Permissions, 1, pairing.permissions);

                first = false;
            }
            homekit_storage_pairing_iterator_done(&it);

            client_finish_tlv_response(context);

            break;
        }
        default: {
            send_tlv_error_response(context, 2, TLVError_Unknown);
            break;
        }
    }

    tlv_free(message);
}

void homekit_server_on_resource(client_context_t *context) {
    CLIENT_INFO(context, "Resource");
    DEBUG_HEAP();

    if (!context->server->config->on_resource) {
        send_404_response(context);
        return;
    }

    context->server->config->on_resource(context->server->body, context->server->body_length);
}


int homekit_server_on_url(http_parser *parser, const char *data, size_t length) {
    client_context_t *context = (client_context_t*) parser->data;

    context->server->endpoint = HOMEKIT_ENDPOINT_UNKNOWN;
    if (parser->method == HTTP_GET) {
        if (!strncmp(data, "/accessories", length)) {
            context->server->endpoint = HOMEKIT_ENDPOINT_GET_ACCESSORIES;
        } else {
            static const char url[] = "/characteristics";
            size_t url_len = sizeof(url)-1;

            if (length >= url_len && !strncmp(data, url, url_len) &&
                    (data[url_len] == 0 || data[url_len] == '?'))
            {
                context->server->endpoint = HOMEKIT_ENDPOINT_GET_CHARACTERISTICS;
                if (data[url_len] == '?') {
                    homekit_server_t *server = context->server;
                    memset(server->endpoint_params.ids, 0, sizeof(server->endpoint_params.ids));
                    server->endpoint_params.format = 0;
                    uint16_t id_count = 0;

                    query_param_iterator_t it;
                    query_param_iterator_init(&it, data+url_len+1, length-url_len-1);

                    query_param_t param;
                    while (query_param_iterator_next(&it, &param)) {
                        if (!strncmp(param.name, "id", param.name_len)) {
                            int pos = 0;

                            while (pos < param.value_len) {
                                if (pos >= param.value_len || !isdigit((unsigned char)param.value[pos])) {
                                    CLIENT_ERROR(context, "Unexpected character in ID query param at position %d: "
                                                 "expected digit, actual '%c'", pos, param.value[pos]);
                                    break;
                                }

                                uint16_t aid = 0;

                                while (pos < param.value_len && isdigit((unsigned char)param.value[pos])) {
                                    aid = aid * 10 + param.value[pos++] - '0';
                                }

                                if (pos >= param.value_len || param.value[pos] != '.') {
                                    CLIENT_ERROR(context, "Unexpected character in ID query param at position %d: "
                                                 "expected '.', actual '%c'", pos, param.value[pos]);
                                    break;
                                }

                                pos++;

                                if (pos >= param.value_len || !isdigit((unsigned char)param.value[pos])) {
                                    CLIENT_ERROR(context, "Unexpected character in ID query param at position %d: "
                                                 "expected digit, actual '%c'", pos, param.value[pos]);
                                    break;
                                }

                                uint16_t iid = 0;
                                while (pos < param.value_len && isdigit((unsigned char)param.value[pos])) {
                                    iid = iid * 10 + param.value[pos++] - '0';
                                }

                                server->endpoint_params.ids[id_count].aid = aid;
                                server->endpoint_params.ids[id_count].iid = iid;
                                id_count++;

                                if (pos >= param.value_len)
                                    break;

                                if (param.value[pos] != ',') {
                                    CLIENT_ERROR(context, "Unexpected character in ID query param at position %d: "
                                                 "expected ',', actual '%c'", pos, param.value[pos]);
                                    break;
                                }

                                pos++;
                            }
                        } else if (!strncmp(param.name, "meta", param.name_len)) {
                            if (param.value && param.value_len == 1 && param.value[0] == '1')
                                server->endpoint_params.format |= characteristic_format_meta;
                        } else if (!strncmp(param.name, "perms", param.name_len)) {
                            if (param.value && param.value_len == 1 && param.value[0] == '1')
                                server->endpoint_params.format |= characteristic_format_perms;
                        } else if (!strncmp(param.name, "type", param.name_len)) {
                            if (param.value && param.value_len == 1 && param.value[0] == '1')
                                server->endpoint_params.format |= characteristic_format_type;
                        } else if (!strncmp(param.name, "ev", param.name_len)) {
                            if (param.value && param.value_len == 1 && param.value[0] == '1')
                                server->endpoint_params.format |= characteristic_format_events;
                        }
                    }

                    query_param_iterator_done(&it);
                }
            }
        }
    } else if (parser->method == HTTP_POST) {
        if (!strncmp(data, "/identify", length)) {
            context->server->endpoint = HOMEKIT_ENDPOINT_IDENTIFY;
        } else if (!strncmp(data, "/pair-setup", length)) {
            context->server->endpoint = HOMEKIT_ENDPOINT_PAIR_SETUP;
        } else if (!strncmp(data, "/pair-verify", length)) {
            context->server->endpoint = HOMEKIT_ENDPOINT_PAIR_VERIFY;
        } else if (!strncmp(data, "/pairings", length)) {
            context->server->endpoint = HOMEKIT_ENDPOINT_PAIRINGS;
        } else if (!strncmp(data, "/resource", length)) {
            context->server->endpoint = HOMEKIT_ENDPOINT_RESOURCE;
        }
    } else if (parser->method == HTTP_PUT) {
        if (!strncmp(data, "/characteristics", length)) {
            context->server->endpoint = HOMEKIT_ENDPOINT_UPDATE_CHARACTERISTICS;
        }
    }

    if (context->server->endpoint == HOMEKIT_ENDPOINT_UNKNOWN) {
        ERROR("Unknown endpoint: %s %.*s", http_method_str(parser->method), length, data);
    }

    return 0;
}

int homekit_server_on_body(http_parser *parser, const char *data, size_t length) {
    client_context_t *context = parser->data;
    if (!context->server->body && !parser->content_length) {
        context->server->body = (char *)data;
        context->server->body_length = length;
        context->server->body_static = true;
    } else {
        if (!context->server->body) {
            context->server->body = malloc(length + parser->content_length + 1);
            context->server->body_length = 0;
            context->server->body_static = false;
        }
        memcpy(context->server->body + context->server->body_length, data, length);
        context->server->body_length += length;
        context->server->body[context->server->body_length] = 0;
    }

    return 0;
}

int homekit_server_on_message_begin(http_parser *parser) {
    client_context_t *context = parser->data;
    context->server->request_completed = false;

    return 0;
}

int homekit_server_on_message_complete(http_parser *parser) {
    client_context_t *context = parser->data;

    if (!context->encrypted) {
        switch(context->server->endpoint) {
            case HOMEKIT_ENDPOINT_PAIR_SETUP: {
                homekit_server_on_pair_setup(context, (const byte *)context->server->body, context->server->body_length);
                break;
            }
            case HOMEKIT_ENDPOINT_PAIR_VERIFY: {
                homekit_server_on_pair_verify(context, (const byte *)context->server->body, context->server->body_length);
                break;
            }
            default: {
                DEBUG("Unknown endpoint");
                send_404_response(context);
                break;
            }
        }
    } else {
        switch(context->server->endpoint) {
            case HOMEKIT_ENDPOINT_IDENTIFY: {
                homekit_server_on_identify(context);
                break;
            }
            case HOMEKIT_ENDPOINT_GET_ACCESSORIES: {
                homekit_server_on_get_accessories(context);
                break;
            }
            case HOMEKIT_ENDPOINT_GET_CHARACTERISTICS: {
                homekit_server_on_get_characteristics(context);
                break;
            }
            case HOMEKIT_ENDPOINT_UPDATE_CHARACTERISTICS: {
                homekit_server_on_update_characteristics(context, (const byte *)context->server->body, context->server->body_length);
                break;
            }
            case HOMEKIT_ENDPOINT_PAIRINGS: {
                homekit_server_on_pairings(context, (const byte *)context->server->body, context->server->body_length);
                break;
            }
            case HOMEKIT_ENDPOINT_RESOURCE: {
                homekit_server_on_resource(context);
                break;
            }
            default: {
                DEBUG("Unknown endpoint");
                send_404_response(context);
                break;
            }
        }
    }

    if (context->server->body) {
        if (!context->server->body_static)
            free(context->server->body);
        context->server->body = NULL;
        context->server->body_length = 0;
        context->server->body_static = false;
    }

    context->server->request_completed = true;

    return 0;
}


static http_parser_settings homekit_http_parser_settings = {
    .on_url = homekit_server_on_url,
    .on_body = homekit_server_on_body,
    .on_message_begin = homekit_server_on_message_begin,
    .on_message_complete = homekit_server_on_message_complete,
};


static void homekit_client_process(client_context_t *context) {
    context->server->parser.data = context;

    size_t data_available = 0;

    do {
        int data_len = read(
            context->socket,
            context->server->data+data_available,
            sizeof(context->server->data)-data_available
        );
        if (data_len == 0) {
            context->disconnect = true;
            return;
        }

        if (data_len < 0) {
            if (errno != EAGAIN) {
                CLIENT_ERROR(context, "Error reading data from socket (code %d). Disconnecting", errno);
                context->disconnect = true;
                return;
            }
            continue;
        }

        CLIENT_DEBUG(context, "Got %d incoming data", data_len);
        byte *payload = (byte *)context->server->data;
        size_t payload_size = (size_t)data_len;

        size_t decrypted_size = sizeof(context->server->data) - 2 - 18;

        if (context->encrypted) {
            CLIENT_DEBUG(context, "Decrypting data");

            int r = client_decrypt(context, context->server->data, data_len, context->server->data+2, &decrypted_size);
            if (r < 0) {
                CLIENT_ERROR(context, "Invalid client data");
                return;
            }
            data_available = data_len - r;
            if (r && data_available) {
                memmove(context->server->data, &context->server->data[r], data_available);
            }
            CLIENT_DEBUG(context, "Decrypted %d bytes, available %d", decrypted_size, data_available);

            payload = context->server->data+2;
            payload_size = decrypted_size;
            if (payload_size)
                print_binary("Decrypted data", payload, payload_size);
        } else {
            data_available = 0;
        }

        current_client_context = context;

        context->server->request_completed = false;

        http_parser_execute(
            &context->server->parser, &homekit_http_parser_settings,
            (char *)payload, payload_size
        );
    } while (data_available && !context->server->request_completed);

    current_client_context = NULL;
    context->server->parser.data = NULL;

    CLIENT_DEBUG(context, "Finished processing");
}


void homekit_server_close_client(homekit_server_t *server, client_context_t *context) {
    char address_buffer[INET_ADDRSTRLEN];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(context->socket, (struct sockaddr *)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, address_buffer, sizeof(address_buffer));
    } else {
        strcpy(address_buffer, "?.?.?.?");
    }
    CLIENT_INFO(context, "Closing client connection from %s",address_buffer);

    FD_CLR(context->socket, &server->fds);
    server->client_count--;

    bitset_clear(server->client_ids, context->id);
    for (uint16_t nid=0; nid < server->notify_count; nid++) {
        bitset_clear(server->subscriptions, nid * HOMEKIT_MAX_CLIENTS + context->id);
    }

    close(context->socket);

    if (server->pairing_context && server->pairing_context->client == context) {
        pairing_context_free(server->pairing_context);
        server->pairing_context = NULL;
    }

    HOMEKIT_NOTIFY_EVENT(server, HOMEKIT_EVENT_CLIENT_DISCONNECTED);

    client_context_free(context);
}


client_context_t *homekit_server_accept_client(homekit_server_t *server) {
    int s = accept(server->listen_fd, (struct sockaddr *)NULL, (socklen_t *)NULL);
    if (s < 0) {
        if (errno == EWOULDBLOCK)
            return NULL;

        ERROR("Failed to accept connection (errno %d)", errno);
        return NULL;
    }

    if (server->client_count >= HOMEKIT_MAX_CLIENTS) {
        INFO("No more room for client connections (max %d)", HOMEKIT_MAX_CLIENTS);
        close(s);
        return NULL;
    }

    const struct timeval rcvtimeout = { 10, 0 }; /* 10 second timeout */
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rcvtimeout, sizeof(rcvtimeout));

    const int yes = 1; /* enable sending keepalive probes for socket */
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));

    const int idle = 180; /* 180 sec idle before start sending probes */
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));

    const int interval = 30; /* 30 sec between probes */
    setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));

    const int maxpkt = 4; /* Drop connection after 4 probes without response */
    setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(maxpkt));

    client_context_t *context = client_context_new();
    if (!context) {
        ERROR("Failed to allocate memory for client context");
        close(s);
        return NULL;
    }
    context->server = server;
    context->id = HOMEKIT_MAX_CLIENTS;
    // find available client ID
    for (uint8_t id=0; id < HOMEKIT_MAX_CLIENTS; id++) {
        if (!bitset_isset(server->client_ids, id)) {
            bitset_set(server->client_ids, id);
            context->id = id;
            break;
        }
    }
    if (context->id == HOMEKIT_MAX_CLIENTS) {
        ERROR("Failed to assign ID for client context");
        client_context_free(context);
        close(s);
        return NULL;
    }

    context->socket = s;
    context->next = server->clients;

    FD_SET(s, &server->fds);
    server->client_count++;
    if (s > server->max_fd)
        server->max_fd = s;
    DEBUG_HEAP();

    char address_buffer[INET_ADDRSTRLEN];

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(s, (struct sockaddr *)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, address_buffer, sizeof(address_buffer));
    } else {
        strcpy(address_buffer, "?.?.?.?");
    }

    CLIENT_INFO(context, "Got new client connection from %s", address_buffer);


    client_context_t *c = server->clients;
    while (c) {
        if (getpeername(c->socket, (struct sockaddr *)&addr, &addr_len) == 0) {
            inet_ntop(AF_INET, &addr.sin_addr, address_buffer, sizeof(address_buffer));
        } else {
            strcpy(address_buffer, "?.?.?.?");
        }
        CLIENT_INFO(c, " Have existing connection from %s %s", address_buffer, c->disconnect?"X":"");
        c = c->next;
    }

    server->clients = context;

    HOMEKIT_NOTIFY_EVENT(server, HOMEKIT_EVENT_CLIENT_CONNECTED);

    return context;
}


void homekit_characteristic_notify(homekit_characteristic_t *ch, homekit_value_t value) {
    if (!server)
        return;

    if (!(ch->permissions & homekit_permissions_notify))
        return;

    xSemaphoreTake(server->notification_lock, portMAX_DELAY);

    characteristic_info_t *ch_info = find_characteristic_info_by_characteristic(server, ch);
    if (!ch_info) {
        ERROR("Trying notify on unknown characteristic \"%s\"", ch->description);
        return;
    }

    DEBUG("Got characteristic %d.%d change event", ch_info->aid, ch_info->iid);

    homekit_value_destruct(&server->notifications[ch_info->notification_id].value);
    homekit_value_copy(&server->notifications[ch_info->notification_id].value, &value);

    bitset_set(server->has_notification, ch_info->notification_id);
    server->has_notifications = true;

    xSemaphoreGive(server->notification_lock);

    // backward compatibility
    homekit_characteristic_change_callback_t *callback = ch->callback;
    while (callback) {
        callback->function(ch, value, callback->context);
        callback = callback->next;
    }
}


void homekit_server_process_notifications(homekit_server_t *server) {
    if (!server->has_notifications)
        return;

    xSemaphoreTake(server->notification_lock, portMAX_DELAY);

    client_context_t *context = server->clients;
    while (context) {
        bool first = true;

        json_stream *json = &context->server->json;
        json_set_context(json, context);
        json_reset(json);

        for (uint16_t nid=0; nid < server->notify_count; nid++) {
            if (!bitset_isset(server->has_notification, nid))
                continue;

            characteristic_info_t *ch_info = find_characteristic_info_by_characteristic(server, server->notifications[nid].ch);

            if (!bitset_isset(server->subscriptions, nid * HOMEKIT_MAX_CLIENTS + context->id)) {
                CLIENT_DEBUG(context, "Not subscribed to characteristic %d.%d, skipping event", ch_info->aid, ch_info->iid);
                continue;
            }

            if (first) {
                CLIENT_DEBUG(context, "Sending EVENT");
                DEBUG_HEAP();

                static byte http_headers[] =
                    "EVENT/1.0 200 OK\r\n"
                    "Content-Type: application/hap+json\r\n"
                    "Transfer-Encoding: chunked\r\n\r\n";

                client_send(context, http_headers, sizeof(http_headers)-1);

                json_object_start(json);
                json_string(json, "characteristics"); json_array_start(json);

                first = false;
            }

            json_object_start(json);
            write_characteristic_json(json, context, ch_info->ch, 0, &server->notifications[nid].value);
            json_object_end(json);
        }

        if (!first) {
            json_array_end(json);
            json_object_end(json);

            json_flush(json);

            client_send_chunk(NULL, 0, context);
        }

        context = context->next;
    }

    for (uint16_t nid=0; nid < server->notify_count; nid++) {
        if (!bitset_isset(server->has_notification, nid))
            continue;

        homekit_value_destruct(&server->notifications[nid].value);
    }

    bitset_clear_all(server->has_notification);
    server->has_notifications = false;

    xSemaphoreGive(server->notification_lock);
}


void homekit_server_close_clients(homekit_server_t *server) {
    int max_fd = server->listen_fd;

    client_context_t head;
    head.next = server->clients;

    client_context_t *context = &head;
    while (context->next) {
        client_context_t *tmp = context->next;

        if (tmp->disconnect) {
            context->next = tmp->next;
            homekit_server_close_client(server, tmp);
        } else {
            if (tmp->socket > max_fd)
                max_fd = tmp->socket;

            context = tmp;
        }
    }

    server->clients = head.next;
    server->max_fd = max_fd;
}


static void homekit_run_server(homekit_server_t *server)
{
    DEBUG("Starting HTTP server");

    struct sockaddr_in serv_addr;
    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd < 0) {
        ERROR("Failed to create server socket (errno %d)", errno);
        return;
    }
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT);
    bind(server->listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    int opt = lwip_fcntl(server->listen_fd, F_GETFL, 0);
    if (opt < 0) {
        ERROR("Failed to read configuration to server socket (errno %d)", errno);
        close(server->listen_fd);
        return;
    }
    opt |= O_NONBLOCK;
    if (lwip_fcntl(server->listen_fd, F_SETFL, opt) == -1) {
        ERROR("Failed to write configuration to server socket (errno %d)", errno);
        close(server->listen_fd);
        return;
    }

    listen(server->listen_fd, 10);

    FD_SET(server->listen_fd, &server->fds);
    server->max_fd = server->listen_fd;
    server->client_count = 0;

    for (;;) {
        fd_set read_fds;
        memcpy(&read_fds, &server->fds, sizeof(read_fds));

        struct timeval timeout = { 1, 0 }; /* 1 second timeout */
        int triggered_nfds = select(server->max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (triggered_nfds > 0) {
            client_context_t *context = NULL;
            if (FD_ISSET(server->listen_fd, &read_fds)) {
                while (true) {
                    context = homekit_server_accept_client(server);
                    if (!context)
                        break;

                    homekit_client_process(context);
                }
                triggered_nfds--;
            }

            context = server->clients;
            while (context && triggered_nfds) {
                if (FD_ISSET(context->socket, &read_fds)) {
                    homekit_client_process(context);
                    triggered_nfds--;
                }

                context = context->next;
            }

            homekit_server_close_clients(server);
        }

        homekit_server_process_notifications(server);
    }

    server_free(server);
}


void homekit_setup_mdns(homekit_server_t *server) {
    INFO("Configuring mDNS");

    homekit_accessory_t *accessory = server->config->accessories[0];
    homekit_service_t *accessory_info =
        homekit_service_by_type(accessory, HOMEKIT_SERVICE_ACCESSORY_INFORMATION);
    if (!accessory_info) {
        ERROR("Invalid accessory declaration: no Accessory Information service");
        return;
    }

    homekit_characteristic_t *name =
        homekit_service_characteristic_by_type(accessory_info, HOMEKIT_CHARACTERISTIC_NAME);
    if (!name) {
        ERROR("Invalid accessory declaration: "
              "no Name characteristic in AccessoryInfo service");
        return;
    }

    homekit_characteristic_t *model =
        homekit_service_characteristic_by_type(accessory_info, HOMEKIT_CHARACTERISTIC_MODEL);
    if (!model) {
        ERROR("Invalid accessory declaration: "
              "no Model characteristic in AccessoryInfo service");
        return;
    }

    homekit_mdns_configure_init(name->value.string_value, PORT);

    // accessory model name (required)
    homekit_mdns_add_txt("md", "%s", model->value.string_value);
    // protocol version (required)
    homekit_mdns_add_txt("pv", "1.0");
    // device ID (required)
    // should be in format XX:XX:XX:XX:XX:XX, otherwise devices will ignore it
    homekit_mdns_add_txt("id", "%s", server->accessory_id);
    // current configuration number (required)
    homekit_mdns_add_txt("c#", "%u", server->config->config_number);
    // current state number (required)
    homekit_mdns_add_txt("s#", "1");
    // feature flags (required if non-zero)
    //   bit 0 - supports HAP pairing. required for all HomeKit accessories
    //   bits 1-7 - reserved
    homekit_mdns_add_txt("ff", "0");
    // status flags
    //   bit 0 - not paired
    //   bit 1 - not configured to join WiFi
    //   bit 2 - problem detected on accessory
    //   bits 3-7 - reserved
    homekit_mdns_add_txt("sf", "%d", (server->paired) ? 0 : 1);
    // accessory category identifier
    homekit_mdns_add_txt("ci", "%d", server->config->category);

    if (server->config->setupId) {
        DEBUG("Accessory Setup ID = %s", server->config->setupId);

        size_t data_size = strlen(server->config->setupId) + strlen(server->accessory_id) + 1;
        char *data = malloc(data_size);
        if (!data) {
            ERROR("Failed to allocate %d bytes for generating setup ID hash", data_size);
        } else {
            snprintf(data, data_size, "%s%s", server->config->setupId, server->accessory_id);
            data[data_size-1] = 0;

            unsigned char shaHash[SHA512_DIGEST_SIZE];
            wc_Sha512Hash((const unsigned char *)data, data_size-1, shaHash);

            free(data);

            unsigned char encodedHash[9];
            memset(encodedHash, 0, sizeof(encodedHash));

            word32 len = sizeof(encodedHash);
            Base64_Encode_NoNl((const unsigned char *)shaHash, 4, encodedHash, &len);

            homekit_mdns_add_txt("sh", "%s", encodedHash);
        }
    }

    homekit_mdns_configure_finalize();
}

int homekit_accessory_id_generate(char *accessory_id) {
    byte buf[6];
    homekit_random_fill(buf, sizeof(buf));

    snprintf(accessory_id, ACCESSORY_ID_SIZE+1, "%02X:%02X:%02X:%02X:%02X:%02X",
             buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

    INFO("Generated new accessory ID: %s", accessory_id);
    return 0;
}

int homekit_accessory_key_generate(ed25519_key *key) {
    int r = crypto_ed25519_generate(key);
    if (r) {
        ERROR("Failed to generate accessory key");
        return r;
    }

    INFO("Generated new accessory key");

    return 0;
}

void homekit_server_task(void *args) {
    homekit_server_t *server = args;
    INFO("Starting server");

    int r = homekit_storage_init();

    if (r == 0) {
        r = homekit_storage_load_accessory_id(server->accessory_id);

        if (!r)
            r = homekit_storage_load_accessory_key(&server->accessory_key);
    }

    if (r) {
        if (r < 0) {
            INFO("Resetting HomeKit storage");
            homekit_storage_reset();
        }

        homekit_accessory_id_generate(server->accessory_id);
        homekit_storage_save_accessory_id(server->accessory_id);

        homekit_accessory_key_generate(&server->accessory_key);
        homekit_storage_save_accessory_key(&server->accessory_key);
    } else {
        INFO("Using existing accessory ID: %s", server->accessory_id);
    }

    pairing_iterator_t pairing_it;
    homekit_storage_pairing_iterator_init(&pairing_it);

    pairing_t pairing;
    while (!homekit_storage_next_pairing(&pairing_it, &pairing)) {
        if (pairing.permissions & pairing_permissions_admin) {
            INFO("Found admin pairing with %s, disabling pair setup", pairing.device_id);
            server->paired = true;
            break;
        }
    }
    homekit_storage_pairing_iterator_done(&pairing_it);

    homekit_mdns_init();
    homekit_setup_mdns(server);

    HOMEKIT_NOTIFY_EVENT(server, HOMEKIT_EVENT_SERVER_INITIALIZED);

    homekit_run_server(server);

    vTaskDelete(NULL);
}

#define ISDIGIT(x) isdigit((unsigned char)(x))
#define ISBASE36(x) (isdigit((unsigned char)(x)) || (x >= 'A' && x <= 'Z'))


int accessory_info_cmp_accessory(const accessory_info_t *a, const accessory_info_t *b) {
    return (a->accessory == b->accessory) ? 0 : ((a->accessory < b->accessory) ? -1 : 1);
}


int service_info_cmp_service(const service_info_t *a, const service_info_t *b) {
    return (a->service == b->service) ? 0 : ((a->service < b->service) ? -1 : 1);
}


int characteristic_info_cmp_characteristic(const characteristic_info_t *a, const characteristic_info_t *b) {
    return (a->ch == b->ch) ? 0 : ((a->ch < b->ch) ? -1 : 1);
}


int homekit_accessories_init(homekit_server_t *server) {
    server->accessory_count = 0;
    server->service_count = 0;
    server->characteristic_count = 0;
    server->notify_count = 0;

    for (homekit_accessory_t **accessory_it = server->config->accessories; *accessory_it; accessory_it++) {
        server->accessory_count++;
        for (homekit_service_t **service_it = (*accessory_it)->services; *service_it; service_it++) {
            server->service_count++;
            for (homekit_characteristic_t **ch_it = (*service_it)->characteristics; *ch_it; ch_it++) {
                homekit_characteristic_t *ch = *ch_it;
                server->characteristic_count++;

                if (ch->permissions & homekit_permissions_notify) {
                    server->notify_count++;
                }
            }
        }
    }

    server->accessory_infos = calloc(server->accessory_count, sizeof(accessory_info_t));
    if (!server->accessory_infos) {
        ERROR("Error initializing HomeKit accessory server: "
              "failed to allocate memory for accessory infos");
        return -1;
    }
    server->service_infos = calloc(server->service_count, sizeof(service_info_t));
    if (!server->service_infos) {
        ERROR("Error initializing HomeKit accessory server: "
              "failed to allocate memory for service infos");
        return -1;
    }
    server->characteristic_infos = calloc(server->characteristic_count, sizeof(characteristic_info_t));
    if (!server->characteristic_infos) {
        ERROR("Error initializing HomeKit accessory server: "
              "failed to allocate memory for characteristic infos");
        return -1;
    }

    server->subscriptions = bitset_new(server->notify_count * HOMEKIT_MAX_CLIENTS);
    if (!server->subscriptions) {
        ERROR("Error initializing HomeKit accessory server: "
              "failed to allocate memory for subscriptions");
        return -1;
    }

    server->notifications = calloc(server->notify_count, sizeof(characteristic_notification_info_t));
    if (!server->notifications) {
        ERROR("Error initializing HomeKit accessory server: "
              "failed to allocate memory for notifications info");
        return -1;
    }

    server->has_notification = bitset_new(server->notify_count);
    if (!server->has_notification) {
        ERROR("Error initializing HomeKit accessory server: "
              "failed to allocate memory for notifications flags");
        return -1;
    }

    uint16_t aid = 1;
    uint16_t service_idx = 0;
    uint16_t characteristic_idx = 0;
    uint16_t notification_idx = 0;
    for (uint16_t accessory_idx=0; accessory_idx < server->accessory_count; accessory_idx++) {
        homekit_accessory_t *accessory = server->config->accessories[accessory_idx];

        server->accessory_infos[accessory_idx].accessory = accessory;
        if (accessory->id) {
            server->accessory_infos[accessory_idx].aid = accessory->id;
            if (accessory->id >= aid)
                aid = accessory->id+1;
        } else {
            server->accessory_infos[accessory_idx].aid = aid++;
        }

        int iid = 1;
        for (homekit_service_t **service_it = accessory->services; *service_it; service_it++, service_idx++) {
            homekit_service_t *service = *service_it;

            server->service_infos[service_idx].service = service;
            if (service->id) {
                if (service->id >= iid)
                    iid = service->id+1;
            } else {
                server->service_infos[service_idx].iid = iid++;
            }

            for (homekit_characteristic_t **ch_it = service->characteristics; *ch_it; ch_it++, characteristic_idx++) {
                homekit_characteristic_t *ch = *ch_it;

                server->characteristic_infos[characteristic_idx].ch = ch;
                server->characteristic_infos[characteristic_idx].aid = server->accessory_infos[accessory_idx].aid;
                if (ch->id) {
                    if (ch->id >= iid)
                        iid = ch->id+1;
                } else {
                    server->characteristic_infos[characteristic_idx].iid = iid++;
                }

                if (ch->permissions & homekit_permissions_notify) {
                    server->characteristic_infos[characteristic_idx].notification_id = notification_idx;
                    server->notifications[notification_idx].ch = ch;
                    notification_idx++;
                }
            }
        }
    }

    qsort(server->accessory_infos,
          server->accessory_count,
          sizeof(*server->accessory_infos),
          (int(*)(const void*, const void*))accessory_info_cmp_accessory);

    qsort(server->service_infos,
          server->service_count,
          sizeof(*server->service_infos),
          (int(*)(const void*, const void*))service_info_cmp_service);

    qsort(server->characteristic_infos,
          server->characteristic_count,
          sizeof(*server->characteristic_infos),
          (int(*)(const void*, const void*))characteristic_info_cmp_characteristic);

    return 0;
}


void homekit_server_init(homekit_server_config_t *config) {
    if (!config->accessories) {
        ERROR("Error initializing HomeKit accessory server: "
              "accessories are not specified");
        return;
    }

    if (!config->password && !config->password_callback) {
        ERROR("Error initializing HomeKit accessory server: "
              "neither password nor password callback is specified");
        return;
    }

    if (config->password) {
        const char *p = config->password;
        if (strlen(p) != 10 ||
                !(ISDIGIT(p[0]) && ISDIGIT(p[1]) && ISDIGIT(p[2]) && p[3] == '-' &&
                    ISDIGIT(p[4]) && ISDIGIT(p[5]) && p[6] == '-' &&
                    ISDIGIT(p[7]) && ISDIGIT(p[8]) && ISDIGIT(p[9]))) {
            ERROR("Error initializing HomeKit accessory server: "
                  "invalid password format");
            return;
        }
    }

    if (config->setupId) {
        const char *p = config->setupId;
        if (strlen(p) != 4 ||
                !(ISBASE36(p[0]) && ISBASE36(p[1]) && ISBASE36(p[2]) && ISBASE36(p[3]))) {
            ERROR("Error initializing HomeKit accessory server: "
                  "invalid setup ID format");
            return;
        }
    }

    if (!config->config_number) {
        config->config_number = config->accessories[0]->config_number;
        if (!config->config_number) {
            config->config_number = 1;
        }
    }

    if (!config->category) {
        config->category = config->accessories[0]->category;
    }

    server = server_new();
    if (!server) {
        ERROR("Error initializing HomeKit accessory server: "
              "failed to allocate memory for server");
        return;
    }
    server->config = config;

    if (homekit_accessories_init(server)) {
        server_free(server);
        server = NULL;
        return;
    }

    if (pdPASS != xTaskCreate(homekit_server_task, "HomeKit Server",
                              SERVER_TASK_STACK, server, 1, NULL)) {
        ERROR("Error initializing HomeKit accessory server: "
              "failed to start a server task");
        server_free(server);
    }
}

void homekit_server_reset() {
    homekit_storage_reset();
}

bool homekit_is_paired() {
    bool paired = false;

    pairing_iterator_t pairing_it;
    homekit_storage_pairing_iterator_init(&pairing_it);

    pairing_t pairing;
    while (!homekit_storage_next_pairing(&pairing_it, &pairing)) {
        if (pairing.permissions & pairing_permissions_admin) {
            paired = true;
            break;
        }
    };
    homekit_storage_pairing_iterator_done(&pairing_it);

    return paired;
}

int homekit_get_accessory_id(char *buffer, size_t size) {
    if (size < ACCESSORY_ID_SIZE + 1)
        return -1;

    int r = homekit_storage_load_accessory_id(buffer);
    if (r)
        return r;

    return 0;
}

int homekit_get_setup_uri(const homekit_server_config_t *config, char *buffer, size_t buffer_size) {
    static const char base36Table[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    if (buffer_size < 20)
        return -1;

    if (!config->password)
        return -1;
    // TODO: validate password in case it is run before server is started

    if (!config->setupId)
        return -1;
    // TODO: validate setupID in case it is run before server is started

    homekit_accessory_t *accessory = homekit_accessory_by_id(config->accessories, 1);
    if (!accessory)
        return -1;

    uint32_t setup_code = 0;
    for (const char *s = config->password; *s; s++)
        if ISDIGIT(*s)
            setup_code = setup_code * 10 + *s - '0';

    uint64_t payload = 0;

    payload <<= 4;  // reserved 4 bits

    payload <<= 8;
    payload |= accessory->category & 0xff;

    payload <<= 4;
    payload |= 2;  // flags (2=IP, 4=BLE, 8=IP_WAC)

    payload <<= 27;
    payload |= setup_code & 0x7fffffff;

    strcpy(buffer, "X-HM://");
    buffer += 7;
    for (int i=8; i >= 0; i--) {
        buffer[i] = base36Table[payload % 36];
        payload /= 36;
    }
    buffer += 9;

    strcpy(buffer, config->setupId);
    buffer += 4;

    buffer[0] = 0;

    return 0;
}
