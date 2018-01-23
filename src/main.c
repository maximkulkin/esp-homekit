#include <stdio.h>

#include <homekit/homekit.h>
#include <homekit/characteristics.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void switch_on_callback(homekit_characteristic_t *_ch, homekit_value_t on, void *context);

void button_intr_callback(uint8_t gpio);

homekit_characteristic_t switch_on = HOMEKIT_CHARACTERISTIC_(
    ON, false, .callback=HOMEKIT_CHARACTERISTIC_CALLBACK(switch_on_callback)
);

void switch_on_callback(homekit_characteristic_t *_ch, homekit_value_t on, void *context) {
    printf("~~~~~~~~~~~~~~~~POWER SWITCH %d~~~~~~~~~~~~~~~~~~~\n", switch_on.value.bool_value);
    int fd = open("/sys/class/gpio/gpio28/value", O_WRONLY);

    if (switch_on.value.bool_value) {
        write(fd, "1\n", 2);
    } else {
        write(fd, "0\n", 2);
    }
    close(fd);
}

void switch_identify(homekit_value_t _value) {
    printf("Switch identify\n");
}

homekit_characteristic_t name = HOMEKIT_CHARACTERISTIC_(NAME, "Switch");

homekit_accessory_t *accessories[] = {
    HOMEKIT_ACCESSORY(.id=1, .category=homekit_accessory_category_switch, .services=(homekit_service_t*[]){
        HOMEKIT_SERVICE(ACCESSORY_INFORMATION, .characteristics=(homekit_characteristic_t*[]){
            &name,
            HOMEKIT_CHARACTERISTIC(MANUFACTURER, "kh"),
            HOMEKIT_CHARACTERISTIC(SERIAL_NUMBER, "037A2BABF19D"),
            HOMEKIT_CHARACTERISTIC(MODEL, "Basic"),
            HOMEKIT_CHARACTERISTIC(FIRMWARE_REVISION, "0.1"),
            HOMEKIT_CHARACTERISTIC(IDENTIFY, switch_identify),
            NULL
        }),
        HOMEKIT_SERVICE(SWITCH, .primary=true, .characteristics=(homekit_characteristic_t*[]){
            HOMEKIT_CHARACTERISTIC(NAME, "Switch"),
            &switch_on,
            NULL
        }),
        NULL
    }),
    NULL
};

homekit_server_config_t config = {
    .accessories = accessories,
    .password = "111-88-111"
};

void create_accessory_name() {
    uint8_t macaddr[6] = {0x01, 0x02, 0x03, 0x4, 0x5, 0x6};
    int name_len = snprintf(NULL, 0, "Switch-%02X%02X%02X",
                            macaddr[3], macaddr[4], macaddr[5]);
    char *name_value = malloc(name_len+1);
    snprintf(name_value, name_len+1, "Switch-%02X%02X%02X",
             macaddr[3], macaddr[4], macaddr[5]);
    name.value = HOMEKIT_STRING(name_value);
}

void main(void) {
    create_accessory_name();
    homekit_server_init(&config);
}
