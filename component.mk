# Component makefile for homekit
ifndef wolfssl_ROOT
$(error Please include wolfssl component prior to homekit)
endif

ifndef cJSON_ROOT
$(error Please include cJSON component prior to homekit)
endif

ifndef http-parser_ROOT
$(error Please include http-parser component prior to homekit)
endif

# Base flash address where persisted information (e.g. pairings) will be stored
HOMEKIT_SPI_FLASH_BASE_ADDR ?= 0x100000

INC_DIRS += $(homekit_ROOT)/include

homekit_INC_DIR = $(homekit_ROOT)/include $(homekit_ROOT)/src
homekit_SRC_DIR = $(homekit_ROOT)/src

$(eval $(call component_compile_rules,homekit))

EXTRA_WOLFSSL_CFLAGS = \
	-DWOLFCRYPT_HAVE_SRP \
	-DWOLFSSL_SHA512 \
	-DHAVE_HKDF \
	-DHAVE_CHACHA \
	-DHAVE_POLY1305 \
	-DHAVE_ED25519 \
	-DHAVE_CURVE25519

wolfssl_CFLAGS += $(EXTRA_WOLFSSL_CFLAGS)
homekit_CFLAGS += $(EXTRA_WOLFSSL_CFLAGS) \
	-DSPIFLASH_BASE_ADDR=$(HOMEKIT_SPI_FLASH_BASE_ADDR)

ifeq ($(HOMEKIT_DEBUG),1)
homekit_CFLAGS += -DHOMEKIT_DEBUG
endif
