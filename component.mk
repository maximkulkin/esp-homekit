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
# Maximum number of simultaneous clients allowed.
# Each connected client requires ~1100-1200 bytes of RAM.
HOMEKIT_MAX_CLIENTS ?= 16
# Set to 1 to enable WolfSSL low resources, saving about 70KB in firmware size,
# but increasing pair verify time from 0.5 to 3.6 secs.
WOLFSSL_LOWRESOURCES_CFLAGS ?= 0
# Set to 1 to disable overclock on pair-verify function (Will increase pair verify time to double).
HOMEKIT_DISABLE_OVERCLOCK ?= 0

INC_DIRS += $(homekit_ROOT)/include

homekit_INC_DIR = $(homekit_ROOT)/include $(homekit_ROOT)/src
homekit_SRC_DIR = $(homekit_ROOT)/src

$(eval $(call component_compile_rules,homekit))

EXTRA_WOLFSSL_CFLAGS = \
	-DWOLFCRYPT_HAVE_SRP \
	-DWOLFSSL_SHA512 \
	-DNO_MD5 \
	-DNO_SHA \
	-DHAVE_HKDF \
	-DHAVE_CHACHA \
	-DHAVE_POLY1305 \
	-DHAVE_ED25519 \
	-DHAVE_CURVE25519 \
	-DWOLFCRYPT_ONLY

ifeq ($(WOLFSSL_LOWRESOURCES_CFLAGS),1)
EXTRA_WOLFSSL_CFLAGS += -DNO_SESSION_CACHE \
	-DRSA_LOW_MEM \
	-DGCM_SMALL \
	-DCURVE25519_SMALL \
	-DED25519_SMALL \
	-DUSE_SLOW_SHA512
endif

wolfssl_CFLAGS += $(EXTRA_WOLFSSL_CFLAGS)
homekit_CFLAGS += $(EXTRA_WOLFSSL_CFLAGS) \
	-DSPIFLASH_BASE_ADDR=$(HOMEKIT_SPI_FLASH_BASE_ADDR) \
	-DHOMEKIT_MAX_CLIENTS=$(HOMEKIT_MAX_CLIENTS)

ifeq ($(HOMEKIT_DISABLE_OVERCLOCK),1)
homekit_CFLAGS += -DHOMEKIT_DISABLE_OVERCLOCK
endif

ifeq ($(HOMEKIT_DEBUG),1)
homekit_CFLAGS += -DHOMEKIT_DEBUG
endif
