set(homekit_SRCS
    "src/accessories.c"
    "src/base64.c"
    "src/bitset.c"
    "src/crypto.c"
    "src/debug.c"
    "src/json.c"
    "src/port.c"
    "src/port_mdns_idf.c"
    "src/query_params.c"
    "src/server.c"
    "src/storage.c"
    "src/tlv.c"
)
set(homekit_REQUIRES wolfssl json http-parser mdns)

set(homekit_COMPILE_OPTIONS
    "-Wno-error=unused-variable"
    "-DHOMEKIT_MAX_CLIENTS=${CONFIG_HOMEKIT_MAX_CLIENTS}"
    "-DESP_IDF"
)

if (${IDF_VERSION_MAJOR} LESS 5)
    list(APPEND homekit_SRCS "src/port_storage_spiflash.c")
    list(APPEND homekit_REQUIRES spi_flash)
    list(APPEND homekit_COMPILE_OPTIONS -DSPIFLASH_BASE_ADDR=${CONFIG_HOMEKIT_SPI_FLASH_BASE_ADDR})
else()
    list(APPEND homekit_SRCS "src/port_storage_partition.c")
    list(APPEND homekit_REQUIRES esp_partition esp_hw_support esp_system)
endif()

idf_component_register(
    SRCS ${homekit_SRCS}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    REQUIRES ${homekit_REQUIRES}
)

list(APPEND EXTRA_WOLFSSL_COMPILE_OPTIONS
    -DWOLFCRYPT_HAVE_SRP
    -DWOLFSSL_SHA512
    -DWOLFSSL_BASE64_ENCODE
    -DNO_MD5
    -DNO_SHA
    -DNO_DSA
    -DHAVE_HKDF
    -DHAVE_CHACHA
    -DHAVE_POLY1305
    -DHAVE_ED25519
    -DHAVE_CURVE25519
    -DNO_SESSION_CACHE
    -DRSA_LOW_MEM
    -DGCM_SMALL
    -DUSE_SLOW_SHA512
    -DWOLFCRYPT_ONLY
)

if(CONFIG_HOMEKIT_SMALL)
    list(APPEND EXTRA_WOLFSSL_COMPILE_OPTIONS -DCURVE25519_SMALL -DED25519_SMALL)
endif()

idf_build_set_property(COMPILE_OPTIONS "${EXTRA_WOLFSSL_COMPILE_OPTIONS}" APPEND)

if(CONFIG_HOMEKIT_DEBUG)
    list(APPEND homekit_COMPILE_OPTIONS PRIVATE -DHOMEKIT_DEBUG)
endif()
target_compile_options(${COMPONENT_LIB} PRIVATE ${homekit_COMPILE_OPTIONS})
