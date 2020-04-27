idf_component_register(
    SRCS
        "src/json.c"
        "src/storage.c"
        "src/tlv.c"
        "src/server.c"
        "src/debug.c"
        "src/accessories.c"
        "src/base64.c"
        "src/port.c"
        "src/query_params.c"
        "src/crypto.c"
    INCLUDE_DIRS include
    PRIV_INCLUDE_DIRS src
    REQUIRES wolfssl json http-parser mdns spi_flash
)

set_source_files_properties(src/storage.c
    PROPERTIES COMPILE_FLAGS
    -Wno-error=unused-value
)

set(WOLFSSL_C_FLAGS
    "-DWOLFCRYPT_HAVE_SRP \
    -DWOLFSSL_SHA512 \
    -DWOLFSSL_BASE64_ENCODE \
    -DNO_MD5 \
    -DNO_SHA \
    -DHAVE_HKDF \
    -DHAVE_CHACHA \
    -DHAVE_POLY1305 \
    -DHAVE_ED25519 \
    -DHAVE_CURVE25519 \
    -DNO_SESSION_CACHE \
    -DRSA_LOW_MEM \
    -DGCM_SMALL \
    -DUSE_SLOW_SHA512 \
    -DWC_NO_HARDEN \
    -DWOLFCRYPT_ONLY"
)

if(CONFIG_HOMEKIT_SMALL)
    set(WOLFSSL_C_FLAGS "${WOLFSSL_C_FLAGS} -DCURVE25519_SMALL -DED25519_SMALL")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    ${WOLFSSL_C_FLAGS} \
    -DHOMEKIT_MAX_CLIENTS=${CONFIG_HOMEKIT_MAX_CLIENTS} \
    -DSPIFLASH_BASE_ADDR=${CONFIG_HOMEKIT_SPI_FLASH_BASE_ADDR} \
    -DESP_IDF"
)

if(CONFIG_HOMEKIT_DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHOMEKIT_DEBUG")
endif()
