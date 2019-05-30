set(HOMEKIT_SRCS
  "src/json.c"
  "src/pairing.c"
  "src/storage.c"
  "src/tlv.c "
  "src/server.c"
  "src/debug.c"
  "src/accessories.c"
  "src/base64.c"
  "src/port.c"
  "src/query_params.c"
  "src/crypto.c"
  )

set(COMPONENT_SRCS ${HOMEKIT_SRCS})

set(COMPONENT_ADD_INCLUDEDIRS
  "src"
  "include"
  )

set(COMPONENT_PRIV_INCLUDEDIRS "src")
set(COMPONENT_SRCEXCLUDE "src/mdnsresponder.c")
set(COMPONENT_REQUIRES wolfssl cJSON http-parser mdns)

register_component()

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
	-DWOLFCRYPT_ONLY"
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  ${WOLFSSL_C_FLAGS} \
  -DHOMEKIT_MAX_CLIENTS=15 \
  -DSPIFLASH_BASE_ADDR=0xA000 \
  -DHOMEKIT_OVERCLOCK=1 \
  -DHOMEKIT_OVERCLOCK_PAIR_SETUP=1 \
  -DHOMEKIT_OVERCLOCK_PAIR_VERIFY=1 \
  -DHOMEKIT_DEBUG=1 \
  -DESP_IDF \
  -DCURVE25519_SMALL \
  -DED25519_SMALL \
  -Wno-error=unused-value"
)

