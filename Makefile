OBJ=\
src/storage.o \
src/accessories.o \
src/crypto.o \
src/debug.o \
src/json.o \
src/pairing.o \
src/query_params.o \
src/tlv.o \
src/server.o \
src/mdnsresponder.o \
http-parser/http_parser.o \
src/main.o \
cJSON/cJSON.o \


CC=mips-openwrt-linux-gcc

CFLAGS=-g -Iinclude -Iwolfssl -I. -IcJSON -Isrc \
	   -DWOLFSSL_USER_SETTINGS \
	   -DHOMEKIT_SHORT_APPLE_UUIDS \
	   -Werror=implicit-function-declaration \
     -DMDNS_RESPONDER_INTERFACE=\"$(MDNS_INTERFACE)\" \

derpkit: wolfssl/src/.libs/libwolfssl.a $(OBJ)
	$(CC) -g $(OBJ) wolfssl/src/.libs/libwolfssl.a -o  $@ -lpthread

wolfssl/src/.libs/libwolfssl.a:
	#cd wolfssl && ./autogen.sh && ./configure  --enable-static --enable-all && $(MAKE)
	cd wolfssl && ./autogen.sh && ./configure --host=mips-openwrt-linux --enable-static --enable-all && $(MAKE)

cJSON/libcjson.a:
	cd cJSON && $(MAKE)

clean: 
	#cd wolfssl && git clean -fxd;
	rm -f $(OBJ)
