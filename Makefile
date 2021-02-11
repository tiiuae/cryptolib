
CC=clang
CFLAGS=-Wall

OPENSSL_ARGS=$(CFLAGS) \
	  -I/usr/local/opt/openssl/include \
	  -L/usr/local/opt/openssl/lib
ECIES_SRC=ecies_openssl.c
ECIES_BIN=ecies

all:
	$(CC) -o $@ $(OPENSSL_ARGS)  -lcrypto  -o $(ECIES_BIN)  $(ECIES_SRC)

cert:
	openssl ecparam -name prime256v1 -noout -genkey -conv_form uncompressed -outform DER -out ecc_key.der

clean:
	rm -f ossl

