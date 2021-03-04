
CC=clang
CFLAGS=-Wall

OPENSSL_ARGS=$(CFLAGS) \
	  -I/usr/local/opt/openssl/include \
	  -L/usr/local/opt/openssl/lib \
	  -L.
ECIES_SRC=ecies_openssl.c
ECIES_BIN=ecies_encrypt
ECIES_D_BIN=ecies_decrypt

all: ecies_encrypt.o libecies.a ecies_decrypt.o
	$(CC) -g -o $@ $(OPENSSL_ARGS)  ecies_encrypt.o -lcrypto -lecies -o $(ECIES_BIN)
	$(CC) -g -o $@ $(OPENSSL_ARGS)  ecies_decrypt.o -lcrypto -lecies -o $(ECIES_D_BIN)

ecies_encrypt.o:
	$(CC) -g -o $@ $(OPENSSL_ARGS) -c ecies_encrypt.c

ecies_decrypt.o:
	$(CC) -g -o $@ $(OPENSSL_ARGS) -c ecies_decrypt.c

ecies_openssl.o:
	$(CC) -g -o $@ $(OPENSSL_ARGS) -lcrypto -c $(ECIES_SRC)

libecies.a: ecies_openssl.o
	ar rcs libecies.a ecies_openssl.o

cert:
	openssl ecparam -name prime256v1 -noout -genkey -conv_form uncompressed -outform DER -out ecc_key.der

clean:
	rm -f ecies_encrypt ecies_decrypt libecies.a *.o

