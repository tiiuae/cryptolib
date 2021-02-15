
CC=clang
CFLAGS=-Wall

OPENSSL_ARGS=$(CFLAGS) \
	  -I/usr/local/opt/openssl/include \
	  -L/usr/local/opt/openssl/lib \
	  -L.
ECIES_SRC=ecies_openssl.c
ECIES_BIN=ecies

all: main.o libecies.a
	$(CC) -o $@ $(OPENSSL_ARGS)  main.o -lcrypto -lecies -o $(ECIES_BIN)

main.o:
	$(CC) -o $@ $(OPENSSL_ARGS) -c main.c

ecies.o:
	$(CC) -o $@ $(OPENSSL_ARGS) -lcrypto -c $(ECIES_SRC)

libecies.a: ecies.o
	ar rcs libecies.a ecies.o

cert:
	openssl ecparam -name prime256v1 -noout -genkey -conv_form uncompressed -outform DER -out ecc_key.der

clean:
	rm -f ecies libecies.a *.o

