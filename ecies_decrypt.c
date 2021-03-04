#include <stdio.h>
#include <string.h>
#include "ecies.h"

#define err(fmt, ...)                                \
        do {                                         \
                printf("ERROR:" fmt, ##__VA_ARGS__); \
                exit(1);                             \
        } while (0)

#define log(fmt, ...)                       \
        do {                                \
                printf(fmt, ##__VA_ARGS__); \
        } while (0)


int main(int argc, char * argv[])
{
        EC_KEY *ec_key = NULL; // EC key from key file

        // Receiver's EC Key (public, private, curve)
        uint8_t *pubk      = NULL;
        uint32_t   pubk_len  = 0;
        uint8_t *privk     = NULL;
        uint32_t   privk_len = 0;
        int      curve;

        // Transmitter's ephemeral public EC Key
        uint8_t *epubk     = NULL;

        // payload details
        char *payload_fname = "payload.enc";

        uint8_t *epubk_r      = NULL;
        uint32_t   epubk_len_r  = 0;
        uint8_t *iv_r             = NULL;
        uint8_t  iv_len_r         = 0;
        uint8_t *tag_r            = NULL;
        uint8_t  tag_len_r        = 0;
        uint8_t *ciphertext_r     = NULL;
        uint32_t  ciphertext_len_r = 0;
        
        if (argc != 2)
                err("Specify init key file in DER format\n"
                    "Usage: %s <file.der> \n", argv[0]);
        
        /* Loads the initialization EC key. */
        ecies_load_init_key(argv[1], &ec_key, &curve,
                                &pubk, &pubk_len, &privk, &privk_len);

        /*
         * Now initialization key loaded:
         *   - 'ppub'  holds the public key in uncompressed binary format
         *   - 'ppriv' holds the private key in binary format
         *   - 'curve' holds the curve name in ID format
         */
        /*
         * Read the ecnrypted payload from the "payload.enc" file
         */
        ecies_encrypted_payload_read(
                                      payload_fname,
                                      curve,
                                      &epubk_r,(uint32_t*)&epubk_len_r,
                                      &iv_r,&iv_len_r,
                                      &tag_r,&tag_len_r,
                                      &ciphertext_r,&ciphertext_len_r);

        log("\n--> ecies_encrypted_payload_read finished <--\n\n");

        /* Decrypts the payload.enc file */
        ecies_decrypt_message(  ec_key, epubk_r, epubk_len_r,
                                iv_r, iv_len_r, tag_r, tag_len_r,
                                ciphertext_r, ciphertext_len_r);

        OPENSSL_free(iv_r);
        OPENSSL_free(tag_r);
        OPENSSL_free(ciphertext_r);
        OPENSSL_free(epubk);
        OPENSSL_free(pubk);
        OPENSSL_free(privk);

        return 0;
}