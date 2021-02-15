#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#ifndef ECIES_H
#define ECIES_H

int ecies_load_init_key(        char     *filename,
                                EC_KEY  **ec_key,    // out
                                int      *curve,     // out
                                uint8_t **pubk,      // out (caller should free)
                                size_t   *pubk_len,  // out
                                uint8_t **privk,     // out (caller should  free)
                                size_t   *privk_len); // out

int ecies_encrypt_message(      uint8_t        *msg,
                                size_t          msg_len,
                                int             curve,
                                const uint8_t  *peer_pubk,
                                const uint8_t   peer_pubk_len,
                                uint8_t       **epubk,          // out (caller should  free)
                                size_t         *epubk_len,      // out
                                uint8_t       **iv,             // out (caller should  free)
                                uint8_t        *iv_len,         // out
                                uint8_t       **tag,            // out (caller should  free)
                                uint8_t        *tag_len,        // out
                                uint8_t       **ciphertext,     // out (caller should  free)
                                uint8_t        *ciphertext_len); // out

int ecies_decrypt_message(      const EC_KEY  *ec_key,
                                const uint8_t *peer_pubk,
                                const uint8_t  peer_pubk_len,
                                uint8_t       *iv,
                                uint32_t       iv_len,
                                uint8_t       *tag,
                                uint32_t       tag_len,
                                uint8_t       *ciphertext,
                                uint32_t       ciphertext_len);
#endif //ECIES_H