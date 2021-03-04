
/*
 * Home: https://github.com/tiiuae/cryptolib.git
 */

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

/*
 * This function takes a buffer with binary data and dumps
 * out a hex string prefixed with a label.
 */
void dump_hex(char *label, uint8_t *buf, int len)
{
        int i;
        log("%-10s: ", label);
        for (i = 0; i < len; ++i) { log("%02x", buf[i]); }
        log("\n");
}

/* Convert an EC key's public key to a binary array. */
int ec_key_public_key_to_bin(const EC_KEY  *ec_key,
                             uint8_t      **pubk,     // out (must free)
                             uint32_t        *pubk_len) // out
{
        const EC_GROUP *ec_group   = EC_KEY_get0_group(ec_key);
        const EC_POINT *pub        = EC_KEY_get0_public_key(ec_key);
        BIGNUM         *pub_bn     = BN_new();
        BN_CTX         *pub_bn_ctx = BN_CTX_new();

        BN_CTX_start(pub_bn_ctx);

        EC_POINT_point2bn(ec_group, pub, POINT_CONVERSION_UNCOMPRESSED,
                          pub_bn, pub_bn_ctx);

        *pubk_len = BN_num_bytes(pub_bn);
        *pubk = OPENSSL_malloc(*pubk_len);

        if (BN_bn2bin(pub_bn, *pubk) != *pubk_len)
                err("Failed to decode pubkey\n");

        BN_CTX_end(pub_bn_ctx);
        BN_CTX_free(pub_bn_ctx);
        BN_clear_free(pub_bn);

        return 0;
}

/* Convert an EC key's private key to a binary array. */
int ec_key_private_key_to_bin(const EC_KEY  *ec_key,
                              uint8_t      **privk,     // out (must free)
                              uint32_t        *privk_len) // out
{
        const BIGNUM *priv = EC_KEY_get0_private_key(ec_key);

        *privk_len = BN_num_bytes(priv);
        *privk = OPENSSL_malloc(*privk_len);

        if (BN_bn2bin(priv, *privk) != *privk_len)
                err("Failed to decode privkey\n");

        return 0;
}

/* Convert a public key binary array to an EC point. */
int ec_key_public_key_bin_to_point(const EC_GROUP  *ec_group,
                                   const uint8_t   *pubk,
                                   const uint32_t     pubk_len,
                                   EC_POINT       **pubk_point) // out
{
        BIGNUM   *pubk_bn;
        BN_CTX   *pubk_bn_ctx;

        *pubk_point = EC_POINT_new(ec_group);

        pubk_bn = BN_bin2bn(pubk, pubk_len, NULL);
        pubk_bn_ctx = BN_CTX_new();
        BN_CTX_start(pubk_bn_ctx);

        EC_POINT_bn2point(ec_group, pubk_bn, *pubk_point, pubk_bn_ctx);

        BN_CTX_end(pubk_bn_ctx);
        BN_CTX_free(pubk_bn_ctx);
        BN_clear_free(pubk_bn);

        return 0;
}

/* (TX) Generate an ephemeral EC key and associated shared symmetric key. */
int ecies_transmitter_generate_symkey(const int       curve,
                                      const uint8_t  *peer_pubk,
                                      const uint32_t    peer_pubk_len,
                                      uint8_t       **epubk,         // out (must free)
                                      uint32_t         *epubk_len,     // out
                                      uint8_t       **skey,          // out (must free)
                                      uint32_t         *skey_len)      // out
{
        EC_KEY         *ec_key          = NULL; /* ephemeral keypair */
        const EC_GROUP *ec_group        = NULL;
        EC_POINT       *peer_pubk_point = NULL;

        /* Create and initialize a new empty key pair on the curve. */
        ec_key = EC_KEY_new_by_curve_name(curve);
        EC_KEY_generate_key(ec_key);
        ec_group = EC_KEY_get0_group(ec_key);

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = ((EC_GROUP_get_degree(ec_group) + 7) / 8);
        *skey     = OPENSSL_malloc(*skey_len);

        /* Convert the peer public key to an EC point. */
        ec_key_public_key_bin_to_point(ec_group, peer_pubk, peer_pubk_len,
                                       &peer_pubk_point);

        /* Generate the shared symmetric key (diffie-hellman primitive). */
        *skey_len = ECDH_compute_key(*skey, *skey_len, peer_pubk_point,
                                     ec_key, NULL);

        /* Write the ephemeral key's public key to the output buffer. */
        ec_key_public_key_to_bin(ec_key, epubk, epubk_len);

        /*
         * NOTE: The private key is thrown away here...
         * With ECIES the transmitter EC key pair is a one time use only.
         */

        return 0;
}

/* (RX) Generate the shared symmetric key. */
int ecies_receiver_generate_symkey(const EC_KEY   *ec_key,
                                   const uint8_t  *peer_pubk,
                                   const uint32_t    peer_pubk_len,
                                   uint8_t       **skey,          // out (must free)
                                   uint32_t         *skey_len)      // out
{
        const EC_GROUP *ec_group        = EC_KEY_get0_group(ec_key);
        EC_POINT       *peer_pubk_point = NULL;

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = ((EC_GROUP_get_degree(ec_group) + 7) / 8);
        *skey     = OPENSSL_malloc(*skey_len);

        /* Convert the peer public key to an EC point. */
        ec_key_public_key_bin_to_point(ec_group, peer_pubk, peer_pubk_len,
                                       &peer_pubk_point);

        /* Generate the shared symmetric key (diffie-hellman primitive). */
        *skey_len = ECDH_compute_key(*skey, *skey_len, peer_pubk_point,
                                     (EC_KEY *)ec_key, NULL);

        return 0;
}

/* Encrypt plaintext data using 256b AES-GCM. */
int aes_gcm_256b_encrypt(uint8_t  *plaintext,
                         size_t    plaintext_len,
                         uint8_t  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t **iv,             // out (must free)
                         uint8_t  *iv_len,         // out
                         uint8_t **tag,            // out (must free)
                         uint8_t  *tag_len,        // out
                         uint8_t **ciphertext,     // out (must free)
                         uint32_t  *ciphertext_len) // out
{
        EVP_CIPHER_CTX *ctx;
        uint32_t len;

        /* Allocate buffers for the IV, tag, and ciphertext. */
        *iv_len = 12;
        *iv = OPENSSL_malloc(*iv_len);
        *tag_len = 12;
        *tag = OPENSSL_malloc(*tag_len);
        *ciphertext = OPENSSL_malloc((plaintext_len + 0xf) & ~0xf);

        /* Create and initialise the context */
        ctx = EVP_CIPHER_CTX_new();
        
        /* Initialise the encryption operation. */
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

        /* Generate a new random IV. */
        RAND_bytes(*iv, *iv_len);

        /* Initialise key and IV */
        EVP_EncryptInit_ex(ctx, NULL, NULL, skey, *iv);

         /*
          * Provide any AAD data. This can be called zero or more times as
          * required
          */
        if (aad && aad_len)
            EVP_EncryptUpdate(ctx, NULL, (int *)&len, aad, aad_len);

        /* Provide the text to be encrypted, and obtain the encrypted output. */
        EVP_EncryptUpdate(ctx, *ciphertext, (int *)&len, plaintext, plaintext_len);
        *ciphertext_len = len;

        /* Finalize the encryption. */
        EVP_EncryptFinal_ex(ctx, (*ciphertext + len), (int *)&len);
        *ciphertext_len += len;

        /* Get the authentication tag. */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tag_len, *tag);

        EVP_CIPHER_CTX_free(ctx);

        return 0;
}

/* Decrypt ciphertext data using 256b AES-GCM. */
int aes_gcm_256b_decrypt(uint8_t  *ciphertext,
                         uint32_t    ciphertext_len,
                         uint8_t  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t  *iv,
                         uint8_t   iv_len,
                         uint8_t  *tag,
                         size_t    tag_len,
                         uint8_t **plaintext,     // out (caller should  free)
                         uint32_t  *plaintext_len) // out
{
        EVP_CIPHER_CTX *ctx;
        uint32_t len, rc;

        /* Allocate a buffer for the plaintext. */
        *plaintext = OPENSSL_malloc(ciphertext_len);

        /* Create and initialise the context */
        ctx = EVP_CIPHER_CTX_new();

        /* Initialise the encryption operation. */
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

        /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
        
        /* Initialise key and IV */
        EVP_DecryptInit_ex(ctx, NULL, NULL, skey, iv);

        /* Provide any AAD data. */
        if (aad && aad_len)
                EVP_DecryptUpdate(ctx, NULL, (int *)&len, aad, aad_len);

        /* Provide the ciphertext to be decrypted, and obtain the plaintext output. */
        EVP_DecryptUpdate(ctx, *plaintext, (int *)&len, ciphertext, ciphertext_len);
        *plaintext_len = len;

        /* Set the expected tag value. */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag);

        /* 
         * Finalize the decryption. A positive return value indicates success, 
         * anything else is a failure - the plaintext is not trustworthy. 
         */
        rc = EVP_DecryptFinal_ex(ctx, (*plaintext + len), (int *)&len);

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        if (rc > 0)
        {
                *plaintext_len += len;
                return 0;
        }

        /* verification failed */
        err("Decryption verification failed\n");
}

int ecies_load_init_key(        char     *filename,
                                EC_KEY  **ec_key,    // out
                                int      *curve,     // out
                                uint8_t **pubk,      // out (caller should  free)
                                uint32_t   *pubk_len,  // out
                                uint8_t **privk,     // out (caller should  free)
                                uint32_t   *privk_len) // out
{
        const EC_GROUP *ec_group = NULL;
        BIO            *bio_key  = NULL;
        BIO            *bio_out  = NULL; /* stdout */

        /*
         * Create a BIO object wrapping a file pointer to read the EC key file
         * in DER format. Then read in and parse the EC key from the file.
         */
        bio_key = BIO_new_file(filename, "r");
        if (bio_key == NULL)
                err("Failed to read EC key file '%s'\n", filename);
        *ec_key = d2i_ECPrivateKey_bio(bio_key, NULL);
        if (*ec_key == NULL)
                err("Failed to parse EC key file '%s'\n", filename);
        BIO_free(bio_key);

        /* Get the curve parameters from the EC key. */
        ec_group = EC_KEY_get0_group(*ec_key);

        /* Create a BIO object wrapping stdout. */
        bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

        /* Set the point conversion outputs to always be 'uncompressed'. */
        EC_KEY_set_conv_form(*ec_key, POINT_CONVERSION_UNCOMPRESSED);

        /* Get the EC key's public key in a binary array format. */
        ec_key_public_key_to_bin(*ec_key, pubk, pubk_len);

        /* Get the EC key's private key in a binary array format. */
        ec_key_private_key_to_bin(*ec_key, privk, privk_len);

        /* Get the EC key's curve name. */
        *curve = EC_GROUP_get_curve_name(ec_group);

        log("--> Initialization key LOADED FROM FILE  <--\n\n");
        dump_hex("pubkey", *pubk, *pubk_len);
        dump_hex("privkey", *privk, *privk_len);
        log("%-10s: %s(%d)\n", "curve", OBJ_nid2sn(*curve), *curve);

        log("--------------------------------------------------------------------\n");
        return 0;
}

int ecies_encrypt_message(      uint8_t        *msg,
                                size_t          msg_len,
                                int             curve,
                                const uint8_t  *peer_pubk,
                                const uint8_t   peer_pubk_len,
                                uint8_t       **epubk,          // out (caller should  free)
                                uint32_t         *epubk_len,      // out
                                uint8_t       **iv,             // out (caller should  free)
                                uint8_t        *iv_len,         // out
                                uint8_t       **tag,            // out (caller should  free)
                                uint8_t        *tag_len,        // out
                                uint8_t       **ciphertext,     // out (caller should  free)
                                uint32_t        *ciphertext_len) // out
{
        uint8_t *skey      = NULL; // DH generated shared symmetric key
        uint32_t   skey_len  = 0;

        /* Generate the shared symmetric key (transmitter). */
        ecies_transmitter_generate_symkey(curve, peer_pubk, peer_pubk_len,
                                          epubk, epubk_len, &skey, &skey_len);
        if (skey_len != 32)
                err("Invalid symkey length %lub (expecting 256b)\n",
                    (skey_len * 8));

        log("-->  [Encrypt] EPHEMERAL EC PUBLIC KEY AND SYMMETRIC KEY  <--\n\n");
        dump_hex("epubkey", *epubk, *epubk_len);
        dump_hex("symkey", skey, skey_len);
        log("--------------------------------------------------------------------\n");
        /* Encrypt the data using 256b AES-GCM. */
        aes_gcm_256b_encrypt(msg, msg_len, skey, NULL, 0,
                             iv, iv_len, tag, tag_len,
                             ciphertext, ciphertext_len);

        log("-->  AES-256-GCM ENCRYPTED DATA  <--\n\n");
        log("%-10s: (%lu) %s\n", "plain-tx", msg_len, msg); // it's a string
        dump_hex("iv", *iv, *iv_len);
        dump_hex("tag", *tag, *tag_len);
        dump_hex("cipher", *ciphertext, *ciphertext_len);
        log("--------------------------------------------------------------------\n");
        free(skey);

        return 0;
}

void base64_encode(const char * input,char** output,int in_length)
{
    BIO* bmem = NULL;
    BIO* b64 = NULL;
    BUF_MEM* bptr = NULL;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, in_length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    *output = (char *)malloc(bptr->length + 1);
    memcpy(*output, bptr->data, bptr->length);
    (*output)[bptr->length] = 0;
    BIO_free_all(b64);

    return;
}

void base64_decode(const char * input, char** output,int* out_length)
{
    BIO* b64 = NULL;
    BIO* bio = NULL;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(input, strlen(input));
    bio = BIO_push(b64, bio);
    *output = (char*)malloc(strlen(input));
    *out_length = BIO_read(bio, *output, strlen(input));
    BIO_free_all(bio);

    return;
}

int ecies_encrypted_payload_write(
                                char          *payload_fname,
                                int           curve,
                                uint8_t       *epubk,      
                                uint32_t        epubk_len,
                                uint8_t       *iv,
                                uint8_t       iv_len,
                                uint8_t       *tag,
                                uint8_t       tag_len,
                                uint8_t       *ciphertext,
                                uint32_t       ciphertext_len)
{
        int ret_val = 0;
        unsigned char *output_buf = NULL;
        FILE *fd = fopen(payload_fname, "wb");
        if(fd == 0)
        {
                log("\n Function: ecies_encrypted_payload_write: File creation failed");
                return -1;
        }
        uint8_t is_valid = (epubk_len > 0) && (iv_len > 0) && (tag_len > 0) && (ciphertext_len);

        if(!is_valid)
        {
                log("\n Function: ecies_encrypted_payload_write: Invalid argument");
                ret_val = -1;
                goto cleanup;
        }
        
        uint32_t buf_len = sizeof(curve)
                         + epubk_len      + sizeof(epubk_len) 
                         + iv_len         + sizeof(iv_len)
                         + tag_len        + sizeof(tag_len)
                         + ciphertext_len + sizeof(ciphertext_len);
        
        output_buf = OPENSSL_malloc(buf_len);
        uint32_t offset = 0;
        memset(output_buf, 0, buf_len);
        
        // write directly the curve
        memcpy(output_buf, &curve, sizeof(curve));
        offset += sizeof(curve);

        // Write the epubk length and then epubk byte stream
        memcpy((output_buf+offset), &epubk_len, sizeof(epubk_len));
        offset += sizeof(epubk_len);

        memcpy((output_buf+offset), epubk, epubk_len);
        offset += epubk_len;

        // Write the iv length and then iv byte stream
        memcpy((output_buf+offset), &iv_len, sizeof(iv_len));
        offset += sizeof(iv_len);

        memcpy((output_buf + offset), iv, iv_len);
        offset += iv_len;

        // Write the tag length and then tag byte stream
        memcpy((output_buf+offset), &tag_len, sizeof(tag_len));
        offset += sizeof(tag_len);

        memcpy((output_buf+offset), tag, tag_len);
        offset += tag_len;

        memcpy((output_buf + offset), &ciphertext_len, sizeof(ciphertext_len));
        offset += sizeof(ciphertext_len);

        memcpy((output_buf + offset), ciphertext, ciphertext_len);
        offset += ciphertext_len;

        size_t bytes_written = fwrite(output_buf, 1, buf_len, fd);
        if(bytes_written != buf_len)
        {
                log("\n Function: ecies_encrypted_payload_write: file write error");
                ret_val = -1;
        }

cleanup:
        fclose(fd);
        if(output_buf != NULL)
                OPENSSL_free(output_buf);

        return ret_val;
}

int32_t readfile(char *filename, unsigned char **file_content) {
    
    FILE *fd = fopen(filename, "rb");
    if(fd == NULL) {
        log("\n Function: readfile: file read error");
        return -1;
    }

    // Determine size of the file
    fseek(fd, 0, SEEK_END);
    int32_t file_len = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    // Allocate space for the file
    *file_content = (unsigned char*)malloc(file_len);
    if(*file_content == NULL) {
        log("\n Function: readfile: memory allocation failed");
        return -1;
    }
    // Read the file_content into the buffer
    size_t bytes_read = fread(*file_content, 1, file_len, fd);

    if(bytes_read != file_len) {
       log("\n Function: readfile: file read error, couldnt read requested amount of data");
       return -1;
    }
    fclose(fd);

    return file_len;
}

int ecies_encrypted_payload_read(
                                char          *payload_fname,
                                int           curve,
                                uint8_t       **epubk,      
                                uint32_t        *epubk_len_r,
                                uint8_t       **iv,
                                uint8_t       *iv_len,
                                uint8_t       **tag,
                                uint8_t       *tag_len,
                                uint8_t       **ciphertext,
                                uint32_t       *ciphertext_len)
{
        uint8_t *file_content = NULL;
        if(payload_fname == 0)
        {
                log("\n Function: ecies_encrypted_payload_read: File name invalid");
                return -1;
        }

        uint8_t is_valid = (epubk_len_r != 0) && (iv_len != 0) && (tag_len != 0) && (ciphertext_len != 0);

        if(!is_valid)
        {
                log("\n Function: ecies_encrypted_payload_read: Invalid argument");
                return -1;
        }

        int32_t buf_len = readfile(payload_fname, &file_content);
        uint32_t offset = 0;
        
        curve = *(int *) (file_content + offset);
        offset += sizeof(curve);

        // Read the epubk length and then epubk byte stream
        *epubk_len_r = *(uint32_t *) (file_content + offset);
        offset += sizeof(uint32_t);

        *epubk = (uint8_t *) OPENSSL_malloc(*epubk_len_r);
        memset(*epubk, 0 , *epubk_len_r);
        memcpy(*epubk, (file_content+offset), *epubk_len_r);
        offset += *epubk_len_r;

        // Read the iv length and then iv byte stream
        *iv_len = *(file_content + offset);
        offset += sizeof(uint8_t);
        *iv = OPENSSL_malloc(*iv_len);
        memset(*iv, 0, *iv_len);

        memcpy(*iv, (file_content + offset) ,*iv_len);
        offset += *iv_len;

        // Read the tag length and then tag byte stream
        *tag_len = *(file_content + offset);
        offset += sizeof(uint8_t);

        *tag = OPENSSL_malloc(*tag_len);
        memset(*tag, 0, *tag_len);
        memcpy(*tag, (file_content + offset), *tag_len);
        offset += *tag_len;

        // Read cipher text length and then cipher text stream
        *ciphertext_len = *(uint32_t *)(file_content + offset);
        offset += sizeof(uint32_t);
        *ciphertext = OPENSSL_malloc(*ciphertext_len);
        memset(*ciphertext, 0, *tag_len);
        memcpy(*ciphertext, (file_content + offset), *ciphertext_len);
        offset += *ciphertext_len;

        return 0;
}

int ecies_decrypt_message(      const EC_KEY  *ec_key,
                                const uint8_t *peer_pubk,
                                const uint8_t  peer_pubk_len,
                                uint8_t       *iv,
                                uint32_t       iv_len,
                                uint8_t       *tag,
                                uint32_t       tag_len,
                                uint8_t       *ciphertext,
                                uint32_t       ciphertext_len)
{
        // Shared symmetric encryption key (DH generated)
        uint8_t *skey     = NULL;
        uint32_t   skey_len = 0;

        // Decrypted data (plaintext)
        uint8_t *plaintext     = NULL;
        uint32_t  plaintext_len = 0;

        /* Generate the shared symmetric key (receiver). */
        ecies_receiver_generate_symkey(ec_key, peer_pubk, peer_pubk_len,
                                       &skey, &skey_len);
        if (skey_len != 32)
                err("Invalid symkey length %lub (expecting 256b)\n",
                    (skey_len * 8));

        log("--> [Decrypt] Generated SYMMETRIC KEY  <--\n\n");
        dump_hex("symkey", skey, skey_len);
        log("--------------------------------------------------------------------\n");
        /* Decrypt the data using 256b AES-GCM. */
        aes_gcm_256b_decrypt(ciphertext, ciphertext_len, skey, NULL, 0,
                             iv, iv_len, tag, tag_len,
                             &plaintext, &plaintext_len);

        log("-->  [Decrypt] AES-GCM DECRYPTED DATA  <--\n\n");
        log("%-10s: (%d) %s\n", "plain-rx", plaintext_len, plaintext);
        log("--------------------------------------------------------------------\n");
        free(skey);
        free(plaintext);

        return 0;
}

