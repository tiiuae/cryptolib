
# Elliptic Curve Integrated Encryption Scheme (ECIES)

## Introduction

This program is a proof-of-concept demonstrating an encrypted message
exchange between two entities using Elliptic Curve Cryptography. ECC
public/private key crypto is used in conjunction with the Diffie-Hellman
primitive to allow both sides to independently generate a one-time use
shared secret key that is used for encryption of data using a symmetric
key algorithm. This protocol is originally defined as the Elliptic Curve
Integrated Encryption Scheme (ECIES) though is slightly modified to not
use a KDF function and HMAC algorithm for authentication and integrity
checking. Instead those functions are replaced with AES-GCM which
simplifies the interaction and continues to satisfy the authentication
and integrity requirements.
 
Execution mimics both the Sender and Receiver communicating using
ECIES. At a high level the flow is as follows:

1. Receiver loads the EC key (public/private/curve)
2. Receiver sends its public key and curve to the Transmitter
3. Sender generates a new ephemeral EC key on the curve
4. Sender generates the shared symmetric key
5. Sender encrypts the data and sends its public key and ciphertext to the Receiver
6. Receiver generates the shared symmetric key
7. Receiver descrypts the data

## Building

Compile using `make`.This generates a binary named `ecies`

```
ecies ➤ make
```

## Running

The Receiver's EC key is pulled from a DER file created using the OpenSSL
`ecparam` command. Use the following command to generate an EC keypair
on the `prime256v1` named curve. A new file named `ecc_key.der` will be
created.

```
ecies ➤ make cert
```
Run the programs with a single filename argument specifying the DER file that
contains the Receiver's EC key.

```
For encryption
ecies ➤ ./ecies_encrypt ecc_key.der "testing ecies"

This will generate a payload.enc file which contains the encrypted data along with metadata

For Decryption
ecies ➤ ./ecies_encrypt ecc_key.der

this will read the payload.enc file and decrypt the data
```

## Example

```
ecies ➤ ./ecies_encrypt ecc_key.der "testing ecies"                                                                                                          git:main*
--> Initialization key LOADED FROM FILE  <--

pubkey    : 04ebd2c913d5054194762571fdde97966c4566361aa008375d6c3b22c9de9970d2fdbac13c8f560b45a0c450976b705516b959358c5681396eae6386cf6edf08cb
privkey   : 1270a9583befc0acf115f13300096fb97b491f1d11368127018cf7974ec805ec
curve     : prime256v1(415)
--------------------------------------------------------------------

 --> Encrypt the data by generating ephemeral key pair <--

-->  [Encrypt] EPHEMERAL EC PUBLIC KEY AND SYMMETRIC KEY  <--

epubkey   : 04b6bffa2d0fe1fd353f283881b431273f207bac160d611ebd5ddf01e2324303a023f25e83fb75fc2073af64f34cd83809e082843212fb01179205ebcc1d0cdc3b
symkey    : 4755276eae5fb68a17149dc8e00a47613181ca0d2dde1028f22c76796dec021b
--------------------------------------------------------------------
-->  AES-256-GCM ENCRYPTED DATA  <--

plain-tx  : (14) testing ecies
iv        : 12d10f73d2cf62ef53fa5e96
tag       : 605703d966b3b7fab4c6a8c4
cipher    : aa03bd5e476bf409a7d21c9cb168
--------------------------------------------------------------------

--> Write curve, ephemeral public key, IV, tag, ciphertxt to the payload.enc file<--


--> ecies_encrypted_payload_write finished, output written into payload.enc <--

ecies ➤                                                                                                                                                      git:main*
ecies ➤ ./ecies_decrypt ecc_key.der                                                                                                                          git:main*
--> Initialization key LOADED FROM FILE  <--

pubkey    : 04ebd2c913d5054194762571fdde97966c4566361aa008375d6c3b22c9de9970d2fdbac13c8f560b45a0c450976b705516b959358c5681396eae6386cf6edf08cb
privkey   : 1270a9583befc0acf115f13300096fb97b491f1d11368127018cf7974ec805ec
curve     : prime256v1(415)
--------------------------------------------------------------------

--> ecies_encrypted_payload_read finished <--

--> [Decrypt] Generated SYMMETRIC KEY  <--

symkey    : 4755276eae5fb68a17149dc8e00a47613181ca0d2dde1028f22c76796dec021b
--------------------------------------------------------------------
-->  [Decrypt] AES-GCM DECRYPTED DATA  <--

plain-rx  : (14) testing ecies
--------------------------------------------------------------------
ecies ➤                                                                                            
```
