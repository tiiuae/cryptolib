
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
ecies ➤ ./ecies ecc_key.der "testing"
```

## Example

```
ecies ➤ ./ecies ecc_key.der "testing"                                                      
[Step1]--> Initialization key LOADED FROM FILE  <--

pubkey    : 04e789a243af0e1cad22effabae7461c63469c2a5df9fd48b3e5daf848595889f9ca8c8f20329f37af0afe1b908d9a673e4abf358a9f77b30f06b69d07e88dc9ed
privkey   : 0dc957099ac71cec80e51245634c8e4a52357b41163da6ccbf532677e9285277
curve     : prime256v1(415)
--------------------------------------------------------------------

 --> Encrypt the data by generating ephemeral key pair <--

[Step2]-->  [Encrypt] EPHEMERAL EC PUBLIC KEY AND SYMMETRIC KEY  <--

epubkey   : 0451f9423d21a40b4badf7e98d643ad5df00ab8ac4f216a36590847d0027c670e8fa3a14fef8058ea71c6f6cf4005d1a04c1bb38108de832b25f2c96c6a7203e5e
symkey    : dc517285057212612f4791e91074f73bde103159092762fee617cb605aa21fda
--------------------------------------------------------------------
[Step2.1]-->  AES-256-GCM ENCRYPTED DATA  <--

plain-tx  : (8) testing
iv        : 017c95c524f09f171de00623
tag       : 6847db923ff6865809919b5f
cipher    : db086eff6c0d621c
--------------------------------------------------------------------

--> sends ephemeral public key, IV, tag, ciphertxt <--

[Step3]--> [Decrypt] Generated SYMMETRIC KEY  <--

symkey    : dc517285057212612f4791e91074f73bde103159092762fee617cb605aa21fda
--------------------------------------------------------------------
[Step3.1]-->  [Decrypt] AES-GCM DECRYPTED DATA  <--

plain-rx  : (8) testing
--------------------------------------------------------------------
ecies ➤
```
