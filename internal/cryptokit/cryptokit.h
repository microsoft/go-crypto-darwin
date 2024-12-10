// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef CRYPTOKIT_H
#define CRYPTOKIT_H

#include <stdint.h>
#include <stddef.h>

// AES GCM encryption and decryption
extern int encryptAESGCM(const uint8_t* key, size_t keyLength, 
                         const uint8_t* data, size_t dataLength, 
                         const uint8_t* nonce, size_t nonceLength, 
                         const uint8_t* aad, size_t aadLength, 
                         uint8_t* cipherText, size_t cipherTextLength, 
                         uint8_t* tag);
extern int decryptAESGCM(const uint8_t* key, size_t keyLength, 
                         const uint8_t* data, size_t dataLength, 
                         const uint8_t* nonce, size_t nonceLength, 
                         const uint8_t* aad, size_t aadLength, 
                         const uint8_t* tag, size_t tagLength, 
                         uint8_t* out, size_t* outLength);

// Generates an Ed25519 keypair.
// The private key is 64 bytes (first 32 bytes are the seed, next 32 bytes are the public key).
// The public key is 32 bytes.
void* generateKeyEd25519();
void freeKeyEd25519(void* key);
void* newPrivateKeyEd25519FromSeed(const uint8_t* seed, int seedLength);
void* newPublicKeyEd25519(const uint8_t* pub, int pubLength);
extern int getPrivateKeyEd25519Bytes(const void* key, uint8_t* buffer, int bufferLength);
extern int extractPublicKeyEd25519(const void* privateKey, uint8_t* buffer, int bufferLength);
extern int signEd25519(const void* privateKey, const uint8_t* message, int messageLength, uint8_t* sigBuffer, int sigBufferLength);
extern int verifyEd25519(const void* publicKey, const uint8_t* message, int messageLength, const uint8_t* sig, int sigLength);

// HKDF key derivation
extern int extractHKDF(int32_t hashFunction, 
                      const uint8_t* secret, size_t secretLength, 
                      const uint8_t* salt, size_t saltLength, 
                      uint8_t* prk, size_t prkLength);
extern int expandHKDF(int32_t hashFunction,
                        const uint8_t* prk, size_t prkLength,
                        const uint8_t* info, size_t infoLength,
                        uint8_t* okm, size_t okmLength);

#endif /* CRYPTOKIT_H */
