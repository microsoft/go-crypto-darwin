// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef CRYPTOKIT_H
#define CRYPTOKIT_H

#include <stdint.h>
#include <stddef.h>

// AES GCM encryption and decryption
extern int encryptAESGCM(const uint8_t* key, size_t keyLength, const uint8_t* data, size_t dataLength, const uint8_t* nonce, size_t nonceLength, const uint8_t* aad, size_t aadLength, uint8_t* cipherText, size_t cipherTextLength, uint8_t* tag);
extern int decryptAESGCM(const uint8_t* key, size_t keyLength, const uint8_t* data, size_t dataLength, const uint8_t* nonce, size_t nonceLength, const uint8_t* aad, size_t aadLength, const uint8_t* tag, size_t tagLength, uint8_t* out, size_t* outLength);

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
