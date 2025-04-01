// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef CRYPTOKIT_H
#define CRYPTOKIT_H

#include <stdint.h>
#include <stddef.h>

// AES GCM encryption and decryption
int encryptAESGCM(const uint8_t *key, size_t keyLength,
                  const uint8_t *data, size_t dataLength,
                  const uint8_t *nonce, size_t nonceLength,
                  const uint8_t *aad, size_t aadLength,
                  uint8_t *cipherText, size_t cipherTextLength,
                  uint8_t *tag);
int decryptAESGCM(const uint8_t *key, size_t keyLength,
                  const uint8_t *data, size_t dataLength,
                  const uint8_t *nonce, size_t nonceLength,
                  const uint8_t *aad, size_t aadLength,
                  const uint8_t *tag, size_t tagLength,
                  uint8_t *out, size_t *outLength);

// Generates an Ed25519 keypair.
// The private key is 64 bytes (first 32 bytes are the seed, next 32 bytes are the public key).
// The public key is 32 bytes.
void generateKeyEd25519(uint8_t *key);
int newPrivateKeyEd25519FromSeed(uint8_t *key, const uint8_t *seed);
int newPublicKeyEd25519(uint8_t *key, const uint8_t *pub);
int signEd25519(const uint8_t *privateKey, const uint8_t *message, size_t messageLength, uint8_t *sigBuffer);
int verifyEd25519(const uint8_t *publicKey, const uint8_t *message, size_t messageLength, const uint8_t *sig);

// HKDF key derivation
int extractHKDF(int32_t hashFunction,
                const uint8_t *secret, size_t secretLength,
                const uint8_t *salt, size_t saltLength,
                uint8_t *prk, size_t prkLength);
int expandHKDF(int32_t hashFunction,
               const uint8_t *prk, size_t prkLength,
               const uint8_t *info, size_t infoLength,
               uint8_t *okm, size_t okmLength);

void *initMAC(int32_t hashFunction, const uint8_t *key, int keyLength);
void freeHMAC(int32_t hashFunction, void *ptr);
void updateHMAC(int32_t hashFunction, void *ptr, const uint8_t *data, int length);
void finalizeHMAC(int32_t hashFunction, void *ptr, uint8_t *outputPointer);

void MD5(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer);
void SHA1(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer);
void SHA256(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer);
void SHA384(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer);
void SHA512(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer);

// MD5
void *NewMD5(void);
int MD5Write(void *ptr, const uint8_t *data, int length);
void MD5Sum(void *ptr, uint8_t *outputPointer);
void MD5Reset(void *ptr);
int MD5Size(void);
int MD5BlockSize(void);
void *MD5Copy(void *ptr);
void MD5Free(void *ptr);

// SHA1
void *NewSHA1(void);
void SHA1Write(void *ptr, const uint8_t *data, int length);
void SHA1Sum(void *ptr, uint8_t *outputPointer);
void SHA1Reset(void *ptr);
int SHA1Size(void);
int SHA1BlockSize(void);
void *SHA1Copy(void *ptr);
void SHA1Free(void *ptr);

// SHA256
void *NewSHA256(void);
void SHA256Write(void *ptr, const uint8_t *data, int length);
void SHA256Sum(void *ptr, uint8_t *outputPointer);
void SHA256Reset(void *ptr);
int SHA256Size(void);
int SHA256BlockSize(void);
void *SHA256Copy(void *ptr);
void SHA256Free(void *ptr);

// SHA384
void *NewSHA384(void);
void SHA384Write(void *ptr, const uint8_t *data, int length);
void SHA384Sum(void *ptr, uint8_t *outputPointer);
void SHA384Reset(void *ptr);
int SHA384Size(void);
int SHA384BlockSize(void);
void *SHA384Copy(void *ptr);
void SHA384Free(void *ptr);

// SHA512
void *NewSHA512(void);
void SHA512Write(void *ptr, const uint8_t *data, int length);
void SHA512Sum(void *ptr, uint8_t *outputPointer);
void SHA512Reset(void *ptr);
int SHA512Size(void);
int SHA512BlockSize(void);
void *SHA512Copy(void *ptr);
void SHA512Free(void *ptr);

#endif /* CRYPTOKIT_H */
