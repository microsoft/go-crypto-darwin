// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This header file is used by the mkcgo tool to generate cgo and Go bindings
// for the CommonCrypto C API. Run "go generate ." to regenerate the bindings.
// Do not include this file, import "zcryptokit.h" instead.

// mkcgo:static_imports

#ifndef _GO_CRYPTOKIT_SHIMS_H // only include this header once
#define _GO_CRYPTOKIT_SHIMS_H

#include <stddef.h>
#include <stdint.h>

// AES GCM encryption and decryption
int go_encryptAESGCM(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, uint8_t *cipherText, size_t cipherTextLength, uint8_t *tag) __attribute__((static));
int go_decryptAESGCM(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, const uint8_t *tag, size_t tagLength, uint8_t *out, size_t *outLength) __attribute__((static));

// Generates an Ed25519 keypair.
// The private key is 64 bytes (first 32 bytes are the seed, next 32 bytes are the public key). The public key is 32 bytes.
void go_generateKeyEd25519(uint8_t *key) __attribute__((static));
int go_newPrivateKeyEd25519FromSeed(uint8_t *key, const uint8_t *seed) __attribute__((static));
int go_newPublicKeyEd25519(uint8_t *key, const uint8_t *pub) __attribute__((static));
int go_signEd25519(const uint8_t *privateKey, const uint8_t *message, size_t messageLength, uint8_t *sigBuffer) __attribute__((static));
int go_verifyEd25519(const uint8_t *publicKey, const uint8_t *message, size_t messageLength, const uint8_t *sig) __attribute__((static));

// HKDF key derivation
int go_extractHKDF(int32_t hashFunction, const uint8_t *secret, size_t secretLength, const uint8_t *salt, size_t saltLength, uint8_t *prk, size_t prkLength) __attribute__((static));
int go_expandHKDF(int32_t hashFunction, const uint8_t *prk, size_t prkLength, const uint8_t *info, size_t infoLength, uint8_t *okm, size_t okmLength) __attribute__((static));

void *go_initHMAC(int32_t hashFunction, const uint8_t *key, int keyLength) __attribute__((nocallback, static));
void go_freeHMAC(int32_t hashFunction, void *ptr) __attribute__((nocallback, static));
void go_updateHMAC(int32_t hashFunction, void *ptr, const uint8_t *data, int length) __attribute__((noescape, nocallback, static));
void go_finalizeHMAC(int32_t hashFunction, void *ptr, uint8_t *outputPointer) __attribute__((noescape, nocallback, static));
void *go_copyHMAC(int32_t hashAlgorithm, void *ptr) __attribute__((static));

void go_MD5(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static));
void go_SHA1(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static));
void go_SHA256(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static));
void go_SHA384(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static));
void go_SHA512(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static));

void *go_hashNew(int32_t hashAlgorithm) __attribute__((nocallback, static));
void go_hashWrite(int32_t hashAlgorithm, void *ptr, const uint8_t *data, int length) __attribute__((noescape, nocallback, static));
void go_hashSum(int32_t hashAlgorithm, void *ptr, uint8_t *outputPointer) __attribute__((noescape, nocallback, static));
void go_hashReset(int32_t hashAlgorithm, void *ptr) __attribute__((nocallback, static));
int go_hashSize(int32_t hashAlgorithm) __attribute__((nocallback, static));
int go_hashBlockSize(int32_t hashAlgorithm) __attribute__((nocallback, static));
void *go_hashCopy(int32_t hashAlgorithm, void *ptr) __attribute__((nocallback, static));
void go_hashFree(int32_t hashAlgorithm, void *ptr) __attribute__((nocallback, static));

#endif // _GO_CRYPTOKIT_SHIMS_H
