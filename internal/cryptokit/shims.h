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
int64_t go_encryptAESGCM(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, uint8_t *cipherText, size_t cipherTextLength, uint8_t *tag) __attribute__((static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(cipherText, cipherTextLength), slice(tag)));
int64_t go_decryptAESGCM(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, const uint8_t *tag, size_t tagLength, uint8_t *out, size_t *outLength) __attribute__((static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(tag, tagLength), slice(out)));

// ChaChaPoly encryption and decryption
int64_t go_encryptChaChaPoly(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, uint8_t *cipherText, size_t cipherTextLength, uint8_t *tag) __attribute__((static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(cipherText, cipherTextLength), slice(tag)));
int64_t go_decryptChaChaPoly(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, const uint8_t *tag, size_t tagLength, uint8_t *out, size_t *outLength) __attribute__((static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(tag, tagLength), slice(out)));

// Generates an Ed25519 keypair.
// The private key is 64 bytes (first 32 bytes are the seed, next 32 bytes are the public key). The public key is 32 bytes.
void go_generateKeyEd25519(uint8_t *key) __attribute__((static, slice(key)));
int64_t go_newPrivateKeyEd25519FromSeed(uint8_t *key, const uint8_t *seed) __attribute__((static, slice(key), slice(seed)));
int64_t go_newPublicKeyEd25519(uint8_t *key, const uint8_t *pub) __attribute__((static, slice(key), slice(pub)));
int64_t go_signEd25519(const uint8_t *privateKey, const uint8_t *message, size_t messageLength, uint8_t *sigBuffer) __attribute__((static, slice(privateKey), slice(message, messageLength), slice(sigBuffer)));
int64_t go_verifyEd25519(const uint8_t *publicKey, const uint8_t *message, size_t messageLength, const uint8_t *sig) __attribute__((static, slice(publicKey), slice(message, messageLength), slice(sig)));

// HKDF key derivation
int64_t go_extractHKDF(int32_t hashFunction, const uint8_t *secret, size_t secretLength, const uint8_t *salt, size_t saltLength, uint8_t *prk, size_t prkLength) __attribute__((static, slice(secret, secretLength), slice(salt, saltLength), slice(prk, prkLength)));
int64_t go_expandHKDF(int32_t hashFunction, const uint8_t *prk, size_t prkLength, const uint8_t *info, size_t infoLength, uint8_t *okm, size_t okmLength) __attribute__((static, slice(prk, prkLength), slice(info, infoLength), slice(okm, okmLength)));

void *go_initHMAC(int32_t hashFunction, const uint8_t *key, int64_t keyLength) __attribute__((nocallback, static, slice(key, keyLength)));
void go_freeHMAC(int32_t hashFunction, void *ptr) __attribute__((nocallback, static));
void go_updateHMAC(int32_t hashFunction, void *ptr, const uint8_t *data, int64_t length) __attribute__((noescape, nocallback, static, slice(data, length)));
void go_finalizeHMAC(int32_t hashFunction, void *ptr, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(outputPointer)));
void *go_copyHMAC(int32_t hashAlgorithm, void *ptr) __attribute__((static));

void go_MD5(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA1(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA256(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA384(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA512(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
int64_t go_supportsSHA3() __attribute__((nocallback, static));
void go_SHA3_256(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA3_384(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA3_512(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));

void *go_hashNew(int32_t hashAlgorithm) __attribute__((nocallback, static));
void go_hashWrite(int32_t hashAlgorithm, void *ptr, const uint8_t *data, int64_t length) __attribute__((noescape, nocallback, static, slice(data, length)));
void go_hashSum(int32_t hashAlgorithm, void *ptr, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(outputPointer)));
void go_hashReset(int32_t hashAlgorithm, void *ptr) __attribute__((nocallback, static));
int64_t go_hashSize(int32_t hashAlgorithm) __attribute__((nocallback, static));
int64_t go_hashBlockSize(int32_t hashAlgorithm) __attribute__((nocallback, static));
void *go_hashCopy(int32_t hashAlgorithm, void *ptr) __attribute__((nocallback, static));
void go_hashFree(int32_t hashAlgorithm, void *ptr) __attribute__((nocallback, static));

// ML-KEM (Post-quantum key encapsulation mechanism)
int64_t go_supportsMLKEM() __attribute__((nocallback, static));
int64_t go_generateKeyMLKEM768(uint8_t *seed, int64_t seedLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen)));
int64_t go_generateKeyMLKEM1024(uint8_t *seed, int64_t seedLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen)));
int64_t go_deriveEncapsulationKeyMLKEM768(const uint8_t *seed, int64_t seedLen, uint8_t *encapKey, int64_t encapKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(encapKey, encapKeyLen)));
int64_t go_deriveEncapsulationKeyMLKEM1024(const uint8_t *seed, int64_t seedLen, uint8_t *encapKey, int64_t encapKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(encapKey, encapKeyLen)));
int64_t go_encapsulateMLKEM768(const uint8_t *encapKey, int64_t encapKeyLen, uint8_t *sharedKey, int64_t sharedKeyLen, uint8_t *ciphertext, int64_t ciphertextLen) __attribute__((noescape, nocallback, static, slice(encapKey, encapKeyLen), slice(sharedKey, sharedKeyLen), slice(ciphertext, ciphertextLen)));
int64_t go_encapsulateMLKEM1024(const uint8_t *encapKey, int64_t encapKeyLen, uint8_t *sharedKey, int64_t sharedKeyLen, uint8_t *ciphertext, int64_t ciphertextLen) __attribute__((noescape, nocallback, static, slice(encapKey, encapKeyLen), slice(sharedKey, sharedKeyLen), slice(ciphertext, ciphertextLen)));
int64_t go_decapsulateMLKEM768(const uint8_t *seed, int64_t seedLen, const uint8_t *ciphertext, int64_t ciphertextLen, uint8_t *sharedKey, int64_t sharedKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(ciphertext, ciphertextLen), slice(sharedKey, sharedKeyLen)));
int64_t go_decapsulateMLKEM1024(const uint8_t *seed, int64_t seedLen, const uint8_t *ciphertext, int64_t ciphertextLen, uint8_t *sharedKey, int64_t sharedKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(ciphertext, ciphertextLen), slice(sharedKey, sharedKeyLen)));

// ECDH
int64_t go_generateKeyECDH(int32_t curveID, uint8_t *privateKey, int64_t privateKeyLen, uint8_t *publicKey, int64_t publicKeyLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen), slice(publicKey, publicKeyLen)));
int64_t go_publicKeyFromPrivateECDH(int32_t curveID, const uint8_t *privateKey, int64_t privateKeyLen, uint8_t *publicKey, int64_t publicKeyLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen), slice(publicKey, publicKeyLen)));
int64_t go_ecdhSharedSecret(int32_t curveID, const uint8_t *privateKey, int64_t privateKeyLen, const uint8_t *publicKey, int64_t publicKeyLen, uint8_t *sharedSecret, int64_t sharedSecretLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen), slice(publicKey, publicKeyLen), slice(sharedSecret, sharedSecretLen)));
int64_t go_validatePrivateKeyECDH(int32_t curveID, const uint8_t *privateKey, int64_t privateKeyLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen)));
int64_t go_validatePublicKeyECDH(int32_t curveID, const uint8_t *publicKey, int64_t publicKeyLen) __attribute__((noescape, nocallback, static, slice(publicKey, publicKeyLen)));

// ECDSA
int64_t go_generateKeyECDSA(int32_t curveID, uint8_t *x, int64_t xLen, uint8_t *y, int64_t yLen, uint8_t *d, int64_t dLen) __attribute__((noescape, nocallback, static, slice(x, xLen), slice(y, yLen), slice(d, dLen)));
int64_t go_ecdsaSign(int32_t curveID, const uint8_t *d, int64_t dLen, const uint8_t *message, int64_t messageLen, uint8_t *signature, int64_t *signatureLen) __attribute__((noescape, nocallback, static, slice(d, dLen), slice(message, messageLen), slice(signature)));
int64_t go_ecdsaVerify(int32_t curveID, const uint8_t *x, int64_t xLen, const uint8_t *y, int64_t yLen, const uint8_t *message, int64_t messageLen, const uint8_t *signature, int64_t signatureLen) __attribute__((noescape, nocallback, static, slice(x, xLen), slice(y, yLen), slice(message, messageLen), slice(signature, signatureLen)));

#endif // _GO_CRYPTOKIT_SHIMS_H
