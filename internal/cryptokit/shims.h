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
int go_encryptAESGCM(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, uint8_t *cipherText, size_t cipherTextLength, uint8_t *tag) __attribute__((static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(cipherText, cipherTextLength), slice(tag)));
int go_decryptAESGCM(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, const uint8_t *tag, size_t tagLength, uint8_t *out, size_t *outLength) __attribute__((static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(tag, tagLength), slice(out)));

// Generates an Ed25519 keypair.
// The private key is 64 bytes (first 32 bytes are the seed, next 32 bytes are the public key). The public key is 32 bytes.
void go_generateKeyEd25519(uint8_t *key) __attribute__((static, slice(key)));
int go_newPrivateKeyEd25519FromSeed(uint8_t *key, const uint8_t *seed) __attribute__((static, slice(key), slice(seed)));
int go_newPublicKeyEd25519(uint8_t *key, const uint8_t *pub) __attribute__((static, slice(key), slice(pub)));
int go_signEd25519(const uint8_t *privateKey, const uint8_t *message, size_t messageLength, uint8_t *sigBuffer) __attribute__((static, slice(privateKey), slice(message, messageLength), slice(sigBuffer)));
int go_verifyEd25519(const uint8_t *publicKey, const uint8_t *message, size_t messageLength, const uint8_t *sig) __attribute__((static, slice(publicKey), slice(message, messageLength), slice(sig)));

// HKDF key derivation
int go_extractHKDF(int32_t hashFunction, const uint8_t *secret, size_t secretLength, const uint8_t *salt, size_t saltLength, uint8_t *prk, size_t prkLength) __attribute__((static, slice(secret, secretLength), slice(salt, saltLength), slice(prk, prkLength)));
int go_expandHKDF(int32_t hashFunction, const uint8_t *prk, size_t prkLength, const uint8_t *info, size_t infoLength, uint8_t *okm, size_t okmLength) __attribute__((static, slice(prk, prkLength), slice(info, infoLength), slice(okm, okmLength)));

void *go_initHMAC(int32_t hashFunction, const uint8_t *key, int keyLength) __attribute__((nocallback, static, slice(key, keyLength)));
void go_freeHMAC(int32_t hashFunction, void *ptr) __attribute__((nocallback, static));
void go_updateHMAC(int32_t hashFunction, void *ptr, const uint8_t *data, int length) __attribute__((noescape, nocallback, static, slice(data, length)));
void go_finalizeHMAC(int32_t hashFunction, void *ptr, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(outputPointer)));
void *go_copyHMAC(int32_t hashAlgorithm, void *ptr) __attribute__((static));

void go_MD5(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA1(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA256(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA384(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA512(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
int go_supportsSHA3() __attribute__((nocallback, static));
void go_SHA3_256(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA3_384(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA3_512(const uint8_t *inputPointer, size_t inputLength, const uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));

void *go_hashNew(int32_t hashAlgorithm) __attribute__((nocallback, static));
void go_hashWrite(int32_t hashAlgorithm, void *ptr, const uint8_t *data, int length) __attribute__((noescape, nocallback, static, slice(data, length)));
void go_hashSum(int32_t hashAlgorithm, void *ptr, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(outputPointer)));
void go_hashReset(int32_t hashAlgorithm, void *ptr) __attribute__((nocallback, static));
int go_hashSize(int32_t hashAlgorithm) __attribute__((nocallback, static));
int go_hashBlockSize(int32_t hashAlgorithm) __attribute__((nocallback, static));
void *go_hashCopy(int32_t hashAlgorithm, void *ptr) __attribute__((nocallback, static));
void go_hashFree(int32_t hashAlgorithm, void *ptr) __attribute__((nocallback, static));

// ML-KEM (Post-quantum key encapsulation mechanism)
int go_supportsMLKEM() __attribute__((nocallback, static));
int go_generateKeyMLKEM768(uint8_t *seed, int seedLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen)));
int go_generateKeyMLKEM1024(uint8_t *seed, int seedLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen)));
int go_deriveEncapsulationKeyMLKEM768(const uint8_t *seed, int seedLen, uint8_t *encapKey, int encapKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(encapKey, encapKeyLen)));
int go_deriveEncapsulationKeyMLKEM1024(const uint8_t *seed, int seedLen, uint8_t *encapKey, int encapKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(encapKey, encapKeyLen)));
int go_encapsulateMLKEM768(const uint8_t *encapKey, int encapKeyLen, uint8_t *sharedKey, int sharedKeyLen, uint8_t *ciphertext, int ciphertextLen) __attribute__((noescape, nocallback, static, slice(encapKey, encapKeyLen), slice(sharedKey, sharedKeyLen), slice(ciphertext, ciphertextLen)));
int go_encapsulateMLKEM1024(const uint8_t *encapKey, int encapKeyLen, uint8_t *sharedKey, int sharedKeyLen, uint8_t *ciphertext, int ciphertextLen) __attribute__((noescape, nocallback, static, slice(encapKey, encapKeyLen), slice(sharedKey, sharedKeyLen), slice(ciphertext, ciphertextLen)));
int go_decapsulateMLKEM768(const uint8_t *seed, int seedLen, const uint8_t *ciphertext, int ciphertextLen, uint8_t *sharedKey, int sharedKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(ciphertext, ciphertextLen), slice(sharedKey, sharedKeyLen)));
int go_decapsulateMLKEM1024(const uint8_t *seed, int seedLen, const uint8_t *ciphertext, int ciphertextLen, uint8_t *sharedKey, int sharedKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(ciphertext, ciphertextLen), slice(sharedKey, sharedKeyLen)));

// ECDH
int go_generateKeyECDH(int32_t curveID, uint8_t *privateKey, int privateKeyLen, uint8_t *publicKey, int publicKeyLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen), slice(publicKey, publicKeyLen)));
int go_publicKeyFromPrivateECDH(int32_t curveID, const uint8_t *privateKey, int privateKeyLen, uint8_t *publicKey, int publicKeyLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen), slice(publicKey, publicKeyLen)));
int go_ecdhSharedSecret(int32_t curveID, const uint8_t *privateKey, int privateKeyLen, const uint8_t *publicKey, int publicKeyLen, uint8_t *sharedSecret, int sharedSecretLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen), slice(publicKey, publicKeyLen), slice(sharedSecret, sharedSecretLen)));
int go_validatePrivateKeyECDH(int32_t curveID, const uint8_t *privateKey, int privateKeyLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen)));
int go_validatePublicKeyECDH(int32_t curveID, const uint8_t *publicKey, int publicKeyLen) __attribute__((noescape, nocallback, static, slice(publicKey, publicKeyLen)));

// ECDSA
int go_generateKeyECDSA(int32_t curveID, uint8_t *x, uint8_t *y, uint8_t *d) __attribute__((noescape, nocallback, static, slice(x), slice(y), slice(d)));
int go_ecdsaSign(int32_t curveID, const uint8_t *d, int dLen, const uint8_t *message, int messageLen, uint8_t *signature, int *signatureLen) __attribute__((noescape, nocallback, static, slice(d, dLen), slice(message, messageLen), slice(signature)));
int go_ecdsaVerify(int32_t curveID, const uint8_t *x, int xLen, const uint8_t *y, int yLen, const uint8_t *message, int messageLen, const uint8_t *signature, int signatureLen) __attribute__((noescape, nocallback, static, slice(x, xLen), slice(y, yLen), slice(message, messageLen), slice(signature, signatureLen)));

#endif // _GO_CRYPTOKIT_SHIMS_H
