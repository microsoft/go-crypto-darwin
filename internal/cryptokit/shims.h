// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This header declares the C API for the CryptoKit Swift bindings.
//
// It serves two purposes:
// 1. The mkcgo tool parses it to generate cgo and Go bindings.
//    Run "go generate ." to regenerate them.
// 2. Swift's @implementation @c validates that Swift function signatures
//    match these declarations at compile time (via cryptokit.h wrapper).
//
// Type conventions:
//   - Return types and length parameters use `long` (not int64_t) because
//     Swift imports `long` as `Int` and `int64_t` as `Int64`. The Swift
//     implementations use `Int`, so the header must use `long` to match.
//     On macOS (LP64), both are 64-bit.
//   - Buffer size parameters use `size_t` where the mkcgo `slice()` attribute
//     pairs them with a pointer for Go slice generation.
//   - Pointer nullability is declared via `#pragma clang assume_nonnull`
//     (guarded by __clang__) so Swift sees non-optional pointer types.
//     mkcgo parses this file as text and ignores the pragma.
//   - Custom __attribute__ annotations (noescape, nocallback, static, slice)
//     are mkcgo extensions. The cryptokit.h wrapper strips them for clang.
//
// Do not include this file directly; import "zcryptokit.h" instead.

// mkcgo:static_imports

#ifndef _GO_CRYPTOKIT_SHIMS_H // only include this header once
#define _GO_CRYPTOKIT_SHIMS_H

#include <stddef.h>
#include <stdint.h>

// When compiled by clang (e.g. via Swift bridging header), assume all
// pointers are nonnull. mkcgo parses this file as text, not via clang,
// so the #ifdef ensures mkcgo never sees these pragmas.
#ifdef __clang__
#pragma clang assume_nonnull begin
#endif

// AES GCM encryption and decryption
long go_encryptAESGCM(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, uint8_t *cipherText, size_t cipherTextLength, uint8_t *tag) __attribute__((noescape, nocallback, static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(cipherText, cipherTextLength), slice(tag)));
long go_decryptAESGCM(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, const uint8_t *tag, size_t tagLength, uint8_t *out, size_t *outLength) __attribute__((noescape, nocallback, static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(tag, tagLength), slice(out)));

// ChaChaPoly encryption and decryption
long go_encryptChaChaPoly(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, uint8_t *cipherText, size_t cipherTextLength, uint8_t *tag) __attribute__((noescape, nocallback, static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(cipherText, cipherTextLength), slice(tag)));
long go_decryptChaChaPoly(const uint8_t *key, size_t keyLength, const uint8_t *data, size_t dataLength, const uint8_t *nonce, size_t nonceLength, const uint8_t *aad, size_t aadLength, const uint8_t *tag, size_t tagLength, uint8_t *out, size_t *outLength) __attribute__((noescape, nocallback, static, slice(key, keyLength), slice(data, dataLength), slice(nonce, nonceLength), slice(aad, aadLength), slice(tag, tagLength), slice(out)));

// Generates an Ed25519 keypair.
// The private key is 64 bytes (first 32 bytes are the seed, next 32 bytes are the public key). The public key is 32 bytes.
void go_generateKeyEd25519(uint8_t *key) __attribute__((noescape, nocallback, static, slice(key)));
long go_newPrivateKeyEd25519FromSeed(uint8_t *key, const uint8_t *seed) __attribute__((noescape, nocallback, static, slice(key), slice(seed)));
long go_newPublicKeyEd25519(uint8_t *key, const uint8_t *pub) __attribute__((noescape, nocallback, static, slice(key), slice(pub)));
long go_signEd25519(const uint8_t *privateKey, const uint8_t *message, size_t messageLength, uint8_t *sigBuffer) __attribute__((noescape, nocallback, static, slice(privateKey), slice(message, messageLength), slice(sigBuffer)));
long go_verifyEd25519(const uint8_t *publicKey, const uint8_t *message, size_t messageLength, const uint8_t *sig) __attribute__((noescape, nocallback, static, slice(publicKey), slice(message, messageLength), slice(sig)));

// HKDF key derivation
long go_extractHKDF(int32_t hashFunction, const uint8_t *secret, size_t secretLength, const uint8_t *salt, size_t saltLength, uint8_t *prk, size_t prkLength) __attribute__((noescape, nocallback, static, slice(secret, secretLength), slice(salt, saltLength), slice(prk, prkLength)));
long go_expandHKDF(int32_t hashFunction, const uint8_t *prk, size_t prkLength, const uint8_t *info, size_t infoLength, uint8_t *okm, size_t okmLength) __attribute__((noescape, nocallback, static, slice(prk, prkLength), slice(info, infoLength), slice(okm, okmLength)));

void *go_initHMAC(int32_t hashFunction, const uint8_t *key, long keyLength) __attribute__((noescape, nocallback, static, slice(key, keyLength)));
void go_freeHMAC(int32_t hashFunction, void *ptr) __attribute__((noescape, nocallback, static));
void go_updateHMAC(int32_t hashFunction, void *ptr, const uint8_t *data, long length) __attribute__((noescape, nocallback, static, slice(data, length)));
void go_finalizeHMAC(int32_t hashFunction, void *ptr, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(outputPointer)));
void *go_copyHMAC(int32_t hashAlgorithm, void *ptr) __attribute__((noescape, nocallback, static));

void go_MD5(const uint8_t *inputPointer, size_t inputLength, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA1(const uint8_t *inputPointer, size_t inputLength, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA256(const uint8_t *inputPointer, size_t inputLength, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA384(const uint8_t *inputPointer, size_t inputLength, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA512(const uint8_t *inputPointer, size_t inputLength, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
long go_supportsSHA3() __attribute__((noescape, nocallback, static));
void go_SHA3_256(const uint8_t *inputPointer, size_t inputLength, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA3_384(const uint8_t *inputPointer, size_t inputLength, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));
void go_SHA3_512(const uint8_t *inputPointer, size_t inputLength, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(inputPointer, inputLength), slice(outputPointer)));

void *go_hashNew(int32_t hashAlgorithm) __attribute__((noescape, nocallback, static));
void go_hashWrite(int32_t hashAlgorithm, void *ptr, const uint8_t *data, long length) __attribute__((noescape, nocallback, static, slice(data, length)));
void go_hashSum(int32_t hashAlgorithm, void *ptr, uint8_t *outputPointer) __attribute__((noescape, nocallback, static, slice(outputPointer)));
void go_hashReset(int32_t hashAlgorithm, void *ptr) __attribute__((noescape, nocallback, static));
long go_hashSize(int32_t hashAlgorithm) __attribute__((noescape, nocallback, static));
long go_hashBlockSize(int32_t hashAlgorithm) __attribute__((noescape, nocallback, static));
void *go_hashCopy(int32_t hashAlgorithm, void *ptr) __attribute__((noescape, nocallback, static));
void go_hashFree(int32_t hashAlgorithm, void *ptr) __attribute__((noescape, nocallback, static));

// ML-KEM (Post-quantum key encapsulation mechanism)
long go_supportsMLKEM() __attribute__((noescape, nocallback, static));
long go_generateKeyMLKEM768(uint8_t *seed, long seedLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen)));
long go_generateKeyMLKEM1024(uint8_t *seed, long seedLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen)));
long go_deriveEncapsulationKeyMLKEM768(const uint8_t *seed, long seedLen, uint8_t *encapKey, long encapKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(encapKey, encapKeyLen)));
long go_deriveEncapsulationKeyMLKEM1024(const uint8_t *seed, long seedLen, uint8_t *encapKey, long encapKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(encapKey, encapKeyLen)));
long go_encapsulateMLKEM768(const uint8_t *encapKey, long encapKeyLen, uint8_t *sharedKey, long sharedKeyLen, uint8_t *ciphertext, long ciphertextLen) __attribute__((noescape, nocallback, static, slice(encapKey, encapKeyLen), slice(sharedKey, sharedKeyLen), slice(ciphertext, ciphertextLen)));
long go_encapsulateMLKEM1024(const uint8_t *encapKey, long encapKeyLen, uint8_t *sharedKey, long sharedKeyLen, uint8_t *ciphertext, long ciphertextLen) __attribute__((noescape, nocallback, static, slice(encapKey, encapKeyLen), slice(sharedKey, sharedKeyLen), slice(ciphertext, ciphertextLen)));
long go_decapsulateMLKEM768(const uint8_t *seed, long seedLen, const uint8_t *ciphertext, long ciphertextLen, uint8_t *sharedKey, long sharedKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(ciphertext, ciphertextLen), slice(sharedKey, sharedKeyLen)));
long go_decapsulateMLKEM1024(const uint8_t *seed, long seedLen, const uint8_t *ciphertext, long ciphertextLen, uint8_t *sharedKey, long sharedKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(ciphertext, ciphertextLen), slice(sharedKey, sharedKeyLen)));

// ML-DSA (Post-quantum digital signature algorithm)
long go_supportsMLDSA() __attribute__((noescape, nocallback, static));
long go_generateKeyMLDSA65(uint8_t *seed, long seedLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen)));
long go_generateKeyMLDSA87(uint8_t *seed, long seedLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen)));
long go_derivePublicKeyMLDSA65(const uint8_t *seed, long seedLen, uint8_t *publicKey, long publicKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(publicKey, publicKeyLen)));
long go_derivePublicKeyMLDSA87(const uint8_t *seed, long seedLen, uint8_t *publicKey, long publicKeyLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(publicKey, publicKeyLen)));
long go_signMLDSA65(const uint8_t *seed, long seedLen, const uint8_t *message, long messageLen, const uint8_t *context, long contextLen, uint8_t *signature, long *signatureLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(message, messageLen), slice(context, contextLen), slice(signature)));
long go_signMLDSA87(const uint8_t *seed, long seedLen, const uint8_t *message, long messageLen, const uint8_t *context, long contextLen, uint8_t *signature, long *signatureLen) __attribute__((noescape, nocallback, static, slice(seed, seedLen), slice(message, messageLen), slice(context, contextLen), slice(signature)));
long go_verifyMLDSA65(const uint8_t *publicKey, long publicKeyLen, const uint8_t *message, long messageLen, const uint8_t *context, long contextLen, const uint8_t *signature, long signatureLen) __attribute__((noescape, nocallback, static, slice(publicKey, publicKeyLen), slice(message, messageLen), slice(context, contextLen), slice(signature, signatureLen)));
long go_verifyMLDSA87(const uint8_t *publicKey, long publicKeyLen, const uint8_t *message, long messageLen, const uint8_t *context, long contextLen, const uint8_t *signature, long signatureLen) __attribute__((noescape, nocallback, static, slice(publicKey, publicKeyLen), slice(message, messageLen), slice(context, contextLen), slice(signature, signatureLen)));
long go_validatePublicKeyMLDSA65(const uint8_t *publicKey, long publicKeyLen) __attribute__((noescape, nocallback, static, slice(publicKey, publicKeyLen)));
long go_validatePublicKeyMLDSA87(const uint8_t *publicKey, long publicKeyLen) __attribute__((noescape, nocallback, static, slice(publicKey, publicKeyLen)));

// ECDH
long go_generateKeyECDH(int32_t curveID, uint8_t *privateKey, long privateKeyLen, uint8_t *publicKey, long publicKeyLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen), slice(publicKey, publicKeyLen)));
long go_publicKeyFromPrivateECDH(int32_t curveID, const uint8_t *privateKey, long privateKeyLen, uint8_t *publicKey, long publicKeyLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen), slice(publicKey, publicKeyLen)));
long go_ecdhSharedSecret(int32_t curveID, const uint8_t *privateKey, long privateKeyLen, const uint8_t *publicKey, long publicKeyLen, uint8_t *sharedSecret, long sharedSecretLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen), slice(publicKey, publicKeyLen), slice(sharedSecret, sharedSecretLen)));
long go_validatePrivateKeyECDH(int32_t curveID, const uint8_t *privateKey, long privateKeyLen) __attribute__((noescape, nocallback, static, slice(privateKey, privateKeyLen)));
long go_validatePublicKeyECDH(int32_t curveID, const uint8_t *publicKey, long publicKeyLen) __attribute__((noescape, nocallback, static, slice(publicKey, publicKeyLen)));

// ECDSA
long go_generateKeyECDSA(int32_t curveID, uint8_t *x, long xLen, uint8_t *y, long yLen, uint8_t *d, long dLen) __attribute__((noescape, nocallback, static, slice(x, xLen), slice(y, yLen), slice(d, dLen)));
long go_ecdsaSign(int32_t curveID, const uint8_t *d, long dLen, const uint8_t *message, long messageLen, uint8_t *signature, long *signatureLen) __attribute__((noescape, nocallback, static, slice(d, dLen), slice(message, messageLen), slice(signature)));
long go_ecdsaVerify(int32_t curveID, const uint8_t *x, long xLen, const uint8_t *y, long yLen, const uint8_t *message, long messageLen, const uint8_t *signature, long signatureLen) __attribute__((noescape, nocallback, static, slice(x, xLen), slice(y, yLen), slice(message, messageLen), slice(signature, signatureLen)));

#ifdef __clang__
#pragma clang assume_nonnull end
#endif

#endif // _GO_CRYPTOKIT_SHIMS_H
