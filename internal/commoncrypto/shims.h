// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This header file is used by the mkcgo tool to generate cgo and Go bindings
// for the CommonCrypto C API. Run "go generate ." to regenerate the bindings.
// Do not include this file, import "zcommoncrypto.h" instead.

#ifndef _GO_COMMONCRYPTO_SHIMS_H // only include this header once
#define _GO_COMMONCRYPTO_SHIMS_H

#include <stdint.h> // uint64_t
#include <stdlib.h> // size_t

// The following includes are used by the checkheader tool.
// #include <CommonCrypto/CommonCrypto.h>

typedef void *CCCryptorRef;
typedef uint32_t CCModeOptions;

typedef enum {
  kCCEncrypt = 0,
  kCCDecrypt = 1,
} CCOperation;

typedef enum {
  kCCModeCBC = 2,
} CCMode;

typedef enum {
  KCCOptionECBMode = 2,
} CCOptions;

typedef enum {
  kCCSuccess = 0,
} CCCryptorStatus;

typedef enum {
  kCCPBKDF2 = 2,
} CCPBKDFAlgorithm;

typedef enum {
  kCCPRFHmacAlgSHA1 = 1,
  kCCPRFHmacAlgSHA256 = 3,
  kCCPRFHmacAlgSHA384 = 4,
  kCCPRFHmacAlgSHA512 = 5,
} CCPseudoRandomAlgorithm;

enum {
  kCCBlockSizeAES128 = 16,
  kCCBlockSizeDES = 8,
};

typedef enum {
  ccNoPadding = 0,
} CCPadding;

typedef enum {
  kCCAlgorithmAES = 0,
  kCCAlgorithmDES = 1,
  kCCAlgorithm3DES = 2,
  kCCAlgorithmRC4 = 4,
} CCAlgorithm;

CCCryptorStatus CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, CCCryptorRef *cryptorRef) __attribute__((framework(System, B), slice(key, keyLength), slice(iv)));
CCCryptorStatus CCCryptorRelease(CCCryptorRef cryptorRef) __attribute__((framework(System, B)));
CCCryptorStatus CCCryptorUpdate(CCCryptorRef cryptorRef, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) __attribute__((framework(System, B), slice(dataIn, dataInLength), slice(dataOut, dataOutAvailable)));
CCCryptorStatus CCKeyDerivationPBKDF(CCPBKDFAlgorithm algorithm, const char *password, size_t passwordLen, const uint8_t *salt, size_t saltLen, CCPseudoRandomAlgorithm prf, unsigned rounds, uint8_t *derivedKey, size_t derivedKeyLen) __attribute__((framework(System, B), slice(password, passwordLen), slice(salt, saltLen), slice(derivedKey, derivedKeyLen)));
CCCryptorStatus CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) __attribute__((framework(System, B), slice(key, keyLength), slice(iv), slice(dataIn, dataInLength), slice(dataOut, dataOutAvailable)));
CCCryptorStatus CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding padding, const void *iv, const void *key, size_t keyLength, const void *tweak, size_t tweakLength, int numRounds, CCModeOptions options, CCCryptorRef *cryptorRef) __attribute__((framework(System, B), slice(iv), slice(key, keyLength), slice(tweak, tweakLength)));
CCCryptorStatus CCCryptorReset(CCCryptorRef cryptorRef, const void *iv) __attribute__((framework(System, B), slice(iv)));

#endif // _GO_COMMONCRYPTO_SHIMS_H
