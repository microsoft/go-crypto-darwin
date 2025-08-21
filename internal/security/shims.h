// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This header file is used by the mkcgo tool to generate cgo and Go bindings for the
// Security framework C API. Run "go generate ." to regenerate the bindings.
// Do not include this file, import "zsecurity.h" instead.

#ifndef _GO_SECURITY_SHIMS_H // only include this header once
#define _GO_SECURITY_SHIMS_H

#include <stdbool.h> // bool
#include <stdint.h>  // uint64_t
#include <stdlib.h>  // size_t

// The following includes are used by the checkheader tool.
// #include <Security/Security.h>

typedef unsigned char Boolean;
typedef void *SecRandomRef;
typedef void *SecKeyRef;
typedef void *CFDataRef;
typedef void *CFTypeRef;
typedef void *CFStringRef;
typedef void *CFDictionaryRef;
typedef void *CFMutableDictionaryRef;
typedef void *CFNumberRef;
typedef void *CFErrorRef;
typedef void *CFAllocatorRef;
typedef void *CFDictionaryKeyCallBacks;
typedef void *CFDictionaryValueCallBacks;
typedef int32_t CFIndex;
typedef CFStringRef SecKeyAlgorithm;

typedef enum {
  kSecKeyOperationTypeSign = 0,
  kSecKeyOperationTypeVerify = 1,
  kSecKeyOperationTypeEncrypt = 2,
  kSecKeyOperationTypeDecrypt = 3,
  kSecKeyOperationTypeKeyExchange = 4
} SecKeyOperationType;

typedef enum {
  kCFStringEncodingUTF8 = 0x08000100
} CFStringEncoding;

typedef enum {
  kCFNumberIntType = 9
} CFNumberType;

extern const SecRandomRef kSecRandomDefault;
extern const CFAllocatorRef kCFAllocatorDefault;
extern const CFStringRef kSecAttrKeyTypeECSECPrimeRandom;
extern const CFStringRef kSecAttrKeyTypeRSA;
extern const CFStringRef kSecAttrKeyClassPublic;
extern const CFStringRef kSecAttrKeyClassPrivate;
extern const CFStringRef kSecAttrKeyType;
extern const CFStringRef kSecAttrKeySizeInBits;
extern const CFStringRef kSecAttrKeyClass;
extern const CFStringRef kSecKeyAlgorithmECDHKeyExchangeStandard;
// PSS
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA1;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA224;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA256;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA384;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA512;
// RAW
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionRaw;
// PKCS1v15
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionPKCS1;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw;
// OAEP
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA1;
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA224;
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA256;
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA384;
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA512;
// ECDSA
extern const CFStringRef kSecKeyAlgorithmECDSASignatureDigestX962;

int SecRandomCopyBytes(SecRandomRef rnd, size_t count, void *bytes) __attribute__((noescape, nocallback));
SecKeyRef SecKeyCopyPublicKey(SecKeyRef key);
SecKeyRef SecKeyCreateWithData(CFDataRef keyData, CFDictionaryRef attributes, CFErrorRef *error);
SecKeyRef SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error);
CFDataRef SecKeyCopyExternalRepresentation(SecKeyRef key, CFErrorRef *error);
CFDataRef SecKeyCopyKeyExchangeResult(SecKeyRef privateKey, SecKeyAlgorithm algorithm, SecKeyRef publicKey, CFDictionaryRef parameters, CFErrorRef *error);
CFDataRef SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error);
CFDataRef SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error);
CFDataRef SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef data, CFErrorRef *error);
Boolean SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef signedData, CFDataRef signature, CFErrorRef *error);
Boolean SecKeyIsAlgorithmSupported(SecKeyRef key, SecKeyOperationType operation, SecKeyAlgorithm algorithm);

CFDataRef CFDataCreate(CFAllocatorRef allocator, const uint8_t *bytes, CFIndex length);
CFDictionaryRef CFDictionaryCreate(CFAllocatorRef allocator, const void **keys, const void **values, CFIndex numValues, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks);
CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks);
CFNumberRef CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr);
CFIndex CFDataGetLength(CFDataRef data);
const uint8_t *CFDataGetBytePtr(CFDataRef data);
size_t SecKeyGetBlockSize(SecKeyRef key);
void CFRelease(CFTypeRef cf);
void CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
CFStringRef CFErrorCopyDescription(CFErrorRef error);
const char *CFStringGetCStringPtr(CFStringRef str, CFStringEncoding encoding);
CFIndex CFStringGetLength(CFStringRef str);
CFIndex CFErrorGetCode(CFErrorRef error);

#endif // _GO_SECURITY_SHIMS_H
