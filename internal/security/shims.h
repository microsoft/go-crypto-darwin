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

extern const CFAllocatorRef kCFAllocatorDefault __attribute__((framework(CoreFoundation, A)));
extern const SecRandomRef kSecRandomDefault __attribute__((framework(Security, A)));
extern const CFStringRef kSecAttrKeyTypeECSECPrimeRandom __attribute__((framework(Security, A)));
extern const CFStringRef kSecAttrKeyTypeRSA __attribute__((framework(Security, A)));
extern const CFStringRef kSecAttrKeyClassPublic __attribute__((framework(Security, A)));
extern const CFStringRef kSecAttrKeyClassPrivate __attribute__((framework(Security, A)));
extern const CFStringRef kSecAttrKeyType __attribute__((framework(Security, A)));
extern const CFStringRef kSecAttrKeySizeInBits __attribute__((framework(Security, A)));
extern const CFStringRef kSecAttrKeyClass __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmECDHKeyExchangeStandard __attribute__((framework(Security, A)));
// PSS
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA1 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA224 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA256 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA384 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPSSSHA512 __attribute__((framework(Security, A)));
// RAW
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionRaw __attribute__((framework(Security, A)));
// PKCS1v15
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionPKCS1 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw __attribute__((framework(Security, A)));
// OAEP
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA1 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA224 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA256 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA384 __attribute__((framework(Security, A)));
extern const CFStringRef kSecKeyAlgorithmRSAEncryptionOAEPSHA512 __attribute__((framework(Security, A)));
// ECDSA
extern const CFStringRef kSecKeyAlgorithmECDSASignatureDigestX962 __attribute__((framework(Security, A)));

int SecRandomCopyBytes(SecRandomRef rnd, size_t count, unsigned char *bytes) __attribute__((framework(Security, A), noescape, nocallback));
SecKeyRef SecKeyCopyPublicKey(SecKeyRef key) __attribute__((framework(Security, A)));
SecKeyRef SecKeyCreateWithData(CFDataRef keyData, CFDictionaryRef attributes, CFErrorRef *error) __attribute__((framework(Security, A)));
SecKeyRef SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) __attribute__((framework(Security, A)));
CFDataRef SecKeyCopyExternalRepresentation(SecKeyRef key, CFErrorRef *error) __attribute__((framework(Security, A)));
CFDataRef SecKeyCopyKeyExchangeResult(SecKeyRef privateKey, SecKeyAlgorithm algorithm, SecKeyRef publicKey, CFDictionaryRef parameters, CFErrorRef *error) __attribute__((framework(Security, A)));
CFDataRef SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error) __attribute__((framework(Security, A)));
CFDataRef SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error) __attribute__((framework(Security, A)));
CFDataRef SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef data, CFErrorRef *error) __attribute__((framework(Security, A)));
Boolean SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef signedData, CFDataRef signature, CFErrorRef *error) __attribute__((framework(Security, A)));
Boolean SecKeyIsAlgorithmSupported(SecKeyRef key, SecKeyOperationType operation, SecKeyAlgorithm algorithm) __attribute__((framework(Security, A)));
size_t SecKeyGetBlockSize(SecKeyRef key) __attribute__((framework(Security, A)));

CFDataRef CFDataCreate(CFAllocatorRef allocator, const uint8_t *bytes, CFIndex length) __attribute__((framework(CoreFoundation, A)));
CFDictionaryRef CFDictionaryCreate(CFAllocatorRef allocator, const void **keys, const void **values, CFIndex numValues, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks) __attribute__((framework(CoreFoundation, A)));
CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks) __attribute__((framework(CoreFoundation, A)));
CFNumberRef CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr) __attribute__((framework(CoreFoundation, A)));
CFIndex CFDataGetLength(CFDataRef data) __attribute__((framework(CoreFoundation, A)));
const uint8_t *CFDataGetBytePtr(CFDataRef data) __attribute__((framework(CoreFoundation, A)));
void CFRelease(CFTypeRef cf) __attribute__((framework(CoreFoundation, A)));
void CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value) __attribute__((framework(CoreFoundation, A)));
CFStringRef CFErrorCopyDescription(CFErrorRef error) __attribute__((framework(CoreFoundation, A)));
const char *CFStringGetCStringPtr(CFStringRef str, CFStringEncoding encoding) __attribute__((framework(CoreFoundation, A)));
CFIndex CFStringGetLength(CFStringRef str) __attribute__((framework(CoreFoundation, A)));
CFIndex CFErrorGetCode(CFErrorRef error) __attribute__((framework(CoreFoundation, A)));

#endif // _GO_SECURITY_SHIMS_H
