// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package commoncrypto

// #include <Security/Security.h>
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"unsafe"
)

type algorithmType int

const (
	algorithmTypePSS algorithmType = iota
	algorithmTypeRAW
	algorithmTypePKCS1v15Enc
	algorithmTypePKCS1v15Sig
	algorithmTypeOAEP
	algorithmTypeECDSA
)

// Algorithm maps for translating crypto.Hash to SecKeyAlgorithm.
var (
	rsaRaw = map[crypto.Hash]C.CFStringRef{
		0: C.kSecKeyAlgorithmRSAEncryptionRaw,
	}
	rsaPKCS1v15Algorithms = map[crypto.Hash]C.CFStringRef{
		crypto.SHA1:   C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1,
		crypto.SHA224: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224,
		crypto.SHA256: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
		crypto.SHA384: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
		crypto.SHA512: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
		0:             C.kSecKeyAlgorithmRSASignatureRaw,
	}
	rsaPSSAlgorithms = map[crypto.Hash]C.CFStringRef{
		crypto.SHA1:   C.kSecKeyAlgorithmRSASignatureDigestPSSSHA1,
		crypto.SHA224: C.kSecKeyAlgorithmRSASignatureDigestPSSSHA224,
		crypto.SHA256: C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
		crypto.SHA384: C.kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
		crypto.SHA512: C.kSecKeyAlgorithmRSASignatureDigestPSSSHA512,
	}
	rsaOAEPAlgorithms = map[crypto.Hash]C.CFStringRef{
		crypto.SHA1:   C.kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
		crypto.SHA224: C.kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
		crypto.SHA256: C.kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
		crypto.SHA384: C.kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
		crypto.SHA512: C.kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
	}
)

type withKeyFunc func(func(C.SecKeyRef) C.int) C.int

// Encrypt encrypts a plaintext message using a given key and algorithm.
func evpEncrypt(withKey withKeyFunc, algorithmType algorithmType, plaintext []byte, hash hash.Hash) ([]byte, error) {
	var cryptoHash crypto.Hash
	if hash != nil {
		var err error
		cryptoHash, err = hashToCryptoHash(hash)
		if err != nil {
			return nil, err
		}
	}
	algorithm, err := selectAlgorithm(cryptoHash, algorithmType)
	if err != nil {
		return nil, err
	}

	dataRef := bytesToCFData(plaintext)
	defer cfRelease(unsafe.Pointer(dataRef))

	var encryptedDataRef C.CFDataRef
	result := withKey(func(key C.SecKeyRef) C.int {
		if C.SecKeyIsAlgorithmSupported(key, C.kSecKeyOperationTypeEncrypt, algorithm) != 1 {
			return -1 // Algorithm not supported by the key
		}
		encryptedDataRef = C.SecKeyCreateEncryptedData(key, algorithm, dataRef, nil)
		if encryptedDataRef == 0 {
			return -1 // Encryption failed
		}
		return 0
	})
	if result != 0 {
		return nil, errors.New("encryption failed")
	}
	defer cfRelease(unsafe.Pointer(encryptedDataRef))

	return cfDataToBytes(encryptedDataRef), nil
}

// Decrypt decrypts a ciphertext using a given key and algorithm.
func evpDecrypt(withKey withKeyFunc, algorithmType algorithmType, ciphertext []byte, hash hash.Hash) ([]byte, error) {
	var cryptoHash crypto.Hash
	if hash != nil {
		var err error
		cryptoHash, err = hashToCryptoHash(hash)
		if err != nil {
			return nil, err
		}
	}
	algorithm, err := selectAlgorithm(cryptoHash, algorithmType)
	if err != nil {
		return nil, err
	}

	msg := bytesToCFData(ciphertext)

	var decryptedDataRef C.CFDataRef
	var cfErr C.CFErrorRef
	result := withKey(func(key C.SecKeyRef) C.int {
		if C.SecKeyIsAlgorithmSupported(key, C.kSecKeyOperationTypeDecrypt, algorithm) != 1 {
			return -1 // Algorithm not supported by the key
		}
		decryptedDataRef = C.SecKeyCreateDecryptedData(key, algorithm, msg, &cfErr)
		if decryptedDataRef == 0 {
			return -1 // Decryption failed
		}
		return 0 // Success
	})

	if goCFErrorRef(cfErr) != nil {
		return nil, goCFErrorRef(cfErr)
	}

	if result != 0 || decryptedDataRef == 0 {
		return nil, errors.New("decryption failed")
	}
	defer cfRelease(unsafe.Pointer(decryptedDataRef))

	return cfDataToBytes(decryptedDataRef), nil
}

func evpSign(withKey withKeyFunc, algorithmType algorithmType, hash crypto.Hash, hashed []byte) ([]byte, error) {
	algorithm, err := selectAlgorithm(hash, algorithmType)
	if err != nil {
		return nil, err
	}

	var signedDataRef C.CFDataRef
	var cfErr C.CFErrorRef
	result := withKey(func(key C.SecKeyRef) C.int {
		if C.SecKeyIsAlgorithmSupported(key, C.kSecKeyOperationTypeSign, algorithm) != 1 {
			return -1 // Algorithm not supported by the key
		}
		signedDataRef = C.SecKeyCreateSignature(key, algorithm, bytesToCFData(hashed), &cfErr)
		if signedDataRef == 0 {
			return -1 // Signing failed
		}
		return 0 // Success
	})

	if goCFErrorRef(cfErr) != nil {
		return nil, goCFErrorRef(cfErr)
	}

	if result != 0 || signedDataRef == 0 {
		return nil, errors.New("signing failed")
	}
	defer cfRelease(unsafe.Pointer(signedDataRef))

	return cfDataToBytes(signedDataRef), nil
}

func evpVerify(withKey withKeyFunc, algorithmType algorithmType, hash crypto.Hash, hashed, signature []byte) error {
	algorithm, err := selectAlgorithm(hash, algorithmType)
	if err != nil {
		return err
	}

	var cfErr C.CFErrorRef
	result := withKey(func(key C.SecKeyRef) C.int {
		if C.SecKeyIsAlgorithmSupported(key, C.kSecKeyOperationTypeVerify, algorithm) != 1 {
			return -1 // Algorithm not supported by the key
		}
		if C.SecKeyVerifySignature(key, algorithm, bytesToCFData(hashed), bytesToCFData(signature), &cfErr) != 1 {
			return -1 // Verification failed
		}
		return 0 // Success
	})

	if goCFErrorRef(cfErr) != nil {
		return goCFErrorRef(cfErr)
	}

	if result != 0 {
		return errors.New("verification failed")
	}
	return nil
}

// hashToCryptoHash converts a hash.Hash to a crypto.Hash.
func hashToCryptoHash(hash hash.Hash) (crypto.Hash, error) {
	switch hash.(type) {
	case *sha1Hash:
		return crypto.SHA1, nil
	case *sha224Hash:
		return crypto.SHA224, nil
	case *sha256Hash:
		return crypto.SHA256, nil
	case *sha384Hash:
		return crypto.SHA384, nil
	case *sha512Hash:
		return crypto.SHA512, nil
	default:
		return 0, errors.New("unsupported hash function")
	}
}

// selectAlgorithm selects the appropriate SecKeyAlgorithm based on hash and algorithm type.
func selectAlgorithm(hash crypto.Hash, algorithmType algorithmType) (C.CFStringRef, error) {
	var algorithmMap map[crypto.Hash]C.CFStringRef
	switch algorithmType {
	case algorithmTypePSS:
		algorithmMap = rsaPSSAlgorithms
	case algorithmTypeRAW:
		algorithmMap = rsaRaw
	case algorithmTypePKCS1v15Enc:
		return C.kSecKeyAlgorithmRSAEncryptionPKCS1, nil
	case algorithmTypePKCS1v15Sig:
		algorithmMap = rsaPKCS1v15Algorithms
	case algorithmTypeOAEP:
		algorithmMap = rsaOAEPAlgorithms
	case algorithmTypeECDSA:
		return C.kSecKeyAlgorithmECDSASignatureDigestX962, nil
	default:
		return 0, errors.New("unsupported algorithm type")
	}

	algorithm, ok := algorithmMap[hash]
	if !ok {
		return 0, errors.New("unsupported combination of algorithm type and hash")
	}

	return algorithm, nil
}

// bytesToCFData turns a byte slice into a CFDataRef. Caller then "owns" the
// CFDataRef and must CFRelease the CFDataRef when done.
func bytesToCFData(buf []byte) C.CFDataRef {
	return C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&buf[0])), C.CFIndex(len(buf)))
}

// cfDataToBytes turns a CFDataRef into a byte slice.
func cfDataToBytes(cfData C.CFDataRef) []byte {
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(cfData)), C.int(C.CFDataGetLength(cfData)))
}

// cfRelease releases a CoreFoundation object.
func cfRelease(ref unsafe.Pointer) {
	C.CFRelease(C.CFTypeRef(ref))
}

// createSecKeyWithData creates a SecKey from the provided encoded key and attributes dictionary.
func createSecKeyWithData(encodedKey []byte, keyType, keyClass C.CFStringRef) (*C.SecKeyRef, error) {
	encodedKeyCF := C.CFDataCreate(C.kCFAllocatorDefault, base(encodedKey), C.CFIndex(len(encodedKey)))
	if encodedKeyCF == 0 {
		return nil, errors.New("crypto/ecdsa: failed to create CFData for private key")
	}
	defer C.CFRelease(C.CFTypeRef(encodedKeyCF))

	attrKeys := []C.CFTypeRef{
		C.CFTypeRef(C.kSecAttrKeyType),
		C.CFTypeRef(C.kSecAttrKeyClass),
	}

	attrValues := []C.CFTypeRef{
		C.CFTypeRef(keyType),
		C.CFTypeRef(keyClass),
	}

	// Create attributes dictionary for the key
	attrDict := C.CFDictionaryCreate(
		C.kCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&attrKeys[0])),
		(*unsafe.Pointer)(unsafe.Pointer(&attrValues[0])),
		C.CFIndex(len(attrKeys)),
		nil,
		nil,
	)
	if attrDict == 0 {
		return nil, errors.New("crypto/rsa: failed to create attributes dictionary")
	}
	defer C.CFRelease(C.CFTypeRef(attrDict))

	// Generate the SecKey
	var errorRef C.CFErrorRef
	key := C.SecKeyCreateWithData(encodedKeyCF, attrDict, &errorRef)
	if goCFErrorRef(errorRef) != nil {
		return nil, goCFErrorRef(errorRef)
	}
	return &key, nil
}

// createSecKeyRandom creates a new SecKey with the provided attributes dictionary.
func createSecKeyRandom(keyType C.CFStringRef, keySize int) ([]byte, error) {
	keyAttrs := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, nil, nil)
	if keyAttrs == 0 {
		return nil, errors.New("failed to create key attributes dictionary")
	}
	defer C.CFRelease(C.CFTypeRef(keyAttrs))

	C.CFDictionarySetValue(
		keyAttrs,
		unsafe.Pointer(C.kSecAttrKeyType),
		unsafe.Pointer(keyType),
	)

	C.CFDictionarySetValue(
		keyAttrs,
		unsafe.Pointer(C.kSecAttrKeySizeInBits),
		unsafe.Pointer(C.CFNumberCreate(C.kCFAllocatorDefault, C.kCFNumberIntType, unsafe.Pointer(&keySize))),
	)

	// Generate the private key
	var errorRef C.CFErrorRef
	var privKeyRef C.SecKeyRef = C.SecKeyCreateRandomKey(C.CFDictionaryRef(keyAttrs), &errorRef)
	if goCFErrorRef(errorRef) != nil {
		return nil, goCFErrorRef(errorRef)
	}
	defer C.CFRelease(C.CFTypeRef(privKeyRef))

	// Export the private key as DER
	privData := C.SecKeyCopyExternalRepresentation(privKeyRef, &errorRef)
	if goCFErrorRef(errorRef) != nil {
		return nil, goCFErrorRef(errorRef)
	}
	defer C.CFRelease(C.CFTypeRef(privData))

	privKeyDER := cfDataToBytes(privData)
	if privKeyDER == nil {
		return nil, errors.New("failed to convert CFData to bytes")
	}
	return privKeyDER, nil
}
