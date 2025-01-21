// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <Security/Security.h>
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"strconv"
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

	if err := goCFErrorRef(cfErr); err != nil {
		return nil, err
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

	if err := goCFErrorRef(cfErr); err != nil {
		return nil, err
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

	if err := goCFErrorRef(cfErr); err != nil {
		return err
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
	var algo C.CFStringRef
	switch algorithmType {
	case algorithmTypePSS:
		switch hash {
		case crypto.SHA1:
			algo = kSecKeyAlgorithmRSASignatureDigestPSSSHA1
		case crypto.SHA224:
			algo = kSecKeyAlgorithmRSASignatureDigestPSSSHA224
		case crypto.SHA256:
			algo = kSecKeyAlgorithmRSASignatureDigestPSSSHA256
		case crypto.SHA384:
			algo = kSecKeyAlgorithmRSASignatureDigestPSSSHA384
		case crypto.SHA512:
			algo = kSecKeyAlgorithmRSASignatureDigestPSSSHA512
		default:
			return 0, errors.New("unsupported PSS hash: " + hash.String())
		}
	case algorithmTypeRAW:
		algo = kSecKeyAlgorithmRSAEncryptionRaw
	case algorithmTypePKCS1v15Enc:
		return kSecKeyAlgorithmRSAEncryptionPKCS1, nil
	case algorithmTypePKCS1v15Sig:
		switch hash {
		case crypto.SHA1:
			algo = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
		case crypto.SHA224:
			algo = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224
		case crypto.SHA256:
			algo = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
		case crypto.SHA384:
			algo = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
		case crypto.SHA512:
			algo = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
		case 0:
			algo = kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw
		default:
			return 0, errors.New("unsupported PKCS1v15 hash: " + hash.String())
		}
	case algorithmTypeOAEP:
		switch hash {
		case crypto.SHA1:
			algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA1
		case crypto.SHA224:
			algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA224
		case crypto.SHA256:
			algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA256
		case crypto.SHA384:
			algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA384
		case crypto.SHA512:
			algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA512
		default:
			return 0, errors.New("unsupported OAEP hash: " + hash.String())
		}
	case algorithmTypeECDSA:
		return kSecKeyAlgorithmECDSASignatureDigestX962, nil
	default:
		return 0, errors.New("unsupported algorithm type: " + strconv.Itoa(int(algorithmType)))
	}
	return algo, nil
}

// bytesToCFData turns a byte slice into a CFDataRef. Caller then "owns" the
// CFDataRef and must CFRelease the CFDataRef when done.
func bytesToCFData(buf []byte) C.CFDataRef {
	return C.CFDataCreate(kCFAllocatorDefault, base(buf), C.CFIndex(len(buf)))
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
func createSecKeyWithData(encodedKey []byte, keyType, keyClass C.CFStringRef) (C.SecKeyRef, error) {
	encodedKeyCF := C.CFDataCreate(kCFAllocatorDefault, base(encodedKey), C.CFIndex(len(encodedKey)))
	if encodedKeyCF == 0 {
		return 0, errors.New("xcrypto: failed to create CFData for private key")
	}
	defer C.CFRelease(C.CFTypeRef(encodedKeyCF))

	attrKeys := []C.CFTypeRef{
		C.CFTypeRef(kSecAttrKeyType),
		C.CFTypeRef(kSecAttrKeyClass),
	}

	attrValues := []C.CFTypeRef{
		C.CFTypeRef(keyType),
		C.CFTypeRef(keyClass),
	}

	// Create attributes dictionary for the key
	attrDict := C.CFDictionaryCreate(
		kCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&attrKeys[0])),
		(*unsafe.Pointer)(unsafe.Pointer(&attrValues[0])),
		C.CFIndex(len(attrKeys)),
		nil,
		nil,
	)
	if attrDict == 0 {
		return 0, errors.New("xcrypto: failed to create attributes dictionary")
	}
	defer C.CFRelease(C.CFTypeRef(attrDict))

	// Generate the SecKey
	var errorRef C.CFErrorRef
	key := C.SecKeyCreateWithData(encodedKeyCF, attrDict, &errorRef)
	if err := goCFErrorRef(errorRef); err != nil {
		return 0, err
	}
	return key, nil
}

// createSecKeyRandom creates a new SecKey with the provided attributes dictionary.
func createSecKeyRandom(keyType C.CFStringRef, keySize int) ([]byte, C.SecKeyRef, error) {
	keyAttrs := C.CFDictionaryCreateMutable(kCFAllocatorDefault, 0, nil, nil)
	if keyAttrs == 0 {
		return nil, 0, errors.New("failed to create key attributes dictionary")
	}
	defer C.CFRelease(C.CFTypeRef(keyAttrs))

	C.CFDictionarySetValue(
		keyAttrs,
		unsafe.Pointer(kSecAttrKeyType),
		unsafe.Pointer(keyType),
	)

	C.CFDictionarySetValue(
		keyAttrs,
		unsafe.Pointer(kSecAttrKeySizeInBits),
		unsafe.Pointer(C.CFNumberCreate(kCFAllocatorDefault, C.kCFNumberIntType, unsafe.Pointer(&keySize))),
	)

	// Generate the private key
	var errorRef C.CFErrorRef
	var privKeyRef C.SecKeyRef = C.SecKeyCreateRandomKey(C.CFDictionaryRef(keyAttrs), &errorRef)
	if err := goCFErrorRef(errorRef); err != nil {
		return nil, 0, err
	}

	// Export the private key as DER
	privData := C.SecKeyCopyExternalRepresentation(privKeyRef, &errorRef)
	if err := goCFErrorRef(errorRef); err != nil {
		return nil, 0, err
	}
	defer C.CFRelease(C.CFTypeRef(privData))

	privKeyDER := cfDataToBytes(privData)
	if privKeyDER == nil {
		return nil, 0, errors.New("failed to convert CFData to bytes")
	}
	return privKeyDER, privKeyRef, nil
}
