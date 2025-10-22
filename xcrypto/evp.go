// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"crypto"
	"errors"
	"hash"
	"slices"
	"strconv"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/security"
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

type withKeyFunc func(func(security.SecKeyRef) error) error

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

	var encryptedDataRef security.CFDataRef
	err = withKey(func(key security.SecKeyRef) error {
		if security.SecKeyIsAlgorithmSupported(key, security.KSecKeyOperationTypeEncrypt, algorithm) != 1 {
			return errors.New("algorithm not supported by the key")
		}
		encryptedDataRef = security.SecKeyCreateEncryptedData(key, algorithm, dataRef, nil)
		if encryptedDataRef == nil {
			return errors.New("encryption failed")
		}
		return nil
	})
	if err != nil {
		return nil, err
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

	var decryptedDataRef security.CFDataRef
	var cfErr security.CFErrorRef
	err = withKey(func(key security.SecKeyRef) error {
		if security.SecKeyIsAlgorithmSupported(key, security.KSecKeyOperationTypeDecrypt, algorithm) != 1 {
			return errors.New("algorithm not supported by the key")
		}
		decryptedDataRef = security.SecKeyCreateDecryptedData(key, algorithm, msg, &cfErr)
		if decryptedDataRef == nil {
			return errors.New("decryption failed")
		}
		return nil
	})

	if err := goCFErrorRef(cfErr); err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}
	defer cfRelease(unsafe.Pointer(decryptedDataRef))

	return cfDataToBytes(decryptedDataRef), nil
}

func evpSign(withKey withKeyFunc, algorithmType algorithmType, hash crypto.Hash, hashed []byte) ([]byte, error) {
	algorithm, err := selectAlgorithm(hash, algorithmType)
	if err != nil {
		return nil, err
	}

	var signedDataRef security.CFDataRef
	var cfErr security.CFErrorRef
	err = withKey(func(key security.SecKeyRef) error {
		if security.SecKeyIsAlgorithmSupported(key, security.KSecKeyOperationTypeSign, algorithm) != 1 {
			return errors.New("algorithm not supported by the key")
		}
		signedDataRef = security.SecKeyCreateSignature(key, algorithm, bytesToCFData(hashed), &cfErr)
		if signedDataRef == nil {
			return errors.New("signing failed")
		}
		return nil
	})

	if err := goCFErrorRef(cfErr); err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}
	defer cfRelease(unsafe.Pointer(signedDataRef))

	return cfDataToBytes(signedDataRef), nil
}

func evpVerify(withKey withKeyFunc, algorithmType algorithmType, hash crypto.Hash, hashed, signature []byte) error {
	algorithm, err := selectAlgorithm(hash, algorithmType)
	if err != nil {
		return err
	}

	var cfErr security.CFErrorRef
	err = withKey(func(key security.SecKeyRef) error {
		if security.SecKeyIsAlgorithmSupported(key, security.KSecKeyOperationTypeVerify, algorithm) != 1 {
			return errors.New("algorithm not supported by the key")
		}
		if security.SecKeyVerifySignature(key, algorithm, bytesToCFData(hashed), bytesToCFData(signature), &cfErr) != 1 {
			return errors.New("verification failed")
		}
		return nil
	})

	if err := goCFErrorRef(cfErr); err != nil {
		return err
	}

	return err
}

// hashToCryptoHash converts a hash.Hash to a crypto.Hash.
func hashToCryptoHash(hash hash.Hash) (crypto.Hash, error) {
	switch hash.(type) {
	case sha1Hash:
		return crypto.SHA1, nil
	case sha256Hash:
		return crypto.SHA256, nil
	case sha384Hash:
		return crypto.SHA384, nil
	case sha512Hash:
		return crypto.SHA512, nil
	case sha3_256Hash:
		return crypto.SHA3_256, nil
	case sha3_384Hash:
		return crypto.SHA3_384, nil
	case sha3_512Hash:
		return crypto.SHA3_512, nil
	default:
		return 0, errors.New("unsupported hash function")
	}
}

// selectAlgorithm selects the appropriate SecKeyAlgorithm based on hash and algorithm type.
func selectAlgorithm(hash crypto.Hash, algorithmType algorithmType) (security.CFStringRef, error) {
	var algo security.CFStringRef
	switch algorithmType {
	case algorithmTypePSS:
		switch hash {
		case crypto.SHA1:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPSSSHA1
		case crypto.SHA224:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPSSSHA224
		case crypto.SHA256:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPSSSHA256
		case crypto.SHA384:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPSSSHA384
		case crypto.SHA512:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPSSSHA512
		default:
			return nil, errors.New("unsupported PSS hash: " + hash.String())
		}
	case algorithmTypeRAW:
		algo = security.KSecKeyAlgorithmRSAEncryptionRaw
	case algorithmTypePKCS1v15Enc:
		return security.KSecKeyAlgorithmRSAEncryptionPKCS1, nil
	case algorithmTypePKCS1v15Sig:
		switch hash {
		case crypto.SHA1:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
		case crypto.SHA224:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224
		case crypto.SHA256:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
		case crypto.SHA384:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
		case crypto.SHA512:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
		case 0:
			algo = security.KSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw
		default:
			return nil, errors.New("unsupported PKCS1v15 hash: " + hash.String())
		}
	case algorithmTypeOAEP:
		switch hash {
		case crypto.SHA1:
			algo = security.KSecKeyAlgorithmRSAEncryptionOAEPSHA1
		case crypto.SHA224:
			algo = security.KSecKeyAlgorithmRSAEncryptionOAEPSHA224
		case crypto.SHA256:
			algo = security.KSecKeyAlgorithmRSAEncryptionOAEPSHA256
		case crypto.SHA384:
			algo = security.KSecKeyAlgorithmRSAEncryptionOAEPSHA384
		case crypto.SHA512:
			algo = security.KSecKeyAlgorithmRSAEncryptionOAEPSHA512
		default:
			return nil, errors.New("unsupported OAEP hash: " + hash.String())
		}
	case algorithmTypeECDSA:
		return security.KSecKeyAlgorithmECDSASignatureDigestX962, nil
	default:
		return nil, errors.New("unsupported algorithm type: " + strconv.Itoa(int(algorithmType)))
	}
	return algo, nil
}

// bytesToCFData turns a byte slice into a CFDataRef. Caller then "owns" the
// CFDataRef and must CFRelease the CFDataRef when done.
func bytesToCFData(buf []byte) security.CFDataRef {
	return security.CFDataCreate(security.KCFAllocatorDefault, addr(buf), security.CFIndex(len(buf)))
}

// cfDataToBytes turns a CFDataRef into a byte slice.
func cfDataToBytes(cfData security.CFDataRef) []byte {
	// TODO: remove this allocation
	return slices.Clone(unsafe.Slice(security.CFDataGetBytePtr(cfData), security.CFDataGetLength(cfData)))
}

// cfRelease releases a CoreFoundation object.
func cfRelease(ref unsafe.Pointer) {
	security.CFRelease(security.CFTypeRef(ref))
}

// createSecKeyWithData creates a SecKey from the provided encoded key and attributes dictionary.
func createSecKeyWithData(encodedKey []byte, keyType, keyClass security.CFStringRef) (security.SecKeyRef, error) {
	encodedKeyCF := security.CFDataCreate(security.KCFAllocatorDefault, addr(encodedKey), security.CFIndex(len(encodedKey)))
	if encodedKeyCF == nil {
		return nil, errors.New("xcrypto: failed to create CFData for private key")
	}
	defer security.CFRelease(security.CFTypeRef(encodedKeyCF))

	attrKeys := []security.CFTypeRef{
		security.CFTypeRef(security.KSecAttrKeyType),
		security.CFTypeRef(security.KSecAttrKeyClass),
	}

	attrValues := []security.CFTypeRef{
		security.CFTypeRef(keyType),
		security.CFTypeRef(keyClass),
	}

	// Create attributes dictionary for the key
	attrDict := security.CFDictionaryCreate(
		security.KCFAllocatorDefault,
		(*unsafe.Pointer)(unsafe.Pointer(&attrKeys[0])),
		(*unsafe.Pointer)(unsafe.Pointer(&attrValues[0])),
		security.CFIndex(len(attrKeys)),
		nil,
		nil,
	)
	if attrDict == nil {
		return nil, errors.New("xcrypto: failed to create attributes dictionary")
	}
	defer security.CFRelease(security.CFTypeRef(attrDict))

	// Generate the SecKey
	var errorRef security.CFErrorRef
	key := security.SecKeyCreateWithData(encodedKeyCF, attrDict, &errorRef)
	if err := goCFErrorRef(errorRef); err != nil {
		return nil, err
	}
	return key, nil
}

// createSecKeyRandom creates a new SecKey with the provided attributes dictionary.
func createSecKeyRandom(keyType security.CFStringRef, keySize int) ([]byte, security.SecKeyRef, error) {
	keyAttrs := security.CFDictionaryCreateMutable(security.KCFAllocatorDefault, 0, nil, nil)
	if keyAttrs == nil {
		return nil, nil, errors.New("failed to create key attributes dictionary")
	}
	defer security.CFRelease(security.CFTypeRef(keyAttrs))

	security.CFDictionarySetValue(
		keyAttrs,
		unsafe.Pointer(security.KSecAttrKeyType),
		unsafe.Pointer(keyType),
	)

	cfNum := security.CFNumberCreate(security.KCFAllocatorDefault, security.KCFNumberIntType, unsafe.Pointer(&keySize))
	defer security.CFRelease(security.CFTypeRef(cfNum))

	security.CFDictionarySetValue(
		keyAttrs,
		unsafe.Pointer(security.KSecAttrKeySizeInBits),
		unsafe.Pointer(cfNum),
	)

	// Generate the private key
	var errorRef security.CFErrorRef
	privKeyRef := security.SecKeyCreateRandomKey(security.CFDictionaryRef(keyAttrs), &errorRef)
	if err := goCFErrorRef(errorRef); err != nil {
		return nil, nil, err
	}

	// Export the private key as DER
	privData := security.SecKeyCopyExternalRepresentation(privKeyRef, &errorRef)
	if err := goCFErrorRef(errorRef); err != nil {
		return nil, nil, err
	}
	defer security.CFRelease(security.CFTypeRef(privData))

	privKeyDER := cfDataToBytes(privData)
	if privKeyDER == nil {
		return nil, nil, errors.New("failed to convert CFData to bytes")
	}
	return privKeyDER, privKeyRef, nil
}
