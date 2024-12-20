// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin && cgo

package xcrypto

// #include <CommonCrypto/CommonCrypto.h>
import "C"
import (
	"errors"
	"hash"
	"unsafe"
)

func PBKDF2(password, salt []byte, iter, keyLen int, fh func() hash.Hash) ([]byte, error) {
	// Map Go hash function to CommonCrypto hash constant
	ccDigest, err := hashToCCDigestPBKDF2(fh())
	if err != nil {
		return nil, err
	}

	if len(password) == 0 {
		// CommonCrypto requires a non-empty password
		// Substitute empty password with placeholder
		password = make([]byte, 1)
	}

	// Allocate output buffer for the derived key
	derivedKey := make([]byte, keyLen)

	// Call CommonCrypto's PBKDF2 implementation
	status := C.CCKeyDerivationPBKDF(
		C.kCCPBKDF2,                              // PBKDF2 algorithm
		sbase(password), C.size_t(len(password)), // Password and its length
		base(salt), C.size_t(len(salt)), // Salt and its length
		ccDigest,     // Digest algorithm
		C.uint(iter), // Iteration count
		(*C.uchar)(unsafe.Pointer(&derivedKey[0])), C.size_t(keyLen), // Output buffer for derived key and its length
	)

	if status != C.kCCSuccess {
		return nil, errors.New("PBKDF2 key derivation failed")
	}

	return derivedKey, nil
}

// Mapping Go hash functions to CommonCrypto hash constants
func hashToCCDigestPBKDF2(hash hash.Hash) (C.CCAlgorithm, error) {
	switch hash.(type) {
	case *sha1Hash:
		return C.kCCPRFHmacAlgSHA1, nil
	case *sha224Hash:
		return C.kCCPRFHmacAlgSHA224, nil
	case *sha256Hash:
		return C.kCCPRFHmacAlgSHA256, nil
	case *sha384Hash:
		return C.kCCPRFHmacAlgSHA384, nil
	case *sha512Hash:
		return C.kCCPRFHmacAlgSHA512, nil
	default:
		return 0, errors.New("unsupported hash function")
	}
}
