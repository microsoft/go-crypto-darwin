// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import (
	"crypto"
	"errors"
	"fmt"
)

// ExtractHKDF performs the extract step of HKDF using the specified hash function.
func ExtractHKDF(hash crypto.Hash, secret, salt []byte) ([]byte, error) {
	// Handle empty secret
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	// Default salt to a zero-filled array if not provided
	if len(salt) == 0 {
		salt = make([]byte, hash.Size())
	}

	h, err := cryptoHashToSwift(hash)
	if err != nil {
		return nil, err
	}

	// Allocate buffer for derived key
	prk := make([]byte, hash.Size())

	// Call Swift function
	result := C.extractHKDF(
		h,
		base(secret), C.size_t(len(secret)),
		base(salt), C.size_t(len(salt)),
		base(prk), C.size_t(len(prk)),
	)

	if result != 0 {
		return nil, errors.New("HKDF derivation failed with exit code: " + fmt.Sprint(result))
	}

	return prk, nil
}

func ExpandHKDF(hash crypto.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	// Handle empty secret
	if len(pseudorandomKey) == 0 {
		return nil, errors.New("pseudorandom key cannot be empty")
	}

	// Determine the maximum expandable key length based on the hash function
	maxAllowedLength := hash.Size() * 255

	// Validate requested key length
	if keyLength > maxAllowedLength {
		return nil, errors.New("requested key length exceeds maximum allowable size")
	}

	h, err := cryptoHashToSwift(hash)
	if err != nil {
		return nil, err
	}

	// Allocate buffer for derived key
	expandedKey := make([]byte, keyLength)

	// Call Swift function
	result := C.expandHKDF(
		h,
		base(pseudorandomKey), C.size_t(len(pseudorandomKey)),
		base(info), C.size_t(len(info)),
		base(expandedKey), C.size_t(len(expandedKey)),
	)

	if result != 0 {
		return nil, errors.New("HKDF derivation failed with exit code: " + fmt.Sprint(result))
	}

	return expandedKey, nil
}

func cryptoHashToSwift(hash crypto.Hash) (C.int32_t, error) {
	switch hash {
	case crypto.SHA1:
		return 1, nil
	case crypto.SHA256:
		return 2, nil
	case crypto.SHA384:
		return 3, nil
	case crypto.SHA512:
		return 4, nil
	default:
		return 0, errors.New("unsupported hash function")
	}
}
