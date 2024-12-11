// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "CryptoKit.h"
import "C"
import (
	"crypto"
	"errors"
)

// ExtractHKDF performs the extract step of HKDF using the specified hash function.
func ExtractHKDF(hash crypto.Hash, secret, salt []byte) ([]byte, error) {
	h, err := cryptoHashToSwift(hash)
	if err != nil {
		return nil, err
	}

	// Allocate buffer for derived key
	prk := make([]byte, hash.Size())

	// Call Swift function
	result := C.extractHKDF(
		h,
		base(secret), C.long(len(secret)),
		base(salt), C.long(len(salt)),
		base(prk), C.long(len(prk)),
	)

	if result != 0 {
		return nil, errors.New("HKDF derivation failed")
	}

	return prk, nil
}

func ExpandHKDF(hash crypto.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	h, err := cryptoHashToSwift(hash)
	if err != nil {
		return nil, err
	}

	// Allocate buffer for derived key
	expandedKey := make([]byte, keyLength)

	// Call Swift function
	result := C.expandHKDF(
		h,
		base(pseudorandomKey), C.long(len(pseudorandomKey)),
		base(info), C.long(len(info)),
		base(expandedKey), C.long(len(expandedKey)),
	)

	if result != 0 {
		return nil, errors.New("HKDF derivation failed")
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
