// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin && cgo

package xcrypto

import (
	"crypto"
	"errors"
	"hash"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

// ExtractHKDF performs the extract step of HKDF using the specified hash function.
func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	// Handle empty secret
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	hash, err := hashToCryptoHash(h())
	if err != nil {
		return nil, err
	}

	// Default salt to a zero-filled array if not provided
	if len(salt) == 0 {
		salt = make([]byte, hash.Size())
	}

	swiftHash, err := cryptoHashToSwift(hash)
	if err != nil {
		return nil, err
	}

	// Allocate buffer for derived key
	prk := make([]byte, hash.Size())

	result := cryptokit.ExtractHKDF(
		swiftHash,
		addr(secret), len(secret),
		addr(salt), len(salt),
		addr(prk), len(prk),
	)
	if result != 0 {
		return nil, errors.New("HKDF derivation failed")
	}

	return prk, nil
}

// ExpandHKDF performs the expand step of HKDF using the specified hash function.
func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	// Handle empty secret
	if len(pseudorandomKey) == 0 {
		return nil, errors.New("pseudorandom key cannot be empty")
	}

	hash, err := hashToCryptoHash(h())
	if err != nil {
		return nil, err
	}

	// Determine the maximum expandable key length based on the hash function
	maxAllowedLength := hash.Size() * 255

	// Validate requested key length
	if keyLength > maxAllowedLength {
		return nil, errors.New("requested key length exceeds maximum allowable size")
	}

	swiftHash, err := cryptoHashToSwift(hash)
	if err != nil {
		return nil, err
	}

	// Allocate buffer for derived key
	expandedKey := make([]byte, keyLength)

	result := cryptokit.ExpandHKDF(
		swiftHash,
		addr(pseudorandomKey), len(pseudorandomKey),
		addr(info), len(info),
		addr(expandedKey), len(expandedKey),
	)
	if result != 0 {
		return nil, errors.New("HKDF derivation failed")
	}

	return expandedKey, nil
}

func cryptoHashToSwift(hash crypto.Hash) (int32, error) {
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
