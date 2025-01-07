// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin && cgo

package xcrypto

import (
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

	prk, err := cryptokit.ExtractHKDF(hash, secret, salt)
	if err != nil {
		return nil, err
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

	expandedKey, err := cryptokit.ExpandHKDF(hash, pseudorandomKey, info, keyLength)
	if err != nil {
		return nil, err
	}

	return expandedKey, nil
}
