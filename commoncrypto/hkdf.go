// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package commoncrypto

import (
	"hash"

	"github.com/microsoft/go-crypto-darwin/cryptokit"
)

// ExtractHKDF performs the extract step of HKDF using the specified hash function.
func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	hash, err := hashToCryptoHash(h())
	if err != nil {
		return nil, err
	}

	prk, err := cryptokit.ExtractHKDF(hash, secret, salt)
	if err != nil {
		return nil, err
	}

	return prk, nil
}

// ExpandHKDF performs the expand step of HKDF using the specified hash function.
func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	hash, err := hashToCryptoHash(h())
	if err != nil {
		return nil, err
	}

	expandedKey, err := cryptokit.ExpandHKDF(hash, pseudorandomKey, info, keyLength)
	if err != nil {
		return nil, err
	}

	return expandedKey, nil
}
