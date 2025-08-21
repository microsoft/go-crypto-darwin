// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build cgo && darwin

package xcrypto

import (
	"errors"
	"hash"

	"github.com/microsoft/go-crypto-darwin/internal/commoncrypto"
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
	var passwordPtr *uint8
	if len(password) > 0 {
		passwordPtr = &password[0]
	}
	var saltPtr *uint8
	if len(salt) > 0 {
		saltPtr = &salt[0]
	}
	status := commoncrypto.CCKeyDerivationPBKDF(
		commoncrypto.KCCPBKDF2,     // PBKDF2 algorithm
		passwordPtr, len(password), // Password pointer and its length
		saltPtr, len(salt), // Salt pointer and its length
		ccDigest,                    // Digest algorithm
		commoncrypto.Unsigned(iter), // Iteration count
		&derivedKey[0], keyLen,      // Output buffer for derived key and its length
	)

	if status != commoncrypto.KCCSuccess {
		return nil, errors.New("PBKDF2 key derivation failed")
	}

	return derivedKey, nil
}

// Mapping Go hash functions to CommonCrypto hash constants
func hashToCCDigestPBKDF2(hash hash.Hash) (commoncrypto.CCPseudoRandomAlgorithm, error) {
	switch hash.(type) {
	case SHA1Hash:
		return commoncrypto.KCCPRFHmacAlgSHA1, nil
	case SHA256Hash:
		return commoncrypto.KCCPRFHmacAlgSHA256, nil
	case SHA384Hash:
		return commoncrypto.KCCPRFHmacAlgSHA384, nil
	case SHA512Hash:
		return commoncrypto.KCCPRFHmacAlgSHA512, nil
	default:
		return 0, errors.New("unsupported hash function")
	}
}
