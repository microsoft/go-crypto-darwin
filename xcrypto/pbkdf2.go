// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"crypto"
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
	status := commoncrypto.CCKeyDerivationPBKDF(
		commoncrypto.KCCPBKDF2, // PBKDF2 algorithm
		password,               // Password
		salt,                   // Salt
		ccDigest,               // Digest algorithm
		uint32(iter),           // Iteration count
		derivedKey,             // Output buffer for derived key
	)

	if status != commoncrypto.KCCSuccess {
		return nil, errors.New("PBKDF2 key derivation failed")
	}

	return derivedKey, nil
}

// Mapping Go hash functions to CommonCrypto hash constants
func hashToCCDigestPBKDF2(hash hash.Hash) (commoncrypto.CCPseudoRandomAlgorithm, error) {
	switch h := hash.(type) {
	case *evpHash:
		switch h.alg.ch {
		case crypto.SHA1:
			return commoncrypto.KCCPRFHmacAlgSHA1, nil
		case crypto.SHA256:
			return commoncrypto.KCCPRFHmacAlgSHA256, nil
		case crypto.SHA384:
			return commoncrypto.KCCPRFHmacAlgSHA384, nil
		case crypto.SHA512:
			return commoncrypto.KCCPRFHmacAlgSHA512, nil
		default:
			return 0, errors.New("unsupported hash function")
		}
	default:
		return 0, errors.New("unsupported hash function")
	}
}
