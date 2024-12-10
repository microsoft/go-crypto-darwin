// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import (
	"errors"
)

// GenerateKeyEd25519 generates an Ed25519 private key using the Swift implementation.
func GenerateKeyEd25519(key []byte) {
	C.generateKeyEd25519(base(key))
}

// NewPrivateKeyEd25519FromSeed generates an Ed25519 private key from a seed.
func NewPrivateKeyEd25519FromSeed(key, seed []byte) error {
	result := C.newPrivateKeyEd25519FromSeed(base(key), base(seed))
	if result != 0 {
		return errors.New("failed to generate Ed25519 key from seed")
	}
	return nil
}

// NewPublicKeyEd25519 creates a new Ed25519 public key from raw bytes.
func NewPublicKeyEd25519(key, pub []byte) error {
	result := C.newPublicKeyEd25519(base(key), base(pub))
	if result != 0 {
		return errors.New("failed to create Ed25519 public key")
	}
	return nil
}

// SignEd25519 signs a message using the provided private key.
func SignEd25519(sig, privateKey, message []byte) error {
	result := C.signEd25519(base(privateKey), base(message), C.size_t(len(message)), base(sig))
	if result < 0 {
		switch result {
		case -1:
			return errors.New("invalid inputs to SignEd25519")
		case -2:
			return errors.New("failed to reconstruct private key")
		case -3:
			return errors.New("failed to sign the message")
		case -4:
			return errors.New("signature buffer too small")
		default:
			return errors.New("unknown error in SignEd25519")
		}
	}
	return nil
}

// VerifyEd25519 verifies a signature using the provided public key and message.
func VerifyEd25519(publicKey, message, sig []byte) error {
	result := C.verifyEd25519(base(publicKey), base(message), C.size_t(len(message)), base(sig))
	switch result {
	case 1:
		return nil // Valid signature
	case 0:
		return errors.New("ed25519: invalid signature")
	case -1:
		return errors.New("invalid inputs to VerifyEd25519")
	case -2:
		return errors.New("failed to reconstruct public key")
	default:
		return errors.New("unknown error in VerifyEd25519")
	}
}
