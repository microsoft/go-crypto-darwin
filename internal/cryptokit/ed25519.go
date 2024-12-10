// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import (
	"errors"
	"unsafe"
)

const (
	// signatureSizeEd25519 is the size, in bytes, of signatures generated and verified by crypto/ed25519.
	signatureSizeEd25519 = 64
	// seedSizeEd25519 is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	seedSizeEd25519 = 32
)

// GenerateKeyEd25519 generates an Ed25519 private key using the Swift implementation.
func GenerateKeyEd25519() (unsafe.Pointer, error) {
	// Call the Swift function
	pkey := C.generateKeyEd25519()
	if pkey == nil {
		return nil, errors.New("failed to generate Ed25519 key")
	}

	// Return the raw pointer (to be managed by the caller)
	return pkey, nil
}

// NewPrivateKeyEd25519FromSeed generates an Ed25519 private key from a seed.
func NewPrivateKeyEd25519FromSeed(seed []byte) (unsafe.Pointer, error) {
	seedPtr := pbase(seed)
	key := C.newPrivateKeyEd25519FromSeed((*C.uint8_t)(seedPtr), C.int(len(seed)))
	if key == nil {
		return nil, errors.New("failed to generate Ed25519 key from seed")
	}

	return key, nil
}

// NewPublicKeyEd25519 creates a new Ed25519 public key from raw bytes.
func NewPublicKeyEd25519(pub []byte) (unsafe.Pointer, error) {
	pubPtr := pbase(pub)
	pkey := C.newPublicKeyEd25519((*C.uint8_t)(pubPtr), C.int(len(pub)))
	if pkey == nil {
		return nil, errors.New("failed to create Ed25519 public key")
	}

	return pkey, nil
}

// GetPrivateKeyEd25519Bytes retrieves the raw bytes of an Ed25519 private key.
func GetPrivateKeyEd25519Bytes(key unsafe.Pointer) ([]byte, error) {
	// Allocate a buffer to hold the private key
	buffer := make([]byte, signatureSizeEd25519)
	cBuffer := (*C.uint8_t)(unsafe.Pointer(&buffer[0]))

	// Call the Swift function
	result := C.getPrivateKeyEd25519Bytes(key, cBuffer, C.int(len(buffer)))
	if result < 0 {
		switch result {
		case -1:
			return nil, errors.New("invalid inputs to GetPrivateKeyEd25519Bytes")
		case -2:
			return nil, errors.New("buffer too small in GetPrivateKeyEd25519Bytes")
		default:
			return nil, errors.New("unknown error in GetPrivateKeyEd25519Bytes")
		}
	}

	return buffer[:result], nil
}

// ExtractPublicKeyEd25519 extracts the public key bytes from a private key.
func ExtractPublicKeyEd25519(privateKey unsafe.Pointer) ([]byte, error) {
	// Allocate a buffer to hold the public key
	buffer := make([]byte, seedSizeEd25519)
	cBuffer := (*C.uint8_t)(unsafe.Pointer(&buffer[0]))

	// Call the Swift function to extract the public key
	result := C.extractPublicKeyEd25519(privateKey, cBuffer, C.int(len(buffer)))
	if result < 0 {
		switch result {
		case -1:
			return nil, errors.New("invalid inputs to ExtractPublicKeyEd25519")
		case -2:
			return nil, errors.New("buffer too small in ExtractPublicKeyEd25519")
		default:
			return nil, errors.New("unknown error in ExtractPublicKeyEd25519")
		}
	}

	// Trim the buffer to the actual size returned
	return buffer[:result], nil
}

// SignEd25519 signs a message using the provided private key.
func SignEd25519(privateKey unsafe.Pointer, message []byte) ([]byte, error) {
	// Allocate a buffer to hold the signature
	sig := make([]byte, signatureSizeEd25519)
	cSig := (*C.uint8_t)(unsafe.Pointer(&sig[0]))

	// Call the Swift function
	messagePtr := unsafe.Pointer(&message[0])
	result := C.signEd25519(privateKey, (*C.uint8_t)(messagePtr), C.int(len(message)), cSig, C.int(len(sig)))
	if result < 0 {
		switch result {
		case -1:
			return nil, errors.New("invalid inputs to SignEd25519")
		case -2:
			return nil, errors.New("failed to reconstruct private key")
		case -3:
			return nil, errors.New("failed to sign the message")
		case -4:
			return nil, errors.New("signature buffer too small")
		default:
			return nil, errors.New("unknown error in SignEd25519")
		}
	}

	// Trim the buffer to the actual size of the signature
	return sig[:result], nil
}

// VerifyEd25519 verifies a signature using the provided public key and message.
func VerifyEd25519(publicKey unsafe.Pointer, message, sig []byte) error {
	messagePtr := base(message)
	sigPtr := base(sig)

	// Call the Swift function
	result := C.verifyEd25519(publicKey, (*C.uint8_t)(messagePtr), C.int(len(message)), (*C.uint8_t)(sigPtr), C.int(len(sig)))
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

// FreeKeyEd25519 releases the memory allocated for the key in Swift.
func FreeKeyEd25519(key unsafe.Pointer) {
	if key != nil {
		C.freeKeyEd25519(key)
	}
}
