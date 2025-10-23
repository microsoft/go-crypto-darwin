// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"errors"
	"runtime"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

const (
	// sharedKeySizeMLKEM is the size of a shared key produced by ML-KEM.
	sharedKeySizeMLKEM = 32

	// seedSizeMLKEM is the size of a seed used to generate a decapsulation key.
	seedSizeMLKEM = 64

	// ciphertextSizeMLKEM768 is the size of a ciphertext produced by ML-KEM-768.
	ciphertextSizeMLKEM768 = 1088

	// encapsulationKeySizeMLKEM768 is the size of an ML-KEM-768 encapsulation key.
	encapsulationKeySizeMLKEM768 = 1184

	// ciphertextSizeMLKEM1024 is the size of a ciphertext produced by ML-KEM-1024.
	ciphertextSizeMLKEM1024 = 1568

	// encapsulationKeySizeMLKEM1024 is the size of an ML-KEM-1024 encapsulation key.
	encapsulationKeySizeMLKEM1024 = 1568
)

// SupportsMLKEM returns true if ML-KEM is supported on this platform.
func SupportsMLKEM() bool {
	return cryptokit.SupportsMLKEM() == 1
}

// DecapsulationKeyMLKEM768 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKeyMLKEM768 [seedSizeMLKEM]byte

// GenerateKeyMLKEM768 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM768() (*DecapsulationKeyMLKEM768, error) {
	dk := &DecapsulationKeyMLKEM768{}
	ret := cryptokit.GenerateKeyMLKEM768((*dk)[:])
	if ret != 0 {
		return nil, errors.New("mlkem: key generation failed")
	}
	runtime.KeepAlive(dk)
	return dk, nil
}

// NewDecapsulationKeyMLKEM768 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKeyMLKEM768(seed []byte) (*DecapsulationKeyMLKEM768, error) {
	if len(seed) != seedSizeMLKEM {
		return nil, errors.New("mlkem: invalid seed size")
	}

	dk := &DecapsulationKeyMLKEM768{}
	copy((*dk)[:], seed)
	return dk, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk *DecapsulationKeyMLKEM768) Bytes() []byte {
	return (*dk)[:]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk *DecapsulationKeyMLKEM768) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != ciphertextSizeMLKEM768 {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	sharedKey = make([]byte, sharedKeySizeMLKEM)
	ret := cryptokit.DecapsulateMLKEM768(
		(*dk)[:],
		ciphertext,
		sharedKey,
	)
	runtime.KeepAlive(dk)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(sharedKey)

	if ret != 0 {
		return nil, errors.New("mlkem: decapsulation failed")
	}
	return sharedKey, nil
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk *DecapsulationKeyMLKEM768) EncapsulationKey() *EncapsulationKeyMLKEM768 {
	ek := &EncapsulationKeyMLKEM768{}
	ret := cryptokit.DeriveEncapsulationKeyMLKEM768(
		(*dk)[:],
		(*ek)[:],
	)
	runtime.KeepAlive(dk)
	runtime.KeepAlive(ek)

	if ret != 0 {
		return nil
	}
	return ek
}

// An EncapsulationKeyMLKEM768 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM768.
type EncapsulationKeyMLKEM768 [encapsulationKeySizeMLKEM768]byte

// NewEncapsulationKeyMLKEM768 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM768 returns an error.
func NewEncapsulationKeyMLKEM768(encapsulationKey []byte) (*EncapsulationKeyMLKEM768, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM768 {
		return nil, errors.New("mlkem: invalid encapsulation key size")
	}

	ek := &EncapsulationKeyMLKEM768{}
	copy((*ek)[:], encapsulationKey)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek *EncapsulationKeyMLKEM768) Bytes() []byte {
	return (*ek)[:]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek *EncapsulationKeyMLKEM768) Encapsulate() (sharedKey, ciphertext []byte) {
	sharedKey = make([]byte, sharedKeySizeMLKEM)
	ciphertext = make([]byte, ciphertextSizeMLKEM768)

	ret := cryptokit.EncapsulateMLKEM768(
		(*ek)[:],
		sharedKey,
		ciphertext,
	)
	runtime.KeepAlive(ek)
	runtime.KeepAlive(sharedKey)
	runtime.KeepAlive(ciphertext)

	if ret != 0 {
		return nil, nil
	}
	return sharedKey, ciphertext
}

// DecapsulationKeyMLKEM1024 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKeyMLKEM1024 [seedSizeMLKEM]byte

// GenerateKeyMLKEM1024 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM1024() (*DecapsulationKeyMLKEM1024, error) {
	dk := &DecapsulationKeyMLKEM1024{}
	ret := cryptokit.GenerateKeyMLKEM1024((*dk)[:])
	if ret != 0 {
		return nil, errors.New("mlkem: key generation failed")
	}
	runtime.KeepAlive(dk)
	return dk, nil
}

// NewDecapsulationKeyMLKEM1024 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKeyMLKEM1024(seed []byte) (*DecapsulationKeyMLKEM1024, error) {
	if len(seed) != seedSizeMLKEM {
		return nil, errors.New("mlkem: invalid seed size")
	}

	dk := &DecapsulationKeyMLKEM1024{}
	copy((*dk)[:], seed)
	return dk, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk *DecapsulationKeyMLKEM1024) Bytes() []byte {
	return (*dk)[:]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk *DecapsulationKeyMLKEM1024) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != ciphertextSizeMLKEM1024 {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	sharedKey = make([]byte, sharedKeySizeMLKEM)
	ret := cryptokit.DecapsulateMLKEM1024(
		(*dk)[:],
		ciphertext,
		sharedKey,
	)
	runtime.KeepAlive(dk)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(sharedKey)

	if ret != 0 {
		return nil, errors.New("mlkem: decapsulation failed")
	}
	return sharedKey, nil
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk *DecapsulationKeyMLKEM1024) EncapsulationKey() *EncapsulationKeyMLKEM1024 {
	ek := &EncapsulationKeyMLKEM1024{}
	ret := cryptokit.DeriveEncapsulationKeyMLKEM1024(
		(*dk)[:],
		(*ek)[:],
	)
	runtime.KeepAlive(dk)
	runtime.KeepAlive(ek)

	if ret != 0 {
		return nil
	}
	return ek
}

// An EncapsulationKeyMLKEM1024 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM1024.
type EncapsulationKeyMLKEM1024 [encapsulationKeySizeMLKEM1024]byte

// NewEncapsulationKeyMLKEM1024 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM1024 returns an error.
func NewEncapsulationKeyMLKEM1024(encapsulationKey []byte) (*EncapsulationKeyMLKEM1024, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM1024 {
		return nil, errors.New("mlkem: invalid encapsulation key size")
	}

	ek := &EncapsulationKeyMLKEM1024{}
	copy((*ek)[:], encapsulationKey)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek *EncapsulationKeyMLKEM1024) Bytes() []byte {
	return (*ek)[:]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek *EncapsulationKeyMLKEM1024) Encapsulate() (sharedKey, ciphertext []byte) {
	sharedKey = make([]byte, sharedKeySizeMLKEM)
	ciphertext = make([]byte, ciphertextSizeMLKEM1024)

	ret := cryptokit.EncapsulateMLKEM1024(
		(*ek)[:],
		sharedKey,
		ciphertext,
	)
	runtime.KeepAlive(ek)
	runtime.KeepAlive(sharedKey)
	runtime.KeepAlive(ciphertext)

	if ret != 0 {
		return nil, nil
	}
	return sharedKey, ciphertext
}
