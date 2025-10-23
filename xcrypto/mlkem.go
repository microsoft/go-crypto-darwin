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
	// SharedKeySize is the size of a shared key produced by ML-KEM.
	SharedKeySize = 32

	// SeedSize is the size of a seed used to generate a decapsulation key.
	SeedSize = 64

	// CiphertextSize768 is the size of a ciphertext produced by ML-KEM-768.
	CiphertextSize768 = 1088

	// EncapsulationKeySize768 is the size of an ML-KEM-768 encapsulation key.
	EncapsulationKeySize768 = 1184

	// CiphertextSize1024 is the size of a ciphertext produced by ML-KEM-1024.
	CiphertextSize1024 = 1568

	// EncapsulationKeySize1024 is the size of an ML-KEM-1024 encapsulation key.
	EncapsulationKeySize1024 = 1568
)

// supportsMLKEM returns true if ML-KEM is available on this macOS version.
func supportsMLKEM() bool {
	return cryptokit.SupportsMLKEM() == 1
}

// DecapsulationKey768 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKey768 struct {
	seed [SeedSize]byte
}

// GenerateKey768 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKey768() (*DecapsulationKey768, error) {
	if !supportsMLKEM() {
		return nil, errors.New("mlkem: ML-KEM is not supported on this macOS version")
	}

	dk := &DecapsulationKey768{}
	ret := cryptokit.GenerateKeyMLKEM768(addrNeverEmpty(dk.seed[:]))
	if ret != 0 {
		return nil, errors.New("mlkem: key generation failed")
	}
	runtime.KeepAlive(dk.seed)
	return dk, nil
}

// NewDecapsulationKey768 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKey768(seed []byte) (*DecapsulationKey768, error) {
	if !supportsMLKEM() {
		return nil, errors.New("mlkem: ML-KEM is not supported on this macOS version")
	}
	if len(seed) != SeedSize {
		return nil, errors.New("mlkem: invalid seed size")
	}

	dk := &DecapsulationKey768{}
	copy(dk.seed[:], seed)
	return dk, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk *DecapsulationKey768) Bytes() []byte {
	return dk.seed[:]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk *DecapsulationKey768) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if !supportsMLKEM() {
		return nil, errors.New("mlkem: ML-KEM is not supported on this macOS version")
	}
	if len(ciphertext) != CiphertextSize768 {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	sharedKey = make([]byte, SharedKeySize)
	ret := cryptokit.DecapsulateMLKEM768(
		addrNeverEmpty(dk.seed[:]),
		addrNeverEmpty(ciphertext),
		addrNeverEmpty(sharedKey),
	)
	runtime.KeepAlive(dk.seed)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(sharedKey)

	if ret != 0 {
		return nil, errors.New("mlkem: decapsulation failed")
	}
	return sharedKey, nil
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk *DecapsulationKey768) EncapsulationKey() *EncapsulationKey768 {
	ek := &EncapsulationKey768{}
	ret := cryptokit.DeriveEncapsulationKeyMLKEM768(
		addrNeverEmpty(dk.seed[:]),
		addrNeverEmpty(ek.bytes[:]),
	)
	runtime.KeepAlive(dk.seed)
	runtime.KeepAlive(ek.bytes)

	if ret != 0 {
		return nil
	}
	return ek
}

// An EncapsulationKey768 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKey768.
type EncapsulationKey768 struct {
	bytes [EncapsulationKeySize768]byte
}

// NewEncapsulationKey768 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKey768 returns an error.
func NewEncapsulationKey768(encapsulationKey []byte) (*EncapsulationKey768, error) {
	if !supportsMLKEM() {
		return nil, errors.New("mlkem: ML-KEM is not supported on this macOS version")
	}
	if len(encapsulationKey) != EncapsulationKeySize768 {
		return nil, errors.New("mlkem: invalid encapsulation key size")
	}

	ek := &EncapsulationKey768{}
	copy(ek.bytes[:], encapsulationKey)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek *EncapsulationKey768) Bytes() []byte {
	return ek.bytes[:]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek *EncapsulationKey768) Encapsulate() (sharedKey, ciphertext []byte) {
	if !supportsMLKEM() {
		return nil, nil
	}

	sharedKey = make([]byte, SharedKeySize)
	ciphertext = make([]byte, CiphertextSize768)

	ret := cryptokit.EncapsulateMLKEM768(
		addrNeverEmpty(ek.bytes[:]),
		addrNeverEmpty(sharedKey),
		addrNeverEmpty(ciphertext),
	)
	runtime.KeepAlive(ek.bytes)
	runtime.KeepAlive(sharedKey)
	runtime.KeepAlive(ciphertext)

	if ret != 0 {
		return nil, nil
	}
	return sharedKey, ciphertext
}

// DecapsulationKey1024 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKey1024 struct {
	seed [SeedSize]byte
}

// GenerateKey1024 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKey1024() (*DecapsulationKey1024, error) {
	if !supportsMLKEM() {
		return nil, errors.New("mlkem: ML-KEM is not supported on this macOS version")
	}

	dk := &DecapsulationKey1024{}
	ret := cryptokit.GenerateKeyMLKEM1024(addrNeverEmpty(dk.seed[:]))
	if ret != 0 {
		return nil, errors.New("mlkem: key generation failed")
	}
	runtime.KeepAlive(dk.seed)
	return dk, nil
}

// NewDecapsulationKey1024 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKey1024(seed []byte) (*DecapsulationKey1024, error) {
	if !supportsMLKEM() {
		return nil, errors.New("mlkem: ML-KEM is not supported on this macOS version")
	}
	if len(seed) != SeedSize {
		return nil, errors.New("mlkem: invalid seed size")
	}

	dk := &DecapsulationKey1024{}
	copy(dk.seed[:], seed)
	return dk, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk *DecapsulationKey1024) Bytes() []byte {
	return dk.seed[:]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk *DecapsulationKey1024) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if !supportsMLKEM() {
		return nil, errors.New("mlkem: ML-KEM is not supported on this macOS version")
	}
	if len(ciphertext) != CiphertextSize1024 {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	sharedKey = make([]byte, SharedKeySize)
	ret := cryptokit.DecapsulateMLKEM1024(
		addrNeverEmpty(dk.seed[:]),
		addrNeverEmpty(ciphertext),
		addrNeverEmpty(sharedKey),
	)
	runtime.KeepAlive(dk.seed)
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(sharedKey)

	if ret != 0 {
		return nil, errors.New("mlkem: decapsulation failed")
	}
	return sharedKey, nil
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk *DecapsulationKey1024) EncapsulationKey() *EncapsulationKey1024 {
	ek := &EncapsulationKey1024{}
	ret := cryptokit.DeriveEncapsulationKeyMLKEM1024(
		addrNeverEmpty(dk.seed[:]),
		addrNeverEmpty(ek.bytes[:]),
	)
	runtime.KeepAlive(dk.seed)
	runtime.KeepAlive(ek.bytes)

	if ret != 0 {
		return nil
	}
	return ek
}

// An EncapsulationKey1024 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKey1024.
type EncapsulationKey1024 struct {
	bytes [EncapsulationKeySize1024]byte
}

// NewEncapsulationKey1024 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKey1024 returns an error.
func NewEncapsulationKey1024(encapsulationKey []byte) (*EncapsulationKey1024, error) {
	if !supportsMLKEM() {
		return nil, errors.New("mlkem: ML-KEM is not supported on this macOS version")
	}
	if len(encapsulationKey) != EncapsulationKeySize1024 {
		return nil, errors.New("mlkem: invalid encapsulation key size")
	}

	ek := &EncapsulationKey1024{}
	copy(ek.bytes[:], encapsulationKey)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek *EncapsulationKey1024) Bytes() []byte {
	return ek.bytes[:]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek *EncapsulationKey1024) Encapsulate() (sharedKey, ciphertext []byte) {
	if !supportsMLKEM() {
		return nil, nil
	}

	sharedKey = make([]byte, SharedKeySize)
	ciphertext = make([]byte, CiphertextSize1024)

	ret := cryptokit.EncapsulateMLKEM1024(
		addrNeverEmpty(ek.bytes[:]),
		addrNeverEmpty(sharedKey),
		addrNeverEmpty(ciphertext),
	)
	runtime.KeepAlive(ek.bytes)
	runtime.KeepAlive(sharedKey)
	runtime.KeepAlive(ciphertext)

	if ret != 0 {
		return nil, nil
	}
	return sharedKey, ciphertext
}
