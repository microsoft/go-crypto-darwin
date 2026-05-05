// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"errors"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

const (
	// privateKeySizeMLDSA is the size of an ML-DSA private key seed.
	privateKeySizeMLDSA = 32

	// publicKeySizeMLDSA65 is the size of an ML-DSA-65 public key encoding.
	publicKeySizeMLDSA65 = 1952

	// publicKeySizeMLDSA87 is the size of an ML-DSA-87 public key encoding.
	publicKeySizeMLDSA87 = 2592

	// signatureSizeMLDSA65 is the size of an ML-DSA-65 signature.
	signatureSizeMLDSA65 = 3309

	// signatureSizeMLDSA87 is the size of an ML-DSA-87 signature.
	signatureSizeMLDSA87 = 4627
)

// SupportsMLDSA returns true if the given ML-DSA parameter set is supported
// on this platform.
func SupportsMLDSA(params MLDSAParameters) bool {
	switch params.publicKeySize {
	case publicKeySizeMLDSA65, publicKeySizeMLDSA87:
		return cryptokit.SupportsMLDSA() == 1
	default:
		return false
	}
}

// MLDSAParameters represents one of the fixed ML-DSA parameter sets.
type MLDSAParameters struct {
	name          string
	publicKeySize int
	signatureSize int
	generateKey   func(seed []uint8) int64
	derivePublic  func(seed []uint8, publicKey []uint8) int64
	sign          func(seed []uint8, message []uint8, context []uint8, signature []uint8, signatureLen *int64) int64
	verify        func(publicKey []uint8, message []uint8, context []uint8, signature []uint8) int64
	validatePub   func(publicKey []uint8) int64
}

var (
	mldsa65 = MLDSAParameters{
		name:          "ML-DSA-65",
		publicKeySize: publicKeySizeMLDSA65,
		signatureSize: signatureSizeMLDSA65,
		generateKey:   cryptokit.GenerateKeyMLDSA65,
		derivePublic:  cryptokit.DerivePublicKeyMLDSA65,
		sign:          cryptokit.SignMLDSA65,
		verify:        cryptokit.VerifyMLDSA65,
		validatePub:   cryptokit.ValidatePublicKeyMLDSA65,
	}
	mldsa87 = MLDSAParameters{
		name:          "ML-DSA-87",
		publicKeySize: publicKeySizeMLDSA87,
		signatureSize: signatureSizeMLDSA87,
		generateKey:   cryptokit.GenerateKeyMLDSA87,
		derivePublic:  cryptokit.DerivePublicKeyMLDSA87,
		sign:          cryptokit.SignMLDSA87,
		verify:        cryptokit.VerifyMLDSA87,
		validatePub:   cryptokit.ValidatePublicKeyMLDSA87,
	}
)

// MLDSA65 returns the ML-DSA-65 parameter set.
func MLDSA65() MLDSAParameters { return mldsa65 }

// MLDSA87 returns the ML-DSA-87 parameter set.
func MLDSA87() MLDSAParameters { return mldsa87 }

func (params MLDSAParameters) valid() bool {
	return params.generateKey != nil
}

// PublicKeySize returns the size of public keys for this parameter set, in bytes.
func (params MLDSAParameters) PublicKeySize() int { return params.publicKeySize }

// SignatureSize returns the size of signatures for this parameter set, in bytes.
func (params MLDSAParameters) SignatureSize() int { return params.signatureSize }

// String returns the name of the parameter set.
func (params MLDSAParameters) String() string { return params.name }

var errInvalidMLDSAParameters = errors.New("mldsa: invalid parameters")

// PrivateKeyMLDSA is an ML-DSA private key seed.
type PrivateKeyMLDSA struct {
	params MLDSAParameters
	seed   [privateKeySizeMLDSA]byte
}

// GenerateKeyMLDSA generates a new ML-DSA private key.
func GenerateKeyMLDSA(params MLDSAParameters) (*PrivateKeyMLDSA, error) {
	if !params.valid() {
		return nil, errInvalidMLDSAParameters
	}
	key := &PrivateKeyMLDSA{params: params}
	if ret := params.generateKey(key.seed[:]); ret != 0 {
		return nil, errors.New("mldsa: key generation failed")
	}
	return key, nil
}

// NewPrivateKeyMLDSA constructs an ML-DSA private key from its seed.
func NewPrivateKeyMLDSA(params MLDSAParameters, seed []byte) (*PrivateKeyMLDSA, error) {
	if !params.valid() {
		return nil, errInvalidMLDSAParameters
	}
	if len(seed) != privateKeySizeMLDSA {
		return nil, errors.New("mldsa: invalid private key size")
	}
	key := &PrivateKeyMLDSA{params: params}
	copy(key.seed[:], seed)
	return key, nil
}

// Bytes returns the private key seed.
func (key *PrivateKeyMLDSA) Bytes() []byte {
	return key.seed[:]
}

// Parameters returns the parameters associated with this private key.
func (key *PrivateKeyMLDSA) Parameters() MLDSAParameters { return key.params }

// PublicKey returns the corresponding public key.
func (key *PrivateKeyMLDSA) PublicKey() *PublicKeyMLDSA {
	publicKey := &PublicKeyMLDSA{params: key.params}
	if ret := key.params.derivePublic(key.seed[:], publicKey.bytes[:key.params.publicKeySize]); ret != 0 {
		panic("mldsa: failed to derive public key")
	}
	return publicKey
}

// Sign signs message with context using ML-DSA.
func (key *PrivateKeyMLDSA) Sign(message []byte, context string) ([]byte, error) {
	if len(context) > 255 {
		return nil, errors.New("mldsa: context too long")
	}
	signature := make([]byte, key.params.signatureSize)
	sigLen := int64(key.params.signatureSize)
	contextBytes := []byte(context)
	if ret := key.params.sign(key.seed[:], message, contextBytes, signature, &sigLen); ret != 0 {
		return nil, errors.New("mldsa: signing failed")
	}
	return signature[:sigLen], nil
}

// SignExternalMu signs a pre-hashed mu message representative using ML-DSA.
func (key *PrivateKeyMLDSA) SignExternalMu(mu []byte) ([]byte, error) {
	if len(mu) != 64 {
		return nil, errors.New("mldsa: invalid message hash length")
	}
	return nil, errors.New("mldsa: external mu not supported")
}

// PublicKeyMLDSA is an ML-DSA public key.
type PublicKeyMLDSA struct {
	params MLDSAParameters
	bytes  [publicKeySizeMLDSA87]byte
}

// NewPublicKeyMLDSA constructs an ML-DSA public key from its encoding.
func NewPublicKeyMLDSA(params MLDSAParameters, publicKey []byte) (*PublicKeyMLDSA, error) {
	if !params.valid() {
		return nil, errInvalidMLDSAParameters
	}
	if len(publicKey) != params.publicKeySize {
		return nil, errors.New("mldsa: invalid public key size")
	}
	if ret := params.validatePub(publicKey); ret != 0 {
		return nil, errors.New("mldsa: invalid public key")
	}
	key := &PublicKeyMLDSA{params: params}
	copy(key.bytes[:], publicKey)
	return key, nil
}

// Bytes returns the public key encoding.
func (key *PublicKeyMLDSA) Bytes() []byte {
	return key.bytes[:key.params.publicKeySize]
}

// Parameters returns the parameters associated with this public key.
func (key *PublicKeyMLDSA) Parameters() MLDSAParameters { return key.params }

// Verify verifies an ML-DSA signature.
func (key *PublicKeyMLDSA) Verify(message, signature []byte, context string) error {
	if len(signature) != key.params.signatureSize {
		return errors.New("mldsa: invalid signature length")
	}
	if len(context) > 255 {
		return errors.New("mldsa: context too long")
	}
	contextBytes := []byte(context)
	if ret := key.params.verify(key.bytes[:key.params.publicKeySize], message, contextBytes, signature); ret != 0 {
		return errors.New("mldsa: verification failed")
	}
	return nil
}

// VerifyExternalMu verifies an ML-DSA signature over a pre-hashed mu message representative.
func (key *PublicKeyMLDSA) VerifyExternalMu(mu, signature []byte) error {
	if len(mu) != 64 {
		return errors.New("mldsa: invalid message hash length")
	}
	if len(signature) != key.params.signatureSize {
		return errors.New("mldsa: invalid signature length")
	}
	return errors.New("mldsa: external mu not supported")
}
