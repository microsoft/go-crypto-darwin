// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"crypto/subtle"
	"errors"
	"unsafe"

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
}

var (
	mldsa65 = MLDSAParameters{
		name:          "ML-DSA-65",
		publicKeySize: publicKeySizeMLDSA65,
		signatureSize: signatureSizeMLDSA65,
	}
	mldsa87 = MLDSAParameters{
		name:          "ML-DSA-87",
		publicKeySize: publicKeySizeMLDSA87,
		signatureSize: signatureSizeMLDSA87,
	}
)

// MLDSA65 returns the ML-DSA-65 parameter set.
func MLDSA65() MLDSAParameters { return mldsa65 }

// MLDSA87 returns the ML-DSA-87 parameter set.
func MLDSA87() MLDSAParameters { return mldsa87 }

func (params MLDSAParameters) valid() bool {
	return params.publicKeySize == publicKeySizeMLDSA65 || params.publicKeySize == publicKeySizeMLDSA87
}

// Dispatch directly to the bindings so escape analysis can see their
// noescape guarantees. Calls through function fields would hide them.
func (params MLDSAParameters) generateKey(seed []byte) int64 {
	switch params.publicKeySize {
	case publicKeySizeMLDSA65:
		return cryptokit.GenerateKeyMLDSA65(seed)
	case publicKeySizeMLDSA87:
		return cryptokit.GenerateKeyMLDSA87(seed)
	default:
		return 1
	}
}

func (params MLDSAParameters) derivePublic(seed, publicKey []byte) int64 {
	switch params.publicKeySize {
	case publicKeySizeMLDSA65:
		return cryptokit.DerivePublicKeyMLDSA65(seed, publicKey)
	case publicKeySizeMLDSA87:
		return cryptokit.DerivePublicKeyMLDSA87(seed, publicKey)
	default:
		return 1
	}
}

func (params MLDSAParameters) sign(seed, message, context, signature []byte, signatureLen *int64) int64 {
	switch params.publicKeySize {
	case publicKeySizeMLDSA65:
		return cryptokit.SignMLDSA65(seed, message, context, signature, signatureLen)
	case publicKeySizeMLDSA87:
		return cryptokit.SignMLDSA87(seed, message, context, signature, signatureLen)
	default:
		return 1
	}
}

func (params MLDSAParameters) verify(publicKey, message, context, signature []byte) int64 {
	switch params.publicKeySize {
	case publicKeySizeMLDSA65:
		return cryptokit.VerifyMLDSA65(publicKey, message, context, signature)
	case publicKeySizeMLDSA87:
		return cryptokit.VerifyMLDSA87(publicKey, message, context, signature)
	default:
		return 1
	}
}

func (params MLDSAParameters) validatePub(publicKey []byte) int64 {
	switch params.publicKeySize {
	case publicKeySizeMLDSA65:
		return cryptokit.ValidatePublicKeyMLDSA65(publicKey)
	case publicKeySizeMLDSA87:
		return cryptokit.ValidatePublicKeyMLDSA87(publicKey)
	default:
		return 1
	}
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

// Equal reports whether key and other represent the same private key.
func (key *PrivateKeyMLDSA) Equal(other *PrivateKeyMLDSA) bool {
	if other == nil {
		return false
	}
	return key.params.name == other.params.name &&
		subtle.ConstantTimeCompare(key.seed[:], other.seed[:]) == 1
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
	// Swift copies the context into Data during the synchronous call.
	// These borrowed string bytes must not be mutated or retained.
	contextBytes := unsafe.Slice(unsafe.StringData(context), len(context))
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

// Equal reports whether key and other represent the same public key.
func (key *PublicKeyMLDSA) Equal(other *PublicKeyMLDSA) bool {
	if other == nil {
		return false
	}
	return key.params.name == other.params.name &&
		subtle.ConstantTimeCompare(key.bytes[:key.params.publicKeySize], other.bytes[:other.params.publicKeySize]) == 1
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
	// Swift copies the context into Data during the synchronous call.
	// These borrowed string bytes must not be mutated or retained.
	contextBytes := unsafe.Slice(unsafe.StringData(context), len(context))
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
