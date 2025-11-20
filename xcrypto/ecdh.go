// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"errors"
	"runtime"
	"slices"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
	"github.com/microsoft/go-crypto-darwin/internal/security"
)

type PublicKeyECDH struct {
	_pkey security.SecKeyRef
	bytes []byte
}

func (k *PublicKeyECDH) finalize() {
	if k._pkey != nil {
		security.CFRelease(security.CFTypeRef(k._pkey))
	}
}

type PrivateKeyECDH struct {
	_pkey security.SecKeyRef
	pub   []byte
	priv  []byte // For X25519: the actual private key bytes
	curve string // Track the curve type
}

func (k *PrivateKeyECDH) finalize() {
	if k._pkey != nil {
		security.CFRelease(security.CFTypeRef(k._pkey))
	}
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	if len(bytes) < 1 {
		return nil, errors.New("NewPublicKeyECDH: missing key")
	}
	// For X25519, we don't need a SecKeyRef since we'll use CryptoKit directly
	if curve == "X25519" {
		return &PublicKeyECDH{nil, slices.Clone(bytes)}, nil
	}
	pubKeyRef, err := createSecKeyWithData(bytes, security.KSecAttrKeyTypeECSECPrimeRandom, security.KSecAttrKeyClassPublic)
	if err != nil {
		return nil, err
	}
	pubKey := &PublicKeyECDH{pubKeyRef, slices.Clone(bytes)}
	runtime.SetFinalizer(pubKey, (*PublicKeyECDH).finalize)
	return pubKey, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

// bytes expects the public key to be in uncompressed ANSI X9.63 format
func NewPrivateKeyECDH(curve string, pub, priv []byte) (*PrivateKeyECDH, error) {
	// For X25519, we don't use SecurityFramework
	if curve == "X25519" {
		// If public key is not provided, generate it from the private key
		publicKey := pub
		if publicKey == nil {
			if len(priv) != 32 {
				return nil, errors.New("crypto/ecdh: invalid private key size")
			}
			// Derive the public key from the private key using CryptoKit
			// We need a 64-byte buffer: first 32 for private key input, last 32 for public key output
			buf := make([]byte, 64)
			copy(buf[:32], priv) // Copy private key into first 32 bytes

			// Call PublicKeyX25519 to derive public key from private key
			ret := cryptokit.PublicKeyX25519(buf)
			if ret != 0 {
				return nil, errors.New("failed to derive X25519 public key")
			}

			// Extract the public key (written to buf[32:64])
			publicKey = buf[32:64]
		}

		privKey := &PrivateKeyECDH{
			_pkey: nil,
			pub:   publicKey,
			priv:  slices.Clone(priv),
			curve: curve,
		}
		return privKey, nil
	}

	key := append(slices.Clone(pub), priv...)
	privKeyRef, err := createSecKeyWithData(key, security.KSecAttrKeyTypeECSECPrimeRandom, security.KSecAttrKeyClassPrivate)
	if err != nil {
		return nil, err
	}
	privKey := &PrivateKeyECDH{privKeyRef, pub, nil, curve}
	runtime.SetFinalizer(privKey, (*PrivateKeyECDH).finalize)
	return privKey, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)

	// For X25519, just return the public key bytes we stored
	if k.curve == "X25519" {
		return &PublicKeyECDH{
			_pkey: nil,
			bytes: slices.Clone(k.pub),
		}, nil
	}

	// For EC curves, use SecurityFramework
	pubKeyRef := security.SecKeyCopyPublicKey(k._pkey)
	if pubKeyRef == nil {
		return nil, errors.New("failed to extract public key")
	}
	pubKey := &PublicKeyECDH{pubKeyRef, k.pub}
	runtime.SetFinalizer(pubKey, (*PublicKeyECDH).finalize)
	return pubKey, nil
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	defer runtime.KeepAlive(pub)

	// Handle X25519 using CryptoKit
	if priv.curve == "X25519" {
		if priv == nil || pub == nil {
			return nil, errors.New("invalid keys")
		}

		if len(priv.priv) != 32 {
			return nil, errors.New("invalid private key size")
		}

		if len(pub.bytes) != 32 {
			return nil, errors.New("invalid public key size")
		}

		// Use CryptoKit to perform the key exchange
		sharedSecret := make([]byte, 32)

		ret := cryptokit.X25519(priv.priv, pub.bytes, sharedSecret)
		if ret != 0 {
			return nil, errors.New("x25519: key exchange failed")
		}

		return sharedSecret, nil
	}

	// Handle EC curves using SecurityFramework
	if priv._pkey == nil {
		return nil, errors.New("ECDH: invalid private key")
	}

	var algorithm = security.KSecKeyAlgorithmECDHKeyExchangeStandard
	supported := security.SecKeyIsAlgorithmSupported(priv._pkey, security.KSecKeyOperationTypeKeyExchange, algorithm)
	if supported == 0 {
		return nil, errors.New("ECDH algorithm not supported for the given private key")
	}

	var cfErr security.CFErrorRef
	// Perform the key exchange
	sharedSecretRef := security.SecKeyCopyKeyExchangeResult(
		priv._pkey,
		algorithm,
		pub._pkey,
		security.CFDictionaryRef(unsafe.Pointer(uintptr(0))),
		&cfErr,
	)
	if err := goCFErrorRef(cfErr); err != nil {
		return nil, err
	}
	defer security.CFRelease(security.CFTypeRef(sharedSecretRef))

	sharedSecret := cfDataToBytes(sharedSecretRef)
	return sharedSecret, nil
}

func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	keySize := curveToKeySizeInBytes(curve)
	if keySize == 0 {
		return nil, nil, errors.New("unsupported curve")
	}

	// Handle X25519 specially using CryptoKit
	if curve == "X25519" {
		privKey := make([]byte, 64)
		result := cryptokit.GenerateKeyX25519(privKey)
		if result != 0 {
			return nil, nil, errors.New("X25519 key generation failed")
		}

		return &PrivateKeyECDH{
			_pkey: nil,
			pub:   privKey[32:64],
			priv:  privKey[:32],
			curve: curve,
		}, privKey[:32], nil
	}

	keySizeInBits := curveToKeySizeInBits(curve)
	// Generate the private key and get its DER representation
	privKeyDER, privKeyRef, err := createSecKeyRandom(security.KSecAttrKeyTypeECSECPrimeRandom, keySizeInBits)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := extractECDHComponents(privKeyDER, keySize)
	if err != nil {
		security.CFRelease(security.CFTypeRef(privKeyRef))
		return nil, nil, err
	}
	k := &PrivateKeyECDH{
		_pkey: privKeyRef,
		pub:   pub,
		priv:  priv,
		curve: curve,
	}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, priv, nil
}

func extractECDHComponents(der []byte, keySize int) (pub, priv []byte, err error) {
	// The private component is the last of the three equally-sized chunks
	// for the elliptic curve private key.
	if len(der) != 1+keySize*3 {
		return nil, nil, errors.New("invalid key length: insufficient data for private component")
	}
	pub = der[:1+keySize*2]
	priv = der[1+keySize*2:]
	return
}
