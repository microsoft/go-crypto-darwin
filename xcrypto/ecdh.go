// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"errors"
	"slices"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

type PublicKeyECDH struct {
	bytes []byte
}

type PrivateKeyECDH struct {
	pub   []byte
	priv  []byte // For X25519: the actual private key bytes
	curve string // Track the curve type
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	if len(bytes) < 1 {
		return nil, errors.New("NewPublicKeyECDH: missing key")
	}

	// For EC curves, validate the key using CryptoKit
	if curve != "X25519" {
		var curveID int32
		switch curve {
		case "P-256":
			curveID = 1
		case "P-384":
			curveID = 2
		case "P-521":
			curveID = 3
		default:
			return nil, errors.New("unsupported curve")
		}

		// Validate the public key
		ret := cryptokit.ValidatePublicKeyECDH(curveID, bytes)
		if ret != 0 {
			return nil, errors.New("invalid public key")
		}
	}

	// For all curves (including EC curves), we just store the bytes
	// X25519 uses raw 32-byte format
	// EC curves use uncompressed X9.63 format (0x04 || x || y)
	return &PublicKeyECDH{bytes: slices.Clone(bytes)}, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

// bytes expects the public key to be in uncompressed ANSI X9.63 format
func NewPrivateKeyECDH(curve string, priv []byte) (*PrivateKeyECDH, error) {
	// For X25519, we don't use SecurityFramework
	if curve == "X25519" {
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
		publicKey := buf[32:64]

		privKey := &PrivateKeyECDH{
			pub:   publicKey,
			priv:  slices.Clone(priv),
			curve: curve,
		}
		return privKey, nil
	}

	// For EC curves (P-256, P-384, P-521), validate and store the keys
	var curveID int32
	switch curve {
	case "P-256":
		curveID = 1
	case "P-384":
		curveID = 2
	case "P-521":
		curveID = 3
	default:
		return nil, errors.New("unsupported curve")
	}

	// Validate the private key
	ret := cryptokit.ValidatePrivateKeyECDH(curveID, priv)
	if ret != 0 {
		return nil, errors.New("invalid private key")
	}

	// Derive the public key
	keySize := curveToKeySizeInBytes(curve)
	pubKeySize := 1 + keySize*2
	publicKey := make([]byte, pubKeySize)
	ret = cryptokit.PublicKeyFromPrivateECDH(curveID, priv, publicKey)
	if ret != 0 {
		return nil, errors.New("failed to derive public key")
	}

	privKey := &PrivateKeyECDH{
		pub:   publicKey,
		priv:  slices.Clone(priv),
		curve: curve,
	}
	return privKey, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	// For all curves, just return the stored public key bytes
	return &PublicKeyECDH{
		bytes: slices.Clone(k.pub),
	}, nil
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	if priv == nil || pub == nil {
		return nil, errors.New("invalid keys")
	}

	// Determine curve ID for CryptoKit
	var curveID int32
	switch priv.curve {
	case "P-256":
		curveID = 1
	case "P-384":
		curveID = 2
	case "P-521":
		curveID = 3
	case "X25519":
		curveID = 0
	default:
		return nil, errors.New("unsupported curve")
	}

	// Handle X25519 using CryptoKit
	if priv.curve == "X25519" {
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

	// Handle EC curves using CryptoKit
	keySize := curveToKeySizeInBytes(priv.curve)
	sharedSecret := make([]byte, keySize)

	ret := cryptokit.EcdhSharedSecret(curveID, priv.priv, pub.bytes, sharedSecret)
	if ret != 0 {
		return nil, errors.New("ECDH: key exchange failed")
	}

	return sharedSecret, nil
}

func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	keySize := curveToKeySizeInBytes(curve)
	if keySize == 0 {
		return nil, nil, errors.New("unsupported curve")
	}

	// Determine curve ID for CryptoKit
	var curveID int32
	switch curve {
	case "P-256":
		curveID = 1
	case "P-384":
		curveID = 2
	case "P-521":
		curveID = 3
	case "X25519":
		curveID = 0
	default:
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
			pub:   privKey[32:64],
			priv:  privKey[:32],
			curve: curve,
		}, privKey[:32], nil
	}

	// For EC curves, use CryptoKit
	pubKeySize := 1 + keySize*2
	privateKey := make([]byte, keySize)
	publicKey := make([]byte, pubKeySize)

	ret := cryptokit.GenerateKeyECDH(curveID, privateKey, publicKey)
	if ret != 0 {
		return nil, nil, errors.New("EC key generation failed")
	}

	// Store the public key in X9.63 format and the private key
	k := &PrivateKeyECDH{
		pub:   slices.Clone(publicKey),
		priv:  slices.Clone(privateKey),
		curve: curve,
	}
	return k, slices.Clone(privateKey), nil
}
