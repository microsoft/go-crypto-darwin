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

	curveID, err := curveToID(curve)
	if err != nil {
		return nil, err
	}

	// Validate the public key
	ret := cryptokit.ValidatePublicKeyECDH(curveID, bytes)
	if ret != 0 {
		return nil, errors.New("invalid public key")
	}

	// For all curves (including EC curves), we just store the bytes
	// X25519 uses raw 32-byte format
	// EC curves use uncompressed X9.63 format (0x04 || x || y)
	return &PublicKeyECDH{bytes: slices.Clone(bytes)}, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

// bytes expects the public key to be in uncompressed ANSI X9.63 format
func NewPrivateKeyECDH(curve string, priv []byte) (*PrivateKeyECDH, error) {
	curveID, err := curveToID(curve)
	if err != nil {
		return nil, err
	}

	// Validate the private key
	ret := cryptokit.ValidatePrivateKeyECDH(curveID, priv)
	if ret != 0 {
		return nil, errors.New("invalid private key")
	}

	// Derive the public key
	keySize := curveToKeySizeInBytes(curve)
	var pubKeySize int
	if curve == "X25519" {
		pubKeySize = 32
	} else {
		pubKeySize = 1 + keySize*2
	}

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

	curveID, err := curveToID(priv.curve)
	if err != nil {
		return nil, err
	}

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

	curveID, err := curveToID(curve)
	if err != nil {
		return nil, nil, err
	}

	var pubKeySize int
	if curve == "X25519" {
		pubKeySize = 32
	} else {
		pubKeySize = 1 + keySize*2
	}

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
