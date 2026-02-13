// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"errors"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

type PrivateKeyECDSA struct {
	x     BigInt // public key x coordinate
	y     BigInt // public key y coordinate
	d     BigInt // private key
	curve string // curve name
}

type PublicKeyECDSA struct {
	x     BigInt // public key x coordinate
	y     BigInt // public key y coordinate
	curve string // curve name
}

func NewPublicKeyECDSA(curve string, x, y BigInt) (*PublicKeyECDSA, error) {
	keySize := curveToKeySizeInBytes(curve)
	if keySize == 0 {
		return nil, errors.New("unsupported curve")
	}
	// Validate that x and y are of appropriate length
	if len(x) > keySize || len(y) > keySize {
		return nil, errors.New("public key coordinates are too large")
	}
	pubKey := &PublicKeyECDSA{
		x:     x,
		y:     y,
		curve: curve,
	}
	return pubKey, nil
}

// NewPrivateKeyECDSA creates a new ECDSA private key using the provided curve name and parameters (x, y, d).
func NewPrivateKeyECDSA(curve string, x, y, d BigInt) (*PrivateKeyECDSA, error) {
	keySize := curveToKeySizeInBytes(curve)
	if keySize == 0 {
		return nil, errors.New("unsupported curve")
	}
	// Validate that x, y, and d are of appropriate length
	if len(x) > keySize || len(y) > keySize || len(d) > keySize {
		return nil, errors.New("key parameters are too large")
	}
	privKey := &PrivateKeyECDSA{
		x:     x,
		y:     y,
		d:     d,
		curve: curve,
	}
	return privKey, nil
}

func GenerateKeyECDSA(curve string) (x, y, d BigInt, err error) {
	keySize := curveToKeySizeInBytes(curve)
	if keySize == 0 {
		return nil, nil, nil, errors.New("unsupported curve")
	}

	curveID, err := curveToID(curve)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate key using CryptoKit
	xBytes := make([]byte, keySize)
	yBytes := make([]byte, keySize)
	dBytes := make([]byte, keySize)

	ret := cryptokit.GenerateKeyECDSA(curveID, xBytes, yBytes, dBytes)
	if ret != 0 {
		return nil, nil, nil, errors.New("ECDSA key generation failed")
	}

	return normalizeBigInt(xBytes), normalizeBigInt(yBytes), normalizeBigInt(dBytes), nil
}

func SignMarshalECDSA(priv *PrivateKeyECDSA, hashed []byte) ([]byte, error) {
	if priv == nil || len(hashed) == 0 {
		return nil, errors.New("invalid parameters")
	}

	curveID, err := curveToID(priv.curve)
	if err != nil {
		return nil, err
	}

	keySize := curveToKeySizeInBytes(priv.curve)

	// Normalize private key to proper size
	dBytes := make([]byte, keySize)
	copy(dBytes[len(dBytes)-len(priv.d):], priv.d)

	// Allocate signature buffer (max size for DER-encoded signature)
	maxSigLen := 256
	signature := make([]byte, maxSigLen)
	sigLen := int64(0)

	ret := cryptokit.EcdsaSign(curveID, dBytes, hashed, signature, &sigLen)
	if ret != 0 {
		return nil, errors.New("ECDSA signing failed")
	}

	if sigLen <= 0 || sigLen > int64(len(signature)) {
		return nil, errors.New("invalid signature length")
	}

	return signature[:sigLen], nil
}

func VerifyECDSA(pub *PublicKeyECDSA, hashed []byte, sig []byte) bool {
	if pub == nil || len(hashed) == 0 || len(sig) == 0 {
		return false
	}

	curveID, err := curveToID(pub.curve)
	if err != nil {
		return false
	}

	keySize := curveToKeySizeInBytes(pub.curve)

	// Normalize public key coordinates to proper size
	xBytes := make([]byte, keySize)
	yBytes := make([]byte, keySize)

	// Safety check: ensure BigInts are not longer than keySize
	if len(pub.x) > keySize || len(pub.y) > keySize {
		return false
	}

	copy(xBytes[len(xBytes)-len(pub.x):], pub.x)
	copy(yBytes[len(yBytes)-len(pub.y):], pub.y)

	ret := cryptokit.EcdsaVerify(curveID, xBytes, yBytes, hashed, sig)
	return ret == 1
}

func normalizeBigInt(b []byte) BigInt {
	// Remove leading zero bytes
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}
