// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin && cgo

package xcrypto

import (
	"strconv"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

const (
	// publicKeySizeEd25519 is the size, in bytes, of public keys as used in crypto/ed25519.
	publicKeySizeEd25519 = 32
	// privateKeySizeEd25519 is the size, in bytes, of private keys as used in crypto/ed25519.
	privateKeySizeEd25519 = 64
	// signatureSizeEd25519 is the size, in bytes, of signatures generated and verified by crypto/ed25519.
	signatureSizeEd25519 = 64
	// seedSizeEd25519 is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	seedSizeEd25519 = 32
)

// PublicKeyEd25519 represents an Ed25519 public key.
type PublicKeyEd25519 []byte

// PrivateKeyEd25519 represents an Ed25519 private key.
type PrivateKeyEd25519 []byte

func (k PrivateKeyEd25519) Public() PublicKeyEd25519 {
	publicKey := make([]byte, publicKeySizeEd25519)
	copy(publicKey, k[seedSizeEd25519:])
	return PublicKeyEd25519(publicKey)
}

// GenerateKeyEd25519 generates a new Ed25519 private key.
func GenerateKeyEd25519() PrivateKeyEd25519 {
	pkeyPriv := make([]byte, privateKeySizeEd25519)
	cryptokit.GenerateKeyEd25519(pkeyPriv)
	return pkeyPriv
}

func NewPrivateKeyEd25519(priv []byte) (PrivateKeyEd25519, error) {
	if len(priv) != privateKeySizeEd25519 {
		panic("ed25519: bad private key length: " + strconv.Itoa(len(priv)))
	}
	return NewPrivateKeyEd25519FromSeed(priv[:seedSizeEd25519])
}

func (k PrivateKeyEd25519) Bytes() ([]byte, error) {
	return k, nil
}

func NewPublicKeyEd25519(pub []byte) (PublicKeyEd25519, error) {
	if len(pub) != publicKeySizeEd25519 {
		panic("ed25519: bad public key length: " + strconv.Itoa(len(pub)))
	}
	pkey := make([]byte, publicKeySizeEd25519)
	err := cryptokit.NewPublicKeyEd25519(pkey, pub)
	if err != nil {
		return nil, err
	}
	return pkey, nil
}

func (k PublicKeyEd25519) Bytes() ([]byte, error) {
	return k, nil
}

// NewPrivateKeyEd25519FromSeed calculates a private key from a seed. It will panic if
// len(seed) is not [SeedSize]. RFC 8032's private keys correspond to seeds in this
// package.
// NewPrivateKeyEd25519FromSeed creates an Ed25519 private key from a seed.
func NewPrivateKeyEd25519FromSeed(seed []byte) (PrivateKeyEd25519, error) {
	if len(seed) != seedSizeEd25519 {
		panic("ed25519: bad seed length: " + strconv.Itoa(len(seed)))
	}
	pkey := make([]byte, privateKeySizeEd25519)
	err := cryptokit.NewPrivateKeyEd25519FromSeed(pkey, seed)
	if err != nil {
		return nil, err
	}
	return pkey, nil
}

// SignEd25519 signs the message with priv and returns a signature.
func SignEd25519(priv PrivateKeyEd25519, message []byte) ([]byte, error) {
	sig := make([]byte, signatureSizeEd25519)
	err := cryptokit.SignEd25519(sig, priv, message)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// VerifyEd25519 reports whether sig is a valid signature of message by pub.
func VerifyEd25519(pub PublicKeyEd25519, message, sig []byte) error {
	return cryptokit.VerifyEd25519(pub, message, sig)
}
