// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"errors"
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
	result := cryptokit.NewPublicKeyEd25519(pkey, pub)
	if result != 0 {
		return nil, errors.New("failed to create Ed25519 public key")
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
	result := cryptokit.NewPrivateKeyEd25519FromSeed(pkey, seed)
	if result != 0 {
		return nil, errors.New("failed to generate Ed25519 key from seed")
	}
	return pkey, nil
}

// SignEd25519 signs the message with priv and returns a signature.
func SignEd25519(priv PrivateKeyEd25519, message []byte) ([]byte, error) {
	sig := make([]byte, signatureSizeEd25519)
	result := cryptokit.SignEd25519(priv, message, sig)
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
	return sig, nil
}

// VerifyEd25519 reports whether sig is a valid signature of message by pub.
func VerifyEd25519(pub PublicKeyEd25519, message, sig []byte) error {
	result := cryptokit.VerifyEd25519(pub, message, sig)
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
