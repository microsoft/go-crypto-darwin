// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"runtime"
	"strconv"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

const (
	// publicKeySizeEd25519 is the size, in bytes, of public keys as used in crypto/ed25519.
	publicKeySizeEd25519 = 32
	// privateKeySizeEd25519 is the size, in bytes, of private keys as used in crypto/ed25519.
	privateKeySizeEd25519 = 64
	// seedSizeEd25519 is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	seedSizeEd25519 = 32
)

// PublicKeyEd25519 represents an Ed25519 public key.
type PublicKeyEd25519 struct {
	_pkey unsafe.Pointer
}

func (k *PublicKeyEd25519) finalize() {
	cryptokit.FreeKeyEd25519(k._pkey)
}

// PrivateKeyEd25519 represents an Ed25519 private key.
type PrivateKeyEd25519 struct {
	_pkey unsafe.Pointer
}

func (k *PrivateKeyEd25519) finalize() {
	cryptokit.FreeKeyEd25519(k._pkey)
}

func (k *PrivateKeyEd25519) Bytes() ([]byte, error) {
	defer runtime.KeepAlive(k)
	return cryptokit.GetPrivateKeyEd25519Bytes(k._pkey)
}

func (k *PrivateKeyEd25519) Public() (*PublicKeyEd25519, error) {
	defer runtime.KeepAlive(k)
	pub, err := cryptokit.ExtractPublicKeyEd25519(k._pkey)
	if err != nil {
		return nil, err
	}
	return NewPublicKeyEd25519(pub)
}

// GenerateKeyEd25519 generates a new Ed25519 private key.
func GenerateKeyEd25519() (*PrivateKeyEd25519, error) {
	pkeyPriv, err := cryptokit.GenerateKeyEd25519()
	if err != nil {
		return nil, err
	}
	privKey := &PrivateKeyEd25519{_pkey: pkeyPriv}
	runtime.SetFinalizer(privKey, (*PrivateKeyEd25519).finalize)
	return privKey, nil
}

func NewPrivateKeyEd25119(priv []byte) (*PrivateKeyEd25519, error) {
	if len(priv) != privateKeySizeEd25519 {
		panic("ed25519: bad private key length: " + strconv.Itoa(len(priv)))
	}
	return NewPrivateKeyEd25519FromSeed(priv[:seedSizeEd25519])
}

func NewPublicKeyEd25519(pub []byte) (*PublicKeyEd25519, error) {
	if len(pub) != publicKeySizeEd25519 {
		panic("ed25519: bad public key length: " + strconv.Itoa(len(pub)))
	}
	pkey, err := cryptokit.NewPublicKeyEd25519(pub)
	if err != nil {
		return nil, err
	}
	pubk := &PublicKeyEd25519{_pkey: pkey}
	runtime.SetFinalizer(pubk, (*PublicKeyEd25519).finalize)

	return pubk, nil
}

// NewPrivateKeyEd25519FromSeed calculates a private key from a seed. It will panic if
// len(seed) is not [SeedSize]. RFC 8032's private keys correspond to seeds in this
// package.
// NewPrivateKeyEd25519FromSeed creates an Ed25519 private key from a seed.
func NewPrivateKeyEd25519FromSeed(seed []byte) (*PrivateKeyEd25519, error) {
	if len(seed) != seedSizeEd25519 {
		panic("ed25519: bad seed length: " + strconv.Itoa(len(seed)))
	}
	// Call the internal function
	pkey, err := cryptokit.NewPrivateKeyEd25519FromSeed(seed)
	if err != nil {
		return nil, err
	}
	priv := &PrivateKeyEd25519{_pkey: pkey}
	runtime.SetFinalizer(priv, (*PrivateKeyEd25519).finalize)

	return priv, nil
}

// SignEd25519 signs the message with priv and returns a signature.
func SignEd25519(priv *PrivateKeyEd25519, message []byte) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	return cryptokit.SignEd25519(priv._pkey, message)
}

// VerifyEd25519 reports whether sig is a valid signature of message by pub.
func VerifyEd25519(pub *PublicKeyEd25519, message, sig []byte) error {
	defer runtime.KeepAlive(pub)
	return cryptokit.VerifyEd25519(pub._pkey, message, sig)
}
