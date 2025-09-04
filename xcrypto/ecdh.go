// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"errors"
	"runtime"
	"slices"
	"unsafe"

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
	key := append(slices.Clone(pub), priv...)
	privKeyRef, err := createSecKeyWithData(key, security.KSecAttrKeyTypeECSECPrimeRandom, security.KSecAttrKeyClassPrivate)
	if err != nil {
		return nil, err
	}
	privKey := &PrivateKeyECDH{privKeyRef, pub}
	runtime.SetFinalizer(privKey, (*PrivateKeyECDH).finalize)
	return privKey, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
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
	k := &PrivateKeyECDH{privKeyRef, pub}
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
