// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <Security/Security.h>
import "C"
import (
	"errors"
	"runtime"
	"slices"
)

type PublicKeyECDH struct {
	_pkey C.SecKeyRef
	bytes []byte
}

func (k *PublicKeyECDH) finalize() {
	if k._pkey != 0 {
		C.CFRelease(C.CFTypeRef(k._pkey))
	}
}

type PrivateKeyECDH struct {
	_pkey C.SecKeyRef
	pub   []byte
}

func (k *PrivateKeyECDH) finalize() {
	if k._pkey != 0 {
		C.CFRelease(C.CFTypeRef(k._pkey))
	}
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	if len(bytes) < 1 {
		return nil, errors.New("NewPublicKeyECDH: missing key")
	}
	pubKeyRef, err := createSecKeyWithData(bytes, C.kSecAttrKeyTypeECSECPrimeRandom, C.kSecAttrKeyClassPublic)
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
	privKeyRef, err := createSecKeyWithData(key, C.kSecAttrKeyTypeECSECPrimeRandom, C.kSecAttrKeyClassPrivate)
	if err != nil {
		return nil, err
	}
	privKey := &PrivateKeyECDH{privKeyRef, pub}
	runtime.SetFinalizer(privKey, (*PrivateKeyECDH).finalize)
	return privKey, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
	pubKeyRef := C.SecKeyCopyPublicKey(k._pkey)
	if pubKeyRef == 0 {
		return nil, errors.New("failed to extract public key")
	}
	pubKey := &PublicKeyECDH{pubKeyRef, k.pub}
	runtime.SetFinalizer(pubKey, (*PublicKeyECDH).finalize)
	return pubKey, nil
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	defer runtime.KeepAlive(pub)

	var algorithm C.CFStringRef = C.kSecKeyAlgorithmECDHKeyExchangeStandard

	supported := C.SecKeyIsAlgorithmSupported(priv._pkey, C.kSecKeyOperationTypeKeyExchange, algorithm)
	if supported == 0 {
		return nil, errors.New("ECDH algorithm not supported for the given private key")
	}

	var cfErr C.CFErrorRef
	// Perform the key exchange
	sharedSecretRef := C.SecKeyCopyKeyExchangeResult(
		priv._pkey,
		algorithm,
		pub._pkey,
		C.CFDictionaryRef(0),
		&cfErr,
	)
	if err := goCFErrorRef(cfErr); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(sharedSecretRef))

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
	privKeyDER, privKeyRef, err := createSecKeyRandom(C.kSecAttrKeyTypeECSECPrimeRandom, keySizeInBits)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := extractECDHComponents(privKeyDER, keySize)
	if err != nil {
		C.CFRelease(C.CFTypeRef(privKeyRef))
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
