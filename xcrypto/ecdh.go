// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <Security/Security.h>
import "C"
import (
	"crypto/elliptic"
	"errors"
	"math/big"
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
	pubKey := &PublicKeyECDH{*pubKeyRef, slices.Clone(bytes)}
	runtime.SetFinalizer(pubKey, (*PublicKeyECDH).finalize)
	return pubKey, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

func NewPrivateKeyECDH(curve string, bytes []byte) (*PrivateKeyECDH, error) {
	encodedKey, err := encodePrivateComponent(bytes, curve)
	if err != nil {
		return nil, err
	}
	privKeyRef, err := createSecKeyWithData(encodedKey, C.kSecAttrKeyTypeECSECPrimeRandom, C.kSecAttrKeyClassPrivate)
	if err != nil {
		return nil, err
	}
	privKey := &PrivateKeyECDH{*privKeyRef}
	runtime.SetFinalizer(privKey, (*PrivateKeyECDH).finalize)
	return privKey, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
	pubKeyRef := C.SecKeyCopyPublicKey(k._pkey)
	if pubKeyRef == 0 {
		return nil, errors.New("failed to extract public key")
	}
	pubBytes, err := getEncodedECDHPublicKey(pubKeyRef)
	if err != nil {
		C.CFRelease(C.CFTypeRef(pubKeyRef))
		return nil, err
	}
	pubKey := &PublicKeyECDH{pubKeyRef, pubBytes}
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
	if goCFErrorRef(cfErr) != nil {
		return nil, goCFErrorRef(cfErr)
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
	bytes, err := extractPrivateComponent(privKeyDER, keySize)
	if err != nil {
		return nil, nil, err
	}
	k := &PrivateKeyECDH{privKeyRef}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, bytes, nil
}

func getEncodedECDHPublicKey(key C.SecKeyRef) ([]byte, error) {
	pubDataRef := C.SecKeyCopyExternalRepresentation(key, nil)
	if pubDataRef == 0 {
		return nil, errors.New("xcrypto: failed to encode public key")
	}
	defer C.CFRelease(C.CFTypeRef(pubDataRef))
	pubBytes := cfDataToBytes(pubDataRef)
	return pubBytes, nil
}

func extractPrivateComponent(der []byte, keySize int) ([]byte, error) {
	// The private component is the last of the three equally-sized chunks
	// for the elliptic curve private key.
	if len(der) < keySize*3 {
		return nil, errors.New("invalid key length: insufficient data for private component")
	}
	// Extract the private component
	privateComponent := der[keySize*2 : keySize*3]
	return privateComponent, nil
}

func encodePrivateComponent(privateComponent []byte, curve string) ([]byte, error) {
	keySize := curveToKeySizeInBytes(curve)
	if len(privateComponent) != keySize {
		return nil, errors.New("invalid key length: private component size does not match expected key size for the given curve")
	}
	// generate public key from privateComponent
	var p elliptic.Curve
	switch curve {
	case "P-256":
		p = elliptic.P256()
	case "P-384":
		p = elliptic.P384()
	case "P-521":
		p = elliptic.P521()
	default:
		return nil, errors.New("unsupported curve")
	}

	// curve.ScalarBaseMult is deprecated unless using the built-in curves namely P-256, P-384, P-521.
	x, y := p.ScalarBaseMult(privateComponent)
	encodedKey, err := encodeToUncompressedAnsiX963Key(x, y, new(big.Int).SetBytes(privateComponent), keySize)
	if err != nil {
		return nil, errors.New("failed to encode public key to uncompressed ANSI X9.63 format")
	}
	return encodedKey, nil
}
