// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <Security/Security.h>
import "C"
import (
	"errors"
	"math/big"
	"runtime"
)

type PrivateKeyECDSA struct {
	_pkey C.SecKeyRef
}

func (k *PrivateKeyECDSA) finalize() {
	if k._pkey != 0 {
		C.CFRelease(C.CFTypeRef(k._pkey))
	}
}

func (k *PrivateKeyECDSA) withKey(f func(C.SecKeyRef) C.int) C.int {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PublicKeyECDSA struct {
	_pkey C.SecKeyRef
}

func (k *PublicKeyECDSA) finalize() {
	if k._pkey != 0 {
		C.CFRelease(C.CFTypeRef(k._pkey))
	}
}

func (k *PublicKeyECDSA) withKey(f func(C.SecKeyRef) C.int) C.int {
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

func NewPublicKeyECDSA(curve string, x, y BigInt) (*PublicKeyECDSA, error) {
	keySize := curveToKeySizeInBytes(curve)
	if keySize == 0 {
		return nil, errors.New("unsupported curve")
	}
	encodedKey, err := encodeToUncompressedAnsiX963Key(x, y, nil, keySize)
	if err != nil {
		return nil, errors.New("failed to encode public key to uncompressed ANSI X9.63 format")
	}

	pubKeyRef, err := createSecKeyWithData(encodedKey, C.kSecAttrKeyTypeECSECPrimeRandom, C.kSecAttrKeyClassPublic)
	if err != nil {
		return nil, err
	}

	pubKey := &PublicKeyECDSA{_pkey: pubKeyRef}
	runtime.SetFinalizer(pubKey, (*PublicKeyECDSA).finalize)
	return pubKey, nil
}

// NewPrivateKeyECDSA creates a new ECDSA private key using the provided curve name and parameters (x, y, d).
func NewPrivateKeyECDSA(curve string, x, y, d BigInt) (*PrivateKeyECDSA, error) {
	keySize := curveToKeySizeInBytes(curve)
	if keySize == 0 {
		return nil, errors.New("unsupported curve")
	}
	encodedKey, err := encodeToUncompressedAnsiX963Key(x, y, d, keySize)
	if err != nil {
		return nil, errors.New("crypto/ecdsa: failed to encode private key: " + err.Error())
	}

	privKeyRef, err := createSecKeyWithData(encodedKey, C.kSecAttrKeyTypeECSECPrimeRandom, C.kSecAttrKeyClassPrivate)
	if err != nil {
		return nil, err
	}

	// Wrap and finalize
	k := &PrivateKeyECDSA{_pkey: privKeyRef}
	runtime.SetFinalizer(k, (*PrivateKeyECDSA).finalize)
	return k, nil
}

func GenerateKeyECDSA(curve string) (x, y, d BigInt, err error) {
	keySize := curveToKeySizeInBytes(curve)
	if keySize == 0 {
		return nil, nil, nil, errors.New("unsupported curve")
	}

	keySizeInBits := curveToKeySizeInBits(curve)
	privKeyDER, privKeyRef, err := createSecKeyRandom(C.kSecAttrKeyTypeECSECPrimeRandom, keySizeInBits)
	if err != nil {
		return nil, nil, nil, err
	}
	defer C.CFRelease(C.CFTypeRef(privKeyRef))
	return decodeFromUncompressedAnsiX963Key(privKeyDER, keySize)
}

func SignMarshalECDSA(priv *PrivateKeyECDSA, hashed []byte) ([]byte, error) {
	return evpSign(priv.withKey, algorithmTypeECDSA, 0, hashed)
}

func VerifyECDSA(pub *PublicKeyECDSA, hashed []byte, sig []byte) bool {
	return evpVerify(pub.withKey, algorithmTypeECDSA, 0, hashed, sig) == nil
}

// encodeToUncompressedAnsiX963Key encodes the given elliptic curve point (x, y) and optional private key (d)
// into an uncompressed ANSI X9.63 format byte slice.
func encodeToUncompressedAnsiX963Key(x, y, d BigInt, keySize int) ([]byte, error) {
	// Build the uncompressed key point (0x04 || x || y { || d })
	size := 1 + keySize*2
	if d != nil {
		size += keySize
	}
	out := make([]byte, size)
	out[0] = 0x04
	err := encodeBigInt(out[1:], []sizedBigInt{
		{x, keySize}, {y, keySize},
		{d, keySize},
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decodeFromUncompressedAnsiX963Key decodes the given uncompressed ANSI X9.63 format byte slice into
// the elliptic curve point (x, y) and optional private key (d).
func decodeFromUncompressedAnsiX963Key(key []byte, keySize int) (x, y, d BigInt, err error) {
	if len(key) < 1 || key[0] != 0x04 {
		return nil, nil, nil, errors.New("invalid uncompressed key format")
	}
	if len(key) < 1+keySize*2 {
		return nil, nil, nil, errors.New("invalid key length")
	}
	x = new(big.Int).SetBytes(key[1 : 1+keySize])
	y = new(big.Int).SetBytes(key[1+keySize : 1+keySize*2])
	if len(key) > 1+keySize*2 {
		d := new(big.Int).SetBytes(key[1+keySize*2:])
		return x, y, d, nil
	}
	return x, y, nil, nil
}

// sizedBigInt defines a big integer with
// a size that can be different from the
// one provided by len(b).
type sizedBigInt struct {
	b    BigInt
	size int
}

// encodeBigInt encodes ints into data.
// It stops iterating over ints when it finds one nil element.
func encodeBigInt(data []byte, ints []sizedBigInt) error {
	for _, v := range ints {
		if v.b == nil {
			return nil
		}
		// b might be shorter than size if the original big number contained leading zeros.
		leadingZeros := int(v.size) - (v.b.BitLen()+7)/8
		if leadingZeros < 0 {
			return errors.New("commoncrypto: invalid parameters")
		}
		copy(data[leadingZeros:], v.b.Bytes())
		data = data[v.size:]
	}
	return nil
}
