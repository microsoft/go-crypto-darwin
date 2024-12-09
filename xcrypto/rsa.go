// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <Security/Security.h>
import "C"
import (
	"crypto"
	"encoding/asn1"
	"errors"
	"hash"
	"runtime"
	"strconv"
)

// GenerateKeyRSA generates an RSA key pair on macOS.
func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}

	privKeyDER, privKeyRef, err := createSecKeyRandom(C.kSecAttrKeyTypeRSA, bits)
	if err != nil {
		return bad(err)
	}
	defer C.CFRelease(C.CFTypeRef(privKeyRef))

	var parsedKey pkcs1PrivateKey
	_, err = asn1.Unmarshal(privKeyDER, &parsedKey)
	if err != nil {
		return bad(err)
	}

	// Assign values
	N = parsedKey.Modulus
	E = parsedKey.PublicExponent
	D = parsedKey.PrivateExponent
	P = parsedKey.Prime1
	Q = parsedKey.Prime2
	Dp = parsedKey.Exponent1
	Dq = parsedKey.Exponent2
	Qinv = parsedKey.Coefficient

	return
}

type PublicKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey C.SecKeyRef
}

func (k *PublicKeyRSA) finalize() {
	if k._pkey != 0 {
		C.CFRelease(C.CFTypeRef(k._pkey))
	}
}

func NewPublicKeyRSA(N, E BigInt) (*PublicKeyRSA, error) {
	// Construct ASN.1 DER encoding for the public key
	type RSAPublicKey struct {
		Modulus  BigInt
		Exponent BigInt
	}
	asn1Data, err := asn1.Marshal(RSAPublicKey{
		Modulus:  N,
		Exponent: E,
	})
	if err != nil {
		return nil, errors.New("crypto/rsa: failed to encode public key: " + err.Error())
	}

	pubKeyRef, err := createSecKeyWithData(asn1Data, C.kSecAttrKeyTypeRSA, C.kSecAttrKeyClassPublic)
	if err != nil {
		return nil, err
	}

	// Create and return the PublicKeyRSA object
	key := &PublicKeyRSA{_pkey: *pubKeyRef}
	runtime.SetFinalizer(key, (*PublicKeyRSA).finalize)
	return key, nil
}

func (k *PublicKeyRSA) withKey(f func(C.SecKeyRef) C.int) C.int {
	// Because of the finalizer, any time key is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PrivateKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey C.SecKeyRef
}

// Construct ASN.1 DER encoding for the private key
type pkcs1PrivateKey struct {
	Version         int
	Modulus         BigInt
	PublicExponent  BigInt
	PrivateExponent BigInt
	Prime1          BigInt
	Prime2          BigInt
	Exponent1       BigInt
	Exponent2       BigInt
	Coefficient     BigInt
}

func (k *PrivateKeyRSA) finalize() {
	if k._pkey != 0 {
		C.CFRelease(C.CFTypeRef(k._pkey))
	}
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKeyRSA, error) {
	// Marshal ASN.1 data for the RSA private key
	asn1Data, err := asn1.Marshal(pkcs1PrivateKey{
		Version:         0, // PKCS#1 specifies version 0 for RSA private keys
		Modulus:         N,
		PublicExponent:  E,
		PrivateExponent: D,
		Prime1:          P,
		Prime2:          Q,
		Exponent1:       Dp,
		Exponent2:       Dq,
		Coefficient:     Qinv,
	})
	if err != nil {
		return nil, errors.New("crypto/rsa: failed to encode private key: " + err.Error())
	}

	privKeyRef, err := createSecKeyWithData(asn1Data, C.kSecAttrKeyTypeRSA, C.kSecAttrKeyClassPrivate)
	if err != nil {
		return nil, err
	}

	// Create and return the PrivateKeyRSA object
	key := &PrivateKeyRSA{_pkey: *privKeyRef}
	runtime.SetFinalizer(key, (*PrivateKeyRSA).finalize)
	return key, nil
}

func (k *PrivateKeyRSA) PublicKey() *PublicKeyRSA {
	var pubKeyRef C.SecKeyRef
	k.withKey(func(key C.SecKeyRef) C.int {
		pubKeyRef = C.SecKeyCopyPublicKey(k._pkey)
		return 0
	})
	pubKey := &PublicKeyRSA{_pkey: pubKeyRef}
	runtime.SetFinalizer(pubKey, (*PublicKeyRSA).finalize)
	return pubKey
}

func (k *PrivateKeyRSA) withKey(f func(C.SecKeyRef) C.int) C.int {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

// DecryptRSAOAEP decrypts data using RSA-OAEP.
func DecryptRSAOAEP(h hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, algorithmTypeOAEP, ciphertext, h)
}

// EncryptRSAOAEP encrypts data using RSA-OAEP.
func EncryptRSAOAEP(h hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, algorithmTypeOAEP, msg, h)
}

// SignRSAPSS signs data with RSA-PSS.
func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	return evpSign(priv.withKey, algorithmTypePSS, h, hashed)
}

// VerifyRSAPSS verifies data with RSA-PSS.
func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	return evpVerify(pub.withKey, algorithmTypePSS, h, hashed, sig)
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	return evpSign(priv.withKey, algorithmTypePKCS1v15Sig, h, hashed)
}

func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	return evpVerify(pub.withKey, algorithmTypePKCS1v15Sig, h, hashed, sig)
}

// DecryptRSAPKCS1 decrypts data using RSA PKCS#1 v1.5 padding.
func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, algorithmTypePKCS1v15Enc, ciphertext, nil)
}

// EncryptRSAPKCS1 encrypts data using RSA PKCS#1 v1.5 padding.
func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, algorithmTypePKCS1v15Enc, msg, nil)
}

func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	return evpDecrypt(priv.withKey, algorithmTypeRAW, ciphertext, nil)
}

func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	return evpEncrypt(pub.withKey, algorithmTypeRAW, msg, nil)
}

// Helper functions

type cfError struct {
	code    int
	message string
}

func (e cfError) Error() string {
	if e.message == "" {
		return "CFError(" + strconv.Itoa(e.code) + "): unknown error"
	}
	return "CFError(" + strconv.Itoa(e.code) + "): " + e.message
}

func goCFErrorRef(ref C.CFErrorRef) error {
	if ref == 0 {
		return nil
	}
	var message string
	if desc := C.CFErrorCopyDescription(ref); desc != C.CFStringRef(0) {
		defer C.CFRelease(C.CFTypeRef(desc))
		if cstr := C.CFStringGetCStringPtr(desc, C.kCFStringEncodingUTF8); cstr != nil {
			message = C.GoString(cstr)
		}
	}
	return &cfError{
		code:    int(C.CFErrorGetCode(ref)),
		message: message,
	}
}
