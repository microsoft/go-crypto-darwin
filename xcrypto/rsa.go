// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"bytes"
	"crypto"
	"errors"
	"hash"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/security"
)

// GenerateKeyRSA generates an RSA key pair on macOS.
// asn1Data is encoded as PKCS#1 ASN1 DER.
func GenerateKeyRSA(bits int) (asn1Data []byte, err error) {
	privKeyDER, privKeyRef, err := createSecKeyRandom(security.KSecAttrKeyTypeRSA, bits)
	if err != nil {
		return nil, err
	}
	security.CFRelease(security.CFTypeRef(privKeyRef))
	return privKeyDER, nil
}

type PublicKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey security.SecKeyRef
}

func (k *PublicKeyRSA) finalize() {
	if k._pkey != nil {
		security.CFRelease(security.CFTypeRef(k._pkey))
	}
}

// NewPublicKeyRSA creates a new RSA public key from ASN1 DER encoded data.
func NewPublicKeyRSA(asn1Data []byte) (*PublicKeyRSA, error) {
	pubKeyRef, err := createSecKeyWithData(asn1Data, security.KSecAttrKeyTypeRSA, security.KSecAttrKeyClassPublic)
	if err != nil {
		return nil, err
	}

	key := &PublicKeyRSA{_pkey: pubKeyRef}
	runtime.SetFinalizer(key, (*PublicKeyRSA).finalize)
	return key, nil
}

func (k *PublicKeyRSA) withKey(f func(security.SecKeyRef) error) error {
	// Because of the finalizer, any time key is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

type PrivateKeyRSA struct {
	// _pkey MUST NOT be accessed directly. Instead, use the withKey method.
	_pkey security.SecKeyRef
}

func (k *PrivateKeyRSA) finalize() {
	if k._pkey != nil {
		security.CFRelease(security.CFTypeRef(k._pkey))
	}
}

// NewPrivateKeyRSA creates a new RSA private key from ASN1 DER encoded data.
func NewPrivateKeyRSA(asn1Data []byte) (*PrivateKeyRSA, error) {
	privKeyRef, err := createSecKeyWithData(asn1Data, security.KSecAttrKeyTypeRSA, security.KSecAttrKeyClassPrivate)
	if err != nil {
		return nil, err
	}

	key := &PrivateKeyRSA{_pkey: privKeyRef}
	runtime.SetFinalizer(key, (*PrivateKeyRSA).finalize)
	return key, nil
}

func (k *PrivateKeyRSA) PublicKey() *PublicKeyRSA {
	var pubKeyRef security.SecKeyRef
	k.withKey(func(key security.SecKeyRef) error {
		pubKeyRef = security.SecKeyCopyPublicKey(k._pkey)
		return nil
	})
	pubKey := &PublicKeyRSA{_pkey: pubKeyRef}
	runtime.SetFinalizer(pubKey, (*PublicKeyRSA).finalize)
	return pubKey
}

func (k *PrivateKeyRSA) withKey(f func(security.SecKeyRef) error) error {
	// Because of the finalizer, any time _pkey is passed to cgo, that call must
	// be followed by a call to runtime.KeepAlive, to make sure k is not
	// collected (and finalized) before the cgo call returns.
	defer runtime.KeepAlive(k)
	return f(k._pkey)
}

// DecryptRSAOAEP decrypts data using RSA-OAEP.
func DecryptRSAOAEP(h hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	plaintext, err := evpDecrypt(priv.withKey, algorithmTypeOAEP, ciphertext, h)
	if err != nil {
		return nil, err
	}
	// If a label was provided, validate it
	if len(label) > 0 {
		h.Write(label)
		labelHash := h.Sum(nil)
		h.Reset()
		if len(plaintext) < len(labelHash) {
			return nil, errors.New("invalid ciphertext: missing label hash")
		}
		// Extract and verify the label hash
		if !bytes.Equal(plaintext[:len(labelHash)], labelHash) {
			return nil, errors.New("invalid label hash")
		}
		plaintext = plaintext[len(labelHash):]
	}
	return plaintext, nil
}

// EncryptRSAOAEP encrypts data using RSA-OAEP.
func EncryptRSAOAEP(h hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	// Combine label with plaintext for encryption
	if len(label) > 0 {
		h.Write(label)
		labelHash := h.Sum(nil)
		msg = append(labelHash, msg...) // Prepend label hash to the message
		h.Reset()
	}
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
	if pub.withKey(func(key security.SecKeyRef) error {
		size := security.SecKeyGetBlockSize(key)
		if len(sig) < int(size) {
			return errors.New("crypto/rsa: signature too short")
		}
		return nil
	}) != nil {
		return errors.New("crypto/rsa: verification error")
	}
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

func (e *cfError) Error() string {
	if e.message == "" {
		return "CFError(" + strconv.Itoa(e.code) + "): unknown error"
	}
	return "CFError(" + strconv.Itoa(e.code) + "): " + e.message
}

func goCFErrorRef(ref security.CFErrorRef) error {
	if ref == nil {
		return nil
	}
	var message string
	if desc := security.CFErrorCopyDescription(ref); desc != nil {
		defer security.CFRelease(security.CFTypeRef(desc))
		if cstr := security.CFStringGetCStringPtr(desc, security.KCFStringEncodingUTF8); cstr != nil {
			message = string(cstrBytes(cstr))
		}
	}
	return &cfError{
		code:    int(security.CFErrorGetCode(ref)),
		message: message,
	}
}

// cstrBytes returns a byte slice containing the contents of the C string
// pointed to by p. The slice does not include the terminating null byte.
func cstrBytes(p *byte) []byte {
	if p == nil {
		return nil
	}
	end := unsafe.Pointer(p)
	for *(*byte)(end) != 0 {
		end = unsafe.Add(end, 1)
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), uintptr(end)-uintptr(unsafe.Pointer(p)))
}
