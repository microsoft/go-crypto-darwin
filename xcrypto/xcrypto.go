// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #cgo CFLAGS: -Wno-deprecated-declarations
// #cgo LDFLAGS: -framework Security -framework CoreFoundation
// #include <CoreFoundation/CFString.h>
import "C"
import (
	"runtime"
	"unsafe"
)

// noescape hides a pointer from escape analysis. noescape is
// the identity function but escape analysis doesn't think the
// output depends on the input. noescape is inlined and currently
// compiles down to zero instructions.
// USE CAREFULLY!
//
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

var zero byte

// addr converts p to its base addr, including a noescape along the way.
// If p is nil, addr returns a non-nil pointer, so that the result can always
// be dereferenced.
//
//go:nosplit
func addr(p []byte) *byte {
	if len(p) == 0 {
		return &zero
	}
	return (*byte)(noescape(unsafe.Pointer(&p[0])))
}

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func sbase(b []byte) *C.char {
	if len(b) == 0 {
		return nil
	}
	return (*C.char)(unsafe.Pointer(&b[0]))
}

func pbase(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}

const kCFAllocatorDefault = 0
const kCFStringEncodingUTF8 = 0x08000100

func stringToCFString(s string) C.CFStringRef {
	p := unsafe.Pointer(unsafe.StringData(s))
	ret := C.CFStringCreateWithBytes(kCFAllocatorDefault, (*C.uint8_t)(p), C.CFIndex(len(s)), kCFStringEncodingUTF8, 0)
	runtime.KeepAlive(p)
	return C.CFStringRef(ret)
}

// Dictionary keys are defined as build-time strings with CFSTR, but the Go
// linker's internal linking mode can't handle CFSTR relocations. Create our
// own dynamic strings instead and just never release them.
//
// Note that this might be the only thing that can break over time if
// these values change, as the ABI arguably requires using the strings
// pointed to by the symbols, not values that happen to be equal to them.
//
// Values taken from:
//   - https://github.com/apple-open-source-mirror/Security/blob/70c059a4fd48e34d6a3a2578be3e86d781753b19/OSX/sec/Security/SecItemConstants.c
//   - https://github.com/apple-open-source-mirror/Security/blob/70c059a4fd48e34d6a3a2578be3e86d781753b19/OSX/sec/Security/SecKeyAdaptors.m
var (
	kSecAttrKeyClass      = stringToCFString("kcls")
	kSecAttrKeySizeInBits = stringToCFString("bsiz")
	kSecAttrKeyType       = stringToCFString("type")

	kSecAttrKeyTypeRSA              = stringToCFString("42")
	kSecAttrKeyTypeECSECPrimeRandom = stringToCFString("73")

	kSecAttrKeyClassPublic  = stringToCFString("0")
	kSecAttrKeyClassPrivate = stringToCFString("1")

	kSecKeyAlgorithmECDHKeyExchangeStandard = stringToCFString("algid:keyexchange:ECDH")

	kSecKeyAlgorithmECDSASignatureDigestX962 = stringToCFString("algid:sign:ECDSA:digest-X962")

	kSecKeyAlgorithmRSAEncryptionPKCS1 = stringToCFString("algid:encrypt:RSA:PKCS1")
	kSecKeyAlgorithmRSAEncryptionRaw   = stringToCFString("algid:encrypt:RSA:raw")

	kSecKeyAlgorithmRSAEncryptionOAEPSHA1   = stringToCFString("algid:encrypt:RSA:OAEP:SHA1")
	kSecKeyAlgorithmRSAEncryptionOAEPSHA224 = stringToCFString("algid:encrypt:RSA:OAEP:SHA224")
	kSecKeyAlgorithmRSAEncryptionOAEPSHA256 = stringToCFString("algid:encrypt:RSA:OAEP:SHA256")
	kSecKeyAlgorithmRSAEncryptionOAEPSHA384 = stringToCFString("algid:encrypt:RSA:OAEP:SHA384")
	kSecKeyAlgorithmRSAEncryptionOAEPSHA512 = stringToCFString("algid:encrypt:RSA:OAEP:SHA512")

	kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw    = stringToCFString("algid:sign:RSA:digest-PKCS1v15")
	kSecKeyAlgorithmRSASignatureDigestPKCS1v15MD5    = stringToCFString("algid:sign:RSA:digest-PKCS1v15:MD5")
	kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1   = stringToCFString("algid:sign:RSA:digest-PKCS1v15:SHA1")
	kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224 = stringToCFString("algid:sign:RSA:digest-PKCS1v15:SHA224")
	kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256 = stringToCFString("algid:sign:RSA:digest-PKCS1v15:SHA256")
	kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384 = stringToCFString("algid:sign:RSA:digest-PKCS1v15:SHA384")
	kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512 = stringToCFString("algid:sign:RSA:digest-PKCS1v15:SHA512")

	kSecKeyAlgorithmRSASignatureDigestPSSSHA1   = stringToCFString("algid:sign:RSA:digest-PSS:SHA1:SHA1:20")
	kSecKeyAlgorithmRSASignatureDigestPSSSHA224 = stringToCFString("algid:sign:RSA:digest-PSS:SHA224:SHA224:24")
	kSecKeyAlgorithmRSASignatureDigestPSSSHA256 = stringToCFString("algid:sign:RSA:digest-PSS:SHA256:SHA256:32")
	kSecKeyAlgorithmRSASignatureDigestPSSSHA384 = stringToCFString("algid:sign:RSA:digest-PSS:SHA384:SHA384:48")
	kSecKeyAlgorithmRSASignatureDigestPSSSHA512 = stringToCFString("algid:sign:RSA:digest-PSS:SHA512:SHA512:64")
)
