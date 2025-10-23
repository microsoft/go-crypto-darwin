// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/commoncrypto"
)

type cbcCipher struct {
	blockSize int
	cryptor   commoncrypto.CCCryptorRef
}

func newCBC(operation commoncrypto.CCOperation, kind commoncrypto.CCAlgorithm, key, iv []byte) *cbcCipher {
	var blockSize int
	switch kind {
	case commoncrypto.KCCAlgorithmAES:
		blockSize = aesBlockSize
	case commoncrypto.KCCAlgorithmDES, commoncrypto.KCCAlgorithm3DES:
		blockSize = desBlockSize
	default:
		panic("invalid algorithm")
	}

	// Create and initialize the cbcMode struct with CCCryptorCreateWithMode here
	x := &cbcCipher{blockSize: blockSize}
	status := commoncrypto.CCCryptorCreateWithMode(
		operation,                      // Specifies whether encryption or decryption is performed (kCCEncrypt or kCCDecrypt).
		commoncrypto.KCCModeCBC,        // Mode of operation, here explicitly set to CBC (Cipher Block Chaining).
		commoncrypto.CCAlgorithm(kind), // The encryption algorithm (e.g., kCCAlgorithmAES128, kCCAlgorithmDES).
		commoncrypto.CcNoPadding,       // Padding option, set to no padding; padding can be handled at a higher level if necessary.
		iv,                             // Initialization Vector (IV) for the cipher, required for CBC mode. Should be nil for ECB mode.
		key,                            // PEncryption key.
		nil,                            // Tweak key, used only for XTS mode; here set to nil as it’s not required for CBC.
		0,                              // Number of rounds, mainly for RC2 and Blowfish; not used here, so set to 0.
		0,                              // Mode options for CTR and F8 modes; not used for CBC, so set to 0.
		&x.cryptor,                     // Pointer to the CCCryptorRef output, which will hold the state for encryption or decryption.
	)

	if status != commoncrypto.KCCSuccess {
		panic("crypto/des: CCCryptorCreateWithMode failed")
	}

	runtime.SetFinalizer(x, (*cbcCipher).finalize)
	return x

}

func (x *cbcCipher) finalize() {
	if x.cryptor != nil {
		commoncrypto.CCCryptorRelease(x.cryptor)
		x.cryptor = nil
	}
}

func (x *cbcCipher) BlockSize() int { return x.blockSize }

func (x *cbcCipher) CryptBlocks(dst, src []byte) {
	if inexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) == 0 {
		return
	}
	var outLength int
	status := commoncrypto.CCCryptorUpdate(
		x.cryptor,  // CCCryptorRef created by CCCryptorCreateWithMode; holds the encryption/decryption state.
		src,        // Input data (source buffer) to be encrypted or decrypted.
		dst,        // Output buffer (destination buffer) where the result will be stored.
		&outLength, // Pointer to a variable that will contain the number of bytes written to the output buffer.
	)
	if status != commoncrypto.KCCSuccess {
		panic("crypto/cipher: CCCryptorUpdate failed")
	}
	runtime.KeepAlive(x)
}

func (x *cbcCipher) SetIV(iv []byte) {
	if len(iv) != x.blockSize {
		panic("crypto/cipher: incorrect IV length")
	}
	status := commoncrypto.CCCryptorReset(x.cryptor, iv)
	if status != commoncrypto.KCCSuccess {
		panic("crypto/cipher: CCCryptorReset failed")
	}
	runtime.KeepAlive(x)
}

// The following two functions are a mirror of golang.org/x/crypto/internal/subtle.

func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}
