// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"encoding/binary"
	"runtime"
	"slices"
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

// ctrStream implements cipher.Stream using CommonCrypto's CTR mode.
//
// CommonCrypto's kCCModeCTR only increments the low 64 bits of the
// 128-bit counter block. NIST SP 800-38A requires incrementing the
// full 128-bit value. To work around this, ctrStream tracks the
// counter and re-initializes the CCCryptor when the low 64 bits
// would overflow, carrying into the high 64 bits.
type ctrStream struct {
	cryptor commoncrypto.CCCryptorRef
	kind    commoncrypto.CCAlgorithm
	key     []byte
	ctrHi   uint64 // high 64 bits of the counter
	ctrLo   uint64 // low 64 bits of the counter
	offset  int    // byte offset within current partial block [0, aesBlockSize)
}

func newCTR(kind commoncrypto.CCAlgorithm, key, iv []byte) *ctrStream {
	if len(iv) != aesBlockSize {
		panic("crypto/cipher: incorrect IV length")
	}
	x := &ctrStream{
		kind:  kind,
		key:   slices.Clone(key),
		ctrHi: binary.BigEndian.Uint64(iv[0:8]),
		ctrLo: binary.BigEndian.Uint64(iv[8:16]),
	}
	x.initCryptor(iv)
	runtime.SetFinalizer(x, (*ctrStream).finalize)
	return x
}

func (x *ctrStream) initCryptor(iv []byte) {
	// Use a local variable for the output pointer to avoid passing
	// &x.cryptor to C — x contains key []byte (a Go pointer), and
	// CGO forbids passing a Go pointer into a struct with other Go pointers.
	var cryptor commoncrypto.CCCryptorRef
	status := commoncrypto.CCCryptorCreateWithMode(
		commoncrypto.KCCEncrypt,
		commoncrypto.KCCModeCTR,
		commoncrypto.CCAlgorithm(x.kind),
		commoncrypto.CcNoPadding,
		iv,
		x.key,
		nil,
		0,
		commoncrypto.KCCModeOptionCTR_BE,
		&cryptor,
	)
	if status != commoncrypto.KCCSuccess {
		panic("crypto/cipher: CCCryptorCreateWithMode CTR failed")
	}
	x.cryptor = cryptor
}

func (x *ctrStream) finalize() {
	if x.cryptor != nil {
		commoncrypto.CCCryptorRelease(x.cryptor)
		x.cryptor = nil
	}
}

func (x *ctrStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if inexactOverlap(dst[:len(src)], src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	for len(src) > 0 {
		n := x.safeLen(len(src))
		var outLength int
		status := commoncrypto.CCCryptorUpdate(x.cryptor, src[:n], dst[:n], &outLength)
		if status != commoncrypto.KCCSuccess {
			panic("crypto/cipher: CCCryptorUpdate CTR failed")
		}
		oldLo := x.ctrLo
		x.advance(n)
		dst, src = dst[n:], src[n:]
		if x.ctrLo < oldLo {
			// Low-64 counter has wrapped; carry into high 64 bits
			// and re-initialize the CCCryptor with the correct counter.
			commoncrypto.CCCryptorRelease(x.cryptor)
			x.cryptor = nil
			x.ctrHi++
			// x.ctrLo is already 0 from the wrap in advance()
			var iv [aesBlockSize]byte
			binary.BigEndian.PutUint64(iv[0:8], x.ctrHi)
			// iv[8:16] is already zero == x.ctrLo
			x.initCryptor(iv[:])
		}
	}
	runtime.KeepAlive(x)
}

// safeLen returns the maximum number of bytes that can be processed
// by the current CCCryptor without crossing the low-64 counter
// overflow boundary. The result is always > 0 and ≤ srcLen.
func (x *ctrStream) safeLen(srcLen int) int {
	blocks := ^x.ctrLo + 1 // safe blocks remaining; wraps to 0 if ctrLo == 0 (meaning 2^64)
	if blocks == 0 {
		return srcLen // ctrLo is 0: overflow is 2^64 blocks away, effectively unlimited
	}
	// Avoid overflow in blocks * aesBlockSize.
	if blocks > uint64(srcLen/aesBlockSize+1) {
		return srcLen
	}
	if safe := int(blocks)*aesBlockSize - x.offset; safe < srcLen {
		return safe
	}
	return srcLen
}

// advance updates the tracked counter after n bytes have been
// processed by CCCryptorUpdate.
func (x *ctrStream) advance(n int) {
	total := x.offset + n
	blocks := uint64(total / aesBlockSize)
	x.offset = total % aesBlockSize
	x.ctrLo += blocks // may wrap to 0, which triggers reinit in the caller
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
