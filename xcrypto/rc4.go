// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <CommonCrypto/CommonCrypto.h>
import "C"
import (
	"errors"
	"runtime"
	"slices"
)

// RC4Cipher is an instance of RC4 using a particular key.
type RC4Cipher struct {
	ctx C.CCCryptorRef
}

// NewRC4Cipher creates and returns a new RC4 cipher with the given key.
func NewRC4Cipher(key []byte) (*RC4Cipher, error) {
	// Clone the key to prevent modification.
	key = slices.Clone(key)
	var ctx C.CCCryptorRef
	status := C.CCCryptorCreate(
		C.kCCEncrypt,       // Operation (RC4 stream)
		C.kCCAlgorithmRC4,  // Algorithm
		0,                  // No padding or other options
		pbase(key),         // Key
		C.size_t(len(key)), // Key length
		nil,                // No IV needed for RC4
		&ctx,               // Output: CCCryptorRef
	)
	if status != C.kCCSuccess {
		return nil, errors.New("failed to create RC4 cipher")
	}
	c := &RC4Cipher{ctx: ctx}
	runtime.SetFinalizer(c, (*RC4Cipher).finalize)
	return c, nil
}

// finalize releases the RC4 cipher context when no longer needed.
func (c *RC4Cipher) finalize() {
	if c.ctx != nil {
		C.CCCryptorRelease(c.ctx)
	}
}

// Reset zeros the key data and makes the cipher unusable.
func (c *RC4Cipher) Reset() {
	if c.ctx != nil {
		C.CCCryptorRelease(c.ctx)
		c.ctx = nil
	}
}

// XORKeyStream sets dst to the result of XORing src with the key stream.
func (c *RC4Cipher) XORKeyStream(dst, src []byte) {
	if c.ctx == nil || len(src) == 0 {
		return
	}
	if inexactOverlap(dst[:len(src)], src) {
		panic("crypto/rc4: invalid buffer overlap")
	}
	// Ensures `dst` has sufficient space.
	_ = dst[len(src)-1]
	var outLen C.size_t
	// Pin both src and dst to prevent GC from relocating their memory.
	if len(src) > 0 {
		var srcPinner runtime.Pinner
		srcPinner.Pin(&src[0])
		defer srcPinner.Unpin()
	}
	if len(dst) > 0 {
		var dstPinner runtime.Pinner
		dstPinner.Pin(&dst[0])
		defer dstPinner.Unpin()
	}
	status := C.CCCryptorUpdate(
		c.ctx,
		pbase(src), C.size_t(len(src)), // Input
		pbase(dst), C.size_t(len(dst)), // Output
		&outLen,
	)
	if status != C.kCCSuccess {
		panic("crypto/cipher: CCCryptorUpdate failed")
	}
	if int(outLen) != len(src) {
		panic("crypto/rc4: src not fully XORed")
	}
	runtime.KeepAlive(c)
}
