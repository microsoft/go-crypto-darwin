// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"errors"
	"runtime"
	"slices"

	"github.com/microsoft/go-crypto-darwin/internal/commoncrypto"
)

// RC4Cipher is an instance of RC4 using a particular key.
type RC4Cipher struct {
	ctx commoncrypto.CCCryptorRef
}

// NewRC4Cipher creates and returns a new RC4 cipher with the given key.
func NewRC4Cipher(key []byte) (*RC4Cipher, error) {
	// Clone the key to prevent modification.
	key = slices.Clone(key)
	var ctx commoncrypto.CCCryptorRef
	status := commoncrypto.CCCryptorCreate(
		commoncrypto.KCCEncrypt,      // Operation (RC4 stream)
		commoncrypto.KCCAlgorithmRC4, // Algorithm
		0,                            // No padding or other options
		key,                          // Key
		nil,                          // No IV needed for RC4
		&ctx,                         // Output: CCCryptorRef
	)
	if status != commoncrypto.KCCSuccess {
		return nil, errors.New("failed to create RC4 cipher")
	}
	c := &RC4Cipher{ctx: ctx}
	runtime.SetFinalizer(c, (*RC4Cipher).finalize)
	return c, nil
}

// finalize releases the RC4 cipher context when no longer needed.
func (c *RC4Cipher) finalize() {
	if c.ctx != nil {
		commoncrypto.CCCryptorRelease(c.ctx)
	}
}

// Reset zeros the key data and makes the cipher unusable.
func (c *RC4Cipher) Reset() {
	if c.ctx != nil {
		commoncrypto.CCCryptorRelease(c.ctx)
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
	var outLen int
	status := commoncrypto.CCCryptorUpdate(
		c.ctx,
		src, // Input
		dst, // Output
		&outLen,
	)
	if status != commoncrypto.KCCSuccess {
		panic("crypto/cipher: CCCryptorUpdate failed")
	}
	if int(outLen) != len(src) {
		panic("crypto/rc4: src not fully XORed")
	}
	runtime.KeepAlive(c)
}
