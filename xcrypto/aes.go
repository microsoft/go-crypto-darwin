// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <CommonCrypto/CommonCrypto.h>
import "C"
import (
	"crypto/cipher"
	"errors"
	"slices"

	"github.com/microsoft/go-crypto-darwin/cryptokit"
)

const aesBlockSize = C.kCCBlockSizeAES128 // AES block size is the same for all key sizes

type aesCipher struct {
	key  []byte
	kind C.CCAlgorithm
}

func NewAESCipher(key []byte) (cipher.Block, error) {
	var alg C.CCAlgorithm
	switch len(key) {
	case 16, 24, 32:
		alg = C.kCCAlgorithmAES
	default:
		return nil, errors.New("crypto/aes: invalid key size")
	}
	c := &aesCipher{
		key:  slices.Clone(key),
		kind: alg,
	}
	return c, nil
}

func (c *aesCipher) BlockSize() int { return aesBlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) {
	blockSize := c.BlockSize()
	if len(src) < blockSize || len(dst) < blockSize {
		panic("crypto/aes: input or output block is too small")
	}

	src, dst = src[:blockSize], dst[:blockSize]

	if inexactOverlap(dst, src) {
		panic("crypto/aes: invalid buffer overlap")
	}

	status := C.CCCrypt(
		C.kCCEncrypt,          // Operation
		C.CCAlgorithm(c.kind), // Algorithm
		0,                     // Options
		pbase(c.key),          // Key
		C.size_t(len(c.key)),  // Key length
		nil,                   // IV
		pbase(src),            // Input
		C.size_t(blockSize),   // Input length
		pbase(dst),            // Output
		C.size_t(blockSize),   // Output length
		nil,                   // Output length
	)
	if status != C.kCCSuccess {
		panic("crypto/aes: encryption failed")
	}
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	blockSize := c.BlockSize()
	if len(src) < blockSize || len(dst) < blockSize {
		panic("crypto/aes: input or output block is too small")
	}

	src, dst = src[:blockSize], dst[:blockSize]

	if inexactOverlap(dst, src) {
		panic("crypto/aes: invalid buffer overlap")
	}

	status := C.CCCrypt(
		C.kCCDecrypt,          // Operation
		C.CCAlgorithm(c.kind), // Algorithm
		0,                     // Options
		pbase(c.key),          // Key
		C.size_t(len(c.key)),  // Key length
		nil,                   // IV
		pbase(src),            // Input
		C.size_t(blockSize),   // Input length
		pbase(dst),            // Output
		C.size_t(blockSize),   // Output length
		nil,                   // Output length
	)
	if status != C.kCCSuccess {
		panic("crypto/aes: decryption failed")
	}
}

// NewGCM constructs a GCM block mode for AES using the cryptokit package
func (c *aesCipher) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	return cryptokit.NewGCM(c.key, c, nonceSize, tagSize)
}

// NewGCMTLS returns a GCM cipher specific to TLS
// and should not be used for non-TLS purposes.
func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	return cryptokit.NewGCMTLS(c.(*aesCipher).key)
}

// NewGCMTLS13 returns a GCM cipher specific to TLS 1.3 and should not be used
// for non-TLS purposes.
func NewGCMTLS13(c cipher.Block) (cipher.AEAD, error) {
	return cryptokit.NewGCMTLS13(c.(*aesCipher).key)
}

func (c *aesCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return newCBC(C.kCCEncrypt, c.kind, c.key, iv)
}

func (c *aesCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return newCBC(C.kCCDecrypt, c.kind, c.key, iv)
}
