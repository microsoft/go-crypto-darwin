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
)

const desBlockSize = C.kCCBlockSizeDES

type desCipher struct {
	key  []byte
	kind C.CCAlgorithm
}

// NewDESCipher creates a new DES cipher block using the specified key (8 bytes).
func NewDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 8 {
		return nil, errors.New("crypto/des: invalid key size for DES")
	}

	c := &desCipher{
		key:  slices.Clone(key),
		kind: C.kCCAlgorithmDES,
	}
	return c, nil
}

// NewTripleDESCipher creates a new 3DES cipher block using the specified key (24 bytes).
func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 24 {
		return nil, errors.New("crypto/des: invalid key size for 3DES")
	}

	c := &desCipher{
		key:  slices.Clone(key),
		kind: C.kCCAlgorithm3DES,
	}
	return c, nil
}

func (c *desCipher) BlockSize() int { return desBlockSize }

func (c *desCipher) Encrypt(dst, src []byte) {
	blockSize := c.BlockSize()
	if len(src) < blockSize || len(dst) < blockSize {
		panic("crypto/des: input or output block is too small")
	}

	if inexactOverlap(dst[:blockSize], src[:blockSize]) {
		panic("crypto/des: invalid buffer overlap")
	}

	var outLength C.size_t
	status := C.CCCrypt(
		C.kCCEncrypt,
		C.CCAlgorithm(c.kind),
		C.kCCOptionECBMode,
		pbase(c.key),
		C.size_t(len(c.key)),
		nil,
		pbase(src[:blockSize]),
		C.size_t(blockSize),
		pbase(dst[:blockSize]),
		C.size_t(blockSize),
		&outLength,
	)
	if status != C.kCCSuccess {
		panic("crypto/des: encryption failed")
	}
}

func (c *desCipher) Decrypt(dst, src []byte) {
	blockSize := c.BlockSize()
	if len(src) < blockSize || len(dst) < blockSize {
		panic("crypto/des: input or output block is too small")
	}

	if inexactOverlap(dst[:blockSize], src[:blockSize]) {
		panic("crypto/des: invalid buffer overlap")
	}

	var outLength C.size_t
	status := C.CCCrypt(
		C.kCCDecrypt,
		C.CCAlgorithm(c.kind),
		C.kCCOptionECBMode,
		pbase(c.key),
		C.size_t(len(c.key)),
		nil,
		pbase(src[:blockSize]),
		C.size_t(blockSize),
		pbase(dst[:blockSize]),
		C.size_t(blockSize),
		&outLength,
	)
	if status != C.kCCSuccess {
		panic("crypto/des: decryption failed")
	}
}

// CBC mode encrypter
func (c *desCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return newCBC(C.kCCEncrypt, c.kind, c.key, iv)
}

// CBC mode decrypter
func (c *desCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return newCBC(C.kCCDecrypt, c.kind, c.key, iv)
}
