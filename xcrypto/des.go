// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build cgo && darwin

package xcrypto

import (
	"crypto/cipher"
	"errors"
	"slices"

	"github.com/microsoft/go-crypto-darwin/internal/commoncrypto"
)

const desBlockSize = commoncrypto.KCCBlockSizeDES

type desCipher struct {
	key  []byte
	kind commoncrypto.CCAlgorithm
}

// NewDESCipher creates a new DES cipher block using the specified key (8 bytes).
func NewDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 8 {
		return nil, errors.New("crypto/des: invalid key size for DES")
	}

	c := &desCipher{
		key:  slices.Clone(key),
		kind: commoncrypto.KCCAlgorithmDES,
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
		kind: commoncrypto.KCCAlgorithm3DES,
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

	var outLength int
	status := commoncrypto.CCCrypt(
		commoncrypto.KCCEncrypt,
		commoncrypto.CCAlgorithm(c.kind),
		commoncrypto.KCCOptionECBMode,
		pbase(c.key),
		int(len(c.key)),
		nil,
		pbase(src[:blockSize]),
		int(blockSize),
		pbase(dst[:blockSize]),
		int(blockSize),
		&outLength,
	)
	if status != commoncrypto.KCCSuccess {
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

	var outLength int
	status := commoncrypto.CCCrypt(
		commoncrypto.KCCDecrypt,
		commoncrypto.CCAlgorithm(c.kind),
		commoncrypto.KCCOptionECBMode,
		pbase(c.key),
		int(len(c.key)),
		nil,
		pbase(src[:blockSize]),
		int(blockSize),
		pbase(dst[:blockSize]),
		int(blockSize),
		&outLength,
	)
	if status != commoncrypto.KCCSuccess {
		panic("crypto/des: decryption failed")
	}
}

// CBC mode encrypter
func (c *desCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return newCBC(commoncrypto.KCCEncrypt, c.kind, c.key, iv)
}

// CBC mode decrypter
func (c *desCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return newCBC(commoncrypto.KCCDecrypt, c.kind, c.key, iv)
}
