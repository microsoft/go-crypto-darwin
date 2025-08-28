// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"crypto/cipher"
	"errors"
	"slices"

	"github.com/microsoft/go-crypto-darwin/internal/commoncrypto"
)

//go:generate go run github.com/microsoft/go-crypto-darwin/cmd/gentestvectors -out vectors_test.go

type cipherGCMTLS uint8

const (
	cipherGCMTLSNone cipherGCMTLS = iota
	cipherGCMTLS12
	cipherGCMTLS13
)

const (
	// AES block size is the same for all key sizes
	aesBlockSize         = commoncrypto.KCCBlockSizeAES128
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
	// TLS 1.2 additional data is constructed as:
	//
	//     additional_data = seq_num(8) + TLSCompressed.type(1) + TLSCompressed.version(2) + TLSCompressed.length(2);
	gcmTls12AddSize = 13
	// TLS 1.3 additional data is constructed as:
	//
	//     additional_data = TLSCiphertext.opaque_type(1) || TLSCiphertext.legacy_record_version(2) || TLSCiphertext.length(2)
	gcmTls13AddSize      = 5
	gcmTlsFixedNonceSize = 4
)

type aesCipher struct {
	key  []byte
	kind commoncrypto.CCAlgorithm
}

func NewAESCipher(key []byte) (cipher.Block, error) {
	var alg commoncrypto.CCAlgorithm
	switch len(key) {
	case 16, 24, 32:
		alg = commoncrypto.KCCAlgorithmAES
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

	status := commoncrypto.CCCrypt(
		commoncrypto.KCCEncrypt,          // Operation
		commoncrypto.CCAlgorithm(c.kind), // Algorithm
		0,                                // Options
		pbase(c.key),                     // Key
		int(len(c.key)),                  // Key length
		nil,                              // IV
		pbase(src),                       // Input
		int(blockSize),                   // Input length
		pbase(dst),                       // Output
		int(blockSize),                   // Output length
		nil,                              // Output length
	)
	if status != commoncrypto.KCCSuccess {
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

	status := commoncrypto.CCCrypt(
		commoncrypto.KCCDecrypt,          // Operation
		commoncrypto.CCAlgorithm(c.kind), // Algorithm
		0,                                // Options
		pbase(c.key),                     // Key
		int(len(c.key)),                  // Key length
		nil,                              // IV
		pbase(src),                       // Input
		int(blockSize),                   // Input length
		pbase(dst),                       // Output
		int(blockSize),                   // Output length
		nil,                              // Output length
	)
	if status != commoncrypto.KCCSuccess {
		panic("crypto/aes: decryption failed")
	}
}

var errOpen = errors.New("cipher: message authentication failed")

func (c *aesCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return newCBC(commoncrypto.KCCEncrypt, c.kind, c.key, iv)
}

func (c *aesCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return newCBC(commoncrypto.KCCDecrypt, c.kind, c.key, iv)
}

// sliceForAppend is a mirror of crypto/cipher.sliceForAppend.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func bigUint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see go.dev/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}
