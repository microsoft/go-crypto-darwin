// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"crypto/cipher"
	"errors"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

const (
	// KeySize is the size of the key used by this AEAD, in bytes.
	chachaKeySize = 32

	// NonceSize is the size of the nonce used with the standard variant of this
	// AEAD, in bytes.
	//
	// Note that this is too short to be safely generated at random if the same
	// key is reused more than 2³² times.
	chachaNonceSize = 12

	// Overhead is the size of the Poly1305 authentication tag, and the
	// difference between a ciphertext length and its plaintext.
	chachaOverhead = 16
)

type chacha20poly1305 struct {
	key [chachaKeySize]byte
}

// NewChaCha20Poly1305 returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key.
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != chachaKeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	ret := new(chacha20poly1305)
	copy(ret.key[:], key)
	return ret, nil
}

func (c *chacha20poly1305) NonceSize() int {
	return chachaNonceSize
}

func (c *chacha20poly1305) Overhead() int {
	return chachaOverhead
}

func (c *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != chachaNonceSize {
		panic("chacha20poly1305: bad nonce length passed to Seal")
	}

	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}

	return c.seal(dst, nonce, plaintext, additionalData)
}

var errOpenChaCha = errors.New("chacha20poly1305: message authentication failed")

func (c *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chachaNonceSize {
		panic("chacha20poly1305: bad nonce length passed to Open")
	}
	if len(ciphertext) < 16 {
		return nil, errOpenChaCha
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha20poly1305: ciphertext too large")
	}

	return c.open(dst, nonce, ciphertext, additionalData)
}

func (c *chacha20poly1305) seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ret, out := sliceForAppend(dst, len(plaintext)+chachaOverhead)

	tag := out[len(plaintext):]

	if cryptokit.EncryptChaChaPoly(c.key[:], plaintext, nonce, additionalData, out[:len(plaintext)], tag) != 0 {
		panic("chacha20poly1305: encryption failed")
	}

	return ret
}

func (c *chacha20poly1305) open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	tag := ciphertext[len(ciphertext)-16:]
	ct := ciphertext[:len(ciphertext)-16]

	ret, out := sliceForAppend(dst, len(ct))

	var outLen int
	if cryptokit.DecryptChaChaPoly(c.key[:], ct, nonce, additionalData, tag, out, &outLen) != 0 {
		return nil, errOpenChaCha
	}

	return ret[:len(dst)+outLen], nil
}
