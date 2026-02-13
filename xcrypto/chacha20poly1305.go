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
	chacha20Poly1305KeySize   = 32
	chacha20Poly1305NonceSize = 12
	chacha20Poly1305Overhead  = 16
)

type chacha20poly1305 struct {
	key [chacha20Poly1305KeySize]byte
}

// NewChaCha20Poly1305 returns a ChaCha20-Poly1305 AEAD that uses the given 256-bit key.
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20Poly1305KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	ret := new(chacha20poly1305)
	copy(ret.key[:], key)
	return ret, nil
}

func (c *chacha20poly1305) NonceSize() int {
	return chacha20Poly1305NonceSize
}

func (c *chacha20poly1305) Overhead() int {
	return chacha20Poly1305Overhead
}

func (c *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != chacha20Poly1305NonceSize {
		panic("chacha20poly1305: bad nonce length passed to Seal")
	}
	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+chacha20Poly1305Overhead)
	if inexactOverlap(out, plaintext) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if anyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	tag := out[len(out)-chacha20Poly1305Overhead:]
	if cryptokit.EncryptChaChaPoly(c.key[:], plaintext, nonce, additionalData, out[:len(plaintext)], tag) != 0 {
		panic("chacha20poly1305: encryption failed")
	}
	return ret
}

func (c *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chacha20Poly1305NonceSize {
		panic("chacha20poly1305: bad nonce length passed to Open")
	}
	if len(ciphertext) < 16 {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha20poly1305: ciphertext too large")
	}
	tag := ciphertext[len(ciphertext)-chacha20Poly1305Overhead:]
	ciphertext = ciphertext[:len(ciphertext)-chacha20Poly1305Overhead]
	ret, out := sliceForAppend(dst, len(ciphertext))
	if inexactOverlap(out, ciphertext) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if anyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	var outLen int
	if cryptokit.DecryptChaChaPoly(c.key[:], ciphertext, nonce, additionalData, tag, out, &outLen) != 0 {
		return nil, errOpen
	}
	return ret[:len(dst)+outLen], nil
}
