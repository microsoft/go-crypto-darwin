// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"crypto/cipher"
	"errors"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

type aesGCM struct {
	key []byte
	tls cipherGCMTLS
	// minNextNonce is the minimum value that the next nonce can be, enforced by
	// all TLS modes.
	minNextNonce uint64
	// mask is the nonce mask used in TLS 1.3 mode.
	mask uint64
	// maskInitialized is true if mask has been initialized. This happens during
	// the first Seal. The initialized mask may be 0. Used by TLS 1.3 mode.
	maskInitialized bool
}

type noGCM struct {
	cipher.Block
}

// NewGCM constructs a GCM block mode for AES using the cryptokit package
func (c *aesCipher) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	if nonceSize != gcmStandardNonceSize && tagSize != gcmTagSize {
		return nil, errors.New("crypto/aes: GCM tag and nonce sizes can't be non-standard at the same time")
	}
	// Fall back to standard library for GCM with non-standard nonce or tag size.
	if nonceSize != gcmStandardNonceSize {
		return cipher.NewGCMWithNonceSize(&noGCM{c}, nonceSize)
	}
	if tagSize != gcmTagSize {
		return cipher.NewGCMWithTagSize(&noGCM{c}, tagSize)
	}
	return &aesGCM{key: c.key, tls: cipherGCMTLSNone}, nil
}

func (g *aesGCM) NonceSize() int { return gcmStandardNonceSize }

func (g *aesGCM) Overhead() int { return gcmTagSize }

func (g *aesGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*aesBlockSize || len(plaintext)+gcmTagSize < len(plaintext) {
		panic("cipher: message too large for GCM")
	}
	if len(dst)+len(plaintext)+gcmTagSize < len(dst) {
		panic("cipher: message too large for buffer")
	}

	if g.tls != cipherGCMTLSNone {
		if g.tls == cipherGCMTLS12 && len(additionalData) != gcmTls12AddSize {
			panic("cipher: incorrect additional data length given to GCM TLS 1.2")
		} else if g.tls == cipherGCMTLS13 && len(additionalData) != gcmTls13AddSize {
			panic("cipher: incorrect additional data length given to GCM TLS 1.3")
		}
		counter := bigUint64(nonce[gcmTlsFixedNonceSize:])

		// TLS 1.3 Masking
		if g.tls == cipherGCMTLS13 {
			if !g.maskInitialized {
				g.mask = counter
				g.maskInitialized = true
			}
			// Apply mask to the counter
			counter ^= g.mask
		}

		// Enforce monotonicity and max limit
		const maxUint64 = 1<<64 - 1
		if counter == maxUint64 {
			panic("cipher: nonce counter must be less than 2^64 - 1")
		}
		if counter < g.minNextNonce {
			panic("cipher: nonce counter must be strictly monotonically increasing")
		}

		defer func() {
			g.minNextNonce = counter + 1
		}()
	}

	// Make room in dst to append plaintext+overhead.
	ret, out := sliceForAppend(dst, len(plaintext)+gcmTagSize)

	// Check delayed until now to make sure len(dst) is accurate.
	if inexactOverlap(out, plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	tag := out[len(out)-gcmTagSize:]
	err := cryptokit.EncryptAESGCM(
		addr(g.key), len(g.key),
		addr(plaintext), len(plaintext),
		addr(nonce), len(nonce),
		addr(additionalData), len(additionalData),
		addr(out[:len(out)-gcmTagSize]), len(out[:len(out)-gcmTagSize]),
		addr(tag),
	)
	if err != 0 {
		panic("cipher: encryption failed")
	}
	return ret
}

func (g *aesGCM) SealWithRandomNonce(out, nonce, plaintext, additionalData []byte) {
	if uint64(len(plaintext)) > uint64((1<<32)-2)*aesBlockSize {
		panic("crypto/cipher: message too large for GCM")
	}
	if len(nonce) != gcmStandardNonceSize {
		panic("crypto/cipher: incorrect nonce length given to GCMWithRandomNonce")
	}
	if len(out) != len(plaintext)+gcmTagSize {
		panic("crypto/cipher: incorrect output length given to GCMWithRandomNonce")
	}
	if inexactOverlap(out, plaintext) {
		panic("crypto/cipher: invalid buffer overlap of output and input")
	}
	if anyOverlap(out, additionalData) {
		panic("crypto/cipher: invalid buffer overlap of output and additional data")
	}

	if g.tls != cipherGCMTLSNone {
		panic("cipher: TLS 1.2 and 1.3 modes do not support random nonce")
	}

	tag := out[len(out)-gcmTagSize:]
	// Generate a random nonce
	RandReader.Read(nonce)
	err := cryptokit.EncryptAESGCM(
		addr(g.key), len(g.key),
		addr(plaintext), len(plaintext),
		addr(nonce), len(nonce),
		addr(additionalData), len(additionalData),
		addr(out[:len(out)-gcmTagSize]), len(out[:len(out)-gcmTagSize]),
		addr(tag),
	)
	if err != 0 {
		panic("cipher: encryption failed")
	}
}

func (g *aesGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if len(ciphertext) < gcmTagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*aesBlockSize+gcmTagSize {
		return nil, errOpen
	}
	// BoringCrypto does not do any TLS check when decrypting, neither do we.

	// Ensure we don't process if ciphertext lacks both ciphertext and tag
	if len(ciphertext) < gcmTagSize {
		return nil, errors.New("decryption failed: ciphertext too short for tag")
	}

	tag := ciphertext[len(ciphertext)-gcmTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-gcmTagSize]

	// Make room in dst to append ciphertext without tag.
	ret, out := sliceForAppend(dst, len(ciphertext))

	// Check delayed until now to make sure len(dst) is accurate.
	if inexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap")
	}

	var decSize int
	err := cryptokit.DecryptAESGCM(
		addr(g.key), len(g.key),
		addr(ciphertext), len(ciphertext),
		addr(nonce), len(nonce),
		addr(additionalData), len(additionalData),
		addr(tag), len(tag),
		addr(out), &decSize,
	)
	if err != 0 || int(decSize) != len(ciphertext) {
		// If the decrypted data size does not match, zero out `out` and return `errOpen`
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}

// NewGCMTLS returns a GCM cipher specific to TLS
// and should not be used for non-TLS purposes.
func NewGCMTLS(block cipher.Block) (cipher.AEAD, error) {
	cipher, ok := block.(*aesCipher)
	if !ok {
		return nil, errors.New("crypto/aes: invalid block cipher")
	}
	return &aesGCM{key: cipher.key, tls: cipherGCMTLS12}, nil
}

// NewGCMTLS13 returns a GCM cipher specific to TLS 1.3 and should not be used
// for non-TLS purposes.
func NewGCMTLS13(block cipher.Block) (cipher.AEAD, error) {
	cipher, ok := block.(*aesCipher)
	if !ok {
		return nil, errors.New("crypto/aes: invalid block cipher")
	}
	return &aesGCM{key: cipher.key, tls: cipherGCMTLS13}, nil
}
