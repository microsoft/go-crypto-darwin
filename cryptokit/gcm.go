// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import (
	"crypto/cipher"
	"errors"
	"unsafe"
)

//go:generate go run github.com/microsoft/go-crypto-darwin/cmd/gentestvectors -out vectors_test.go

type cipherGCMTLS uint8

const (
	cipherGCMTLSNone cipherGCMTLS = iota
	cipherGCMTLS12
	cipherGCMTLS13
)

const (
	aesBlockSize         = 16
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

type noGCM struct {
	cipher.Block
}

type AESCipher interface {
	Key() []byte
}

func NewGCM(key []byte, block cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if nonceSize != gcmStandardNonceSize && tagSize != gcmTagSize {
		return nil, errors.New("crypto/aes: GCM tag and nonce sizes can't be non-standard at the same time")
	}
	if nonceSize != gcmStandardNonceSize {
		return cipher.NewGCMWithNonceSize(&noGCM{block}, nonceSize)
	}
	if tagSize != gcmTagSize {
		return cipher.NewGCMWithTagSize(&noGCM{block}, tagSize)
	}
	return newGCM(key, cipherGCMTLSNone)
}

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

// NewGCMTLS returns a GCM cipher specific to TLS
// and should not be used for non-TLS purposes.
func NewGCMTLS(key []byte) (cipher.AEAD, error) {
	return newGCM(key, cipherGCMTLS12)
}

func (c *aesGCM) NewGCMTLS() (cipher.AEAD, error) {
	return newGCM(c.key, cipherGCMTLS12)
}

// NewGCMTLS13 returns a GCM cipher specific to TLS 1.3 and should not be used
// for non-TLS purposes.
func NewGCMTLS13(key []byte) (cipher.AEAD, error) {
	return newGCM(key, cipherGCMTLS13)
}

func (c *aesGCM) NewGCMTLS13() (cipher.AEAD, error) {
	return newGCM(c.key, cipherGCMTLS13)
}

// Define `newGCM` to call the CryptoKit GCM encryption you set up in Swift.
func newGCM(key []byte, tls cipherGCMTLS) (*aesGCM, error) {
	g := &aesGCM{key: key, tls: tls}
	return g, nil
}

func (g *aesGCM) NonceSize() int {
	return gcmStandardNonceSize
}

func (g *aesGCM) Overhead() int {
	return gcmTagSize
}

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

	// Call the Swift-based AES-GCM encryption
	C.encryptAESGCM(
		base(g.key), C.size_t(len(g.key)),
		base(plaintext), C.size_t(len(plaintext)),
		base(nonce), C.size_t(len(nonce)),
		base(additionalData), C.size_t(len(additionalData)),
		base(out), C.size_t(len(out)),
		base(tag),
	)
	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

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

	ret, out := sliceForAppend(dst, len(ciphertext))

	// Prepare to call the Swift-based AES-GCM decryption function
	cNonce := base(nonce)
	cAad := base(additionalData)

	var decSize C.size_t

	// Call Swift-based AES-GCM decryption
	err := C.decryptAESGCM(
		base(g.key), C.size_t(len(g.key)),
		base(ciphertext), C.size_t(len(ciphertext)),
		cNonce, C.size_t(len(nonce)),
		cAad, C.size_t(len(additionalData)),
		base(tag), C.size_t(len(tag)),
		base(out), &decSize,
	)

	if err != 0 {
		return nil, errOpen
	}

	if int(decSize) != len(ciphertext) {
		// If the decrypted data size does not match, zero out `out` and return `errOpen`
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
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
