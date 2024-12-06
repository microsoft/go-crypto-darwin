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

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
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
	aesBlockSize         = C.kCCBlockSizeAES128
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

// NewGCM constructs a generic GCM AEAD cipher.
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
	err := cryptokit.EncryptAESGCM(g.key, plaintext, nonce, additionalData, out[:len(out)-gcmTagSize], tag)
	if err != 0 {
		panic("cipher: encryption failed")
	}
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

	decSize, err := cryptokit.DecryptAESGCM(g.key, ciphertext, nonce, additionalData, tag, out)
	if err != 0 {
		return nil, errOpen
	}

	if decSize != len(ciphertext) {
		// If the decrypted data size does not match, zero out `out` and return `errOpen`
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	return ret, nil
}

// NewGCMTLS returns a GCM cipher specific to TLS 1.2.
func NewGCMTLS(block cipher.Block) (cipher.AEAD, error) {
	cipher, ok := block.(*aesCipher)
	if !ok {
		return nil, errors.New("crypto/aes: invalid block cipher")
	}
	return &aesGCM{key: cipher.key, tls: cipherGCMTLS12}, nil
}

// NewGCMTLS13 returns a GCM cipher specific to TLS 1.3.
func NewGCMTLS13(block cipher.Block) (cipher.AEAD, error) {
	cipher, ok := block.(*aesCipher)
	if !ok {
		return nil, errors.New("crypto/aes: invalid block cipher")
	}
	return &aesGCM{key: cipher.key, tls: cipherGCMTLS13}, nil
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
