// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <CommonCrypto/CommonCrypto.h>
import "C"
import (
	"errors"
	"hash"
	"runtime"
	"slices"
)

// commonCryptoHMAC encapsulates an HMAC using xcrypto.
type commonCryptoHMAC struct {
	ctx       C.CCHmacContext
	alg       C.CCAlgorithm
	key       []byte
	output    []byte
	size      int
	blockSize int
}

// NewHMAC returns a new HMAC using xcrypto.
// The function h must return a hash implemented by
// CommonCrypto (for example, h could be xcrypto.NewSHA256).
// If h is not recognized, NewHMAC returns nil.
func NewHMAC(fh func() hash.Hash, key []byte) hash.Hash {
	h := fh()
	ccDigest, err := hashToCCDigestHMAC(h)
	if err != nil {
		return nil // Unsupported hash function.
	}

	// Handle empty key case to match CommonCrypto's behavior.
	if len(key) == 0 {
		key = make([]byte, C.CC_SHA512_DIGEST_LENGTH)
	} else {
		key = slices.Clone(key)
	}

	hmac := &commonCryptoHMAC{
		alg:       ccDigest,
		key:       key,
		size:      h.Size(),
		blockSize: h.BlockSize(),
	}

	// Initialize the HMAC context with xcrypto.
	C.CCHmacInit(&hmac.ctx, hmac.alg, pbase(hmac.key), C.size_t(len(hmac.key)))
	return hmac
}

// Write adds more data to the running HMAC hash.
func (h *commonCryptoHMAC) Write(p []byte) (int, error) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.CCHmacUpdate(&h.ctx, pbase(p), C.size_t(len(p)))
	runtime.KeepAlive(h)
	return len(p), nil
}

// Sum appends the current HMAC of the data to `in`.
func (h *commonCryptoHMAC) Sum(in []byte) []byte {
	if h.output == nil {
		h.output = make([]byte, h.size)
	}
	// Copy the context to preserve it for further operations after Sum is called.
	hmacCtxCopy := h.ctx
	C.CCHmacFinal(&hmacCtxCopy, pbase(h.output))
	return append(in, h.output...)
}

// Reset resets the HMAC state to initial values.
func (h *commonCryptoHMAC) Reset() {
	// Re-initialize the HMAC context with the stored key and algorithm.
	C.CCHmacInit(&h.ctx, h.alg, pbase(h.key), C.size_t(len(h.key)))
	runtime.KeepAlive(h)
}

// Size returns the size of the HMAC output.
func (h commonCryptoHMAC) Size() int {
	return h.size
}

// BlockSize returns the block size of the underlying hash function.
func (h commonCryptoHMAC) BlockSize() int {
	return h.blockSize
}

// Mapping Go hash functions to CommonCrypto hash constants
func hashToCCDigestHMAC(hash hash.Hash) (C.CCAlgorithm, error) {
	switch hash.(type) {
	case *md5Hash:
		return C.kCCHmacAlgMD5, nil
	case *sha1Hash:
		return C.kCCHmacAlgSHA1, nil
	case *sha224Hash:
		return C.kCCHmacAlgSHA224, nil
	case *sha256Hash:
		return C.kCCHmacAlgSHA256, nil
	case *sha384Hash:
		return C.kCCHmacAlgSHA384, nil
	case *sha512Hash:
		return C.kCCHmacAlgSHA512, nil
	default:
		return 0, errors.New("unsupported hash function")
	}
}
