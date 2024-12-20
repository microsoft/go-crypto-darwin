// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin && cgo

package xcrypto

// #include <CommonCrypto/CommonCrypto.h>
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"unsafe"
)

// NOTE: Implementation ported from https://go-review.googlesource.com/c/go/+/404295.
// The cgo calls in this file are arranged to avoid marking the parameters as escaping.
// To do that, we call noescape (including via addr).
// We must also make sure that the data pointer arguments have the form unsafe.Pointer(&...)
// so that cgo does not annotate them with cgoCheckPointer calls. If it did that, it might look
// beyond the byte slice and find Go pointers in unprocessed parts of a larger allocation.
// To do both of these simultaneously, the idiom is unsafe.Pointer(&*addr(p)),
// where addr returns the base pointer of p, substituting a non-nil pointer for nil,
// and applying a noescape along the way.
// This is all to preserve compatibility with the allocation behavior of the non-commoncrypto implementations.

// SupportsHash returns true if a hash.Hash implementation is supported for h.
func SupportsHash(h crypto.Hash) bool {
	switch h {
	case crypto.MD4, crypto.MD5, crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}

func MD4(p []byte) (sum [16]byte) {
	result := C.CC_MD4(unsafe.Pointer(&*addr(p)), C.CC_LONG(len(p)), (*C.uchar)(&*addr(sum[:])))
	if result == nil {
		panic("commoncrypto: MD4 failed")
	}
	return
}

func MD5(p []byte) (sum [16]byte) {
	result := C.CC_MD5(unsafe.Pointer(&*addr(p)), C.CC_LONG(len(p)), (*C.uchar)(&*addr(sum[:])))
	if result == nil {
		panic("commoncrypto: MD5 failed")
	}
	return
}

func SHA1(p []byte) (sum [20]byte) {
	result := C.CC_SHA1(unsafe.Pointer(&*addr(p)), C.CC_LONG(len(p)), (*C.uchar)(&*addr(sum[:])))
	if result == nil {
		panic("commoncrypto: SHA1 failed")
	}
	return
}

func SHA224(p []byte) (sum [28]byte) {
	result := C.CC_SHA224(unsafe.Pointer(&*addr(p)), C.CC_LONG(len(p)), (*C.uchar)(&*addr(sum[:])))
	if result == nil {
		panic("commoncrypto: SHA224 failed")
	}
	return
}

func SHA256(p []byte) (sum [32]byte) {
	result := C.CC_SHA256(unsafe.Pointer(&*addr(p)), C.CC_LONG(len(p)), (*C.uchar)(&*addr(sum[:])))
	if result == nil {
		panic("commoncrypto: SHA256 failed")
	}
	return
}

func SHA384(p []byte) (sum [48]byte) {
	result := C.CC_SHA384(unsafe.Pointer(&*addr(p)), C.CC_LONG(len(p)), (*C.uchar)(&*addr(sum[:])))
	if result == nil {
		panic("commoncrypto: SHA384 failed")
	}
	return
}

func SHA512(p []byte) (sum [64]byte) {
	result := C.CC_SHA512(unsafe.Pointer(&*addr(p)), C.CC_LONG(len(p)), (*C.uchar)(&*addr(sum[:])))
	if result == nil {
		panic("commoncrypto: SHA512 failed")
	}
	return
}

type evpHash struct {
	ctx unsafe.Pointer
	// ctx2 is used in evpHash.sum to avoid changing
	// the state of ctx. Having it here allows reusing the
	// same allocated object multiple times.
	ctx2      unsafe.Pointer
	init      func(ctx unsafe.Pointer) C.int
	update    func(ctx unsafe.Pointer, data []byte) C.int
	final     func(ctx unsafe.Pointer, digest []byte) C.int
	blockSize int
	size      int
	ctxSize   int
}

func newEvpHash(init func(ctx unsafe.Pointer) C.int, update func(ctx unsafe.Pointer, data []byte) C.int, final func(ctx unsafe.Pointer, digest []byte) C.int, ctxSize, blockSize, size int) *evpHash {
	ctx := C.malloc(C.size_t(ctxSize))
	ctx2 := C.malloc(C.size_t(ctxSize))
	init(ctx)
	h := &evpHash{
		ctx:       ctx,
		ctx2:      ctx2,
		init:      init,
		update:    update,
		final:     final,
		blockSize: blockSize,
		size:      size,
		ctxSize:   ctxSize,
	}
	runtime.SetFinalizer(h, (*evpHash).finalize)
	return h
}

func (h *evpHash) finalize() {
	C.free(h.ctx)
	C.free(h.ctx2)
}

func (h *evpHash) Reset() {
	// There is no need to reset h.ctx2 because it is always reset after
	// use in evpHash.sum.
	h.init(h.ctx)
	runtime.KeepAlive(h)
}

func (h *evpHash) Write(p []byte) (int, error) {
	if len(p) > 0 {
		// Use a local variable to prevent the compiler from misinterpreting the pointer
		data := p
		if h.update(h.ctx, data) != 1 {
			return 0, errors.New("commoncrypto: Update function failed")
		}
	}
	runtime.KeepAlive(h) // Ensure the hash object is not garbage-collected
	return len(p), nil
}

func (h *evpHash) WriteString(s string) (int, error) {
	if len(s) > 0 {
		data := []byte(s)
		if h.update(h.ctx, data) != 1 {
			return 0, errors.New("commoncrypto: Update function failed")
		}
	}
	runtime.KeepAlive(h)
	return len(s), nil
}

func (h *evpHash) WriteByte(c byte) error {
	if h.update(h.ctx, []byte{c}) != 1 {
		return errors.New("commoncrypto: Update function failed")
	}
	runtime.KeepAlive(h)
	return nil
}
func (h *evpHash) Size() int {
	return h.size
}

func (h *evpHash) BlockSize() int {
	return h.blockSize
}

func (h *evpHash) Sum(b []byte) []byte {
	digest := make([]byte, h.size)
	C.memcpy(h.ctx2, h.ctx, C.size_t(h.ctxSize))
	h.final(h.ctx2, digest)
	return append(b, digest...)
}

type md4Hash struct {
	*evpHash
}

// NewMD4 initializes a new MD4 hasher.
func NewMD4() hash.Hash {
	return &md4Hash{
		evpHash: newEvpHash(
			func(ctx unsafe.Pointer) C.int { return C.CC_MD4_Init((*C.CC_MD4_CTX)(ctx)) },
			func(ctx unsafe.Pointer, data []byte) C.int {
				return C.CC_MD4_Update((*C.CC_MD4_CTX)(ctx), unsafe.Pointer(&*addr(data)), C.CC_LONG(len(data)))
			},
			func(ctx unsafe.Pointer, digest []byte) C.int {
				return C.CC_MD4_Final(base(digest), (*C.CC_MD4_CTX)(ctx))
			},
			C.sizeof_CC_MD4_CTX,
			C.CC_MD4_BLOCK_BYTES,
			C.CC_MD4_DIGEST_LENGTH,
		),
	}
}

type md5Hash struct {
	*evpHash
}

// NewMD5 initializes a new MD5 hasher.
func NewMD5() hash.Hash {
	return &md5Hash{
		evpHash: newEvpHash(
			func(ctx unsafe.Pointer) C.int { return C.CC_MD5_Init((*C.CC_MD5_CTX)(ctx)) },
			func(ctx unsafe.Pointer, data []byte) C.int {
				return C.CC_MD5_Update((*C.CC_MD5_CTX)(ctx), unsafe.Pointer(&*addr(data)), C.CC_LONG(len(data)))
			},
			func(ctx unsafe.Pointer, digest []byte) C.int {
				return C.CC_MD5_Final(base(digest), (*C.CC_MD5_CTX)(ctx))
			},
			C.sizeof_CC_MD5_CTX,
			C.CC_MD5_BLOCK_BYTES,
			C.CC_MD5_DIGEST_LENGTH,
		),
	}
}

type sha1Hash struct {
	*evpHash
}

// NewSHA1 initializes a new SHA1 hasher.
func NewSHA1() hash.Hash {
	return &sha1Hash{
		evpHash: newEvpHash(
			func(ctx unsafe.Pointer) C.int { return C.CC_SHA1_Init((*C.CC_SHA1_CTX)(ctx)) },
			func(ctx unsafe.Pointer, data []byte) C.int {
				return C.CC_SHA1_Update((*C.CC_SHA1_CTX)(ctx), unsafe.Pointer(&*addr(data)), C.CC_LONG(len(data)))
			},
			func(ctx unsafe.Pointer, digest []byte) C.int {
				return C.CC_SHA1_Final(base(digest), (*C.CC_SHA1_CTX)(ctx))
			},
			C.sizeof_CC_SHA1_CTX,
			C.CC_SHA1_BLOCK_BYTES,
			C.CC_SHA1_DIGEST_LENGTH,
		),
	}
}

type sha224Hash struct {
	*evpHash
}

// NewSHA224 initializes a new SHA224 hasher.
func NewSHA224() hash.Hash {
	return &sha224Hash{
		evpHash: newEvpHash(
			func(ctx unsafe.Pointer) C.int { return C.CC_SHA224_Init((*C.CC_SHA256_CTX)(ctx)) },
			func(ctx unsafe.Pointer, data []byte) C.int {
				return C.CC_SHA224_Update((*C.CC_SHA256_CTX)(ctx), unsafe.Pointer(&*addr(data)), C.CC_LONG(len(data)))
			},
			func(ctx unsafe.Pointer, digest []byte) C.int {
				return C.CC_SHA224_Final(base(digest), (*C.CC_SHA256_CTX)(ctx))
			},
			C.sizeof_CC_SHA256_CTX,
			C.CC_SHA224_BLOCK_BYTES,
			C.CC_SHA224_DIGEST_LENGTH,
		),
	}
}

type sha256Hash struct {
	*evpHash
}

// NewSHA256 initializes a new SHA256 hasher.
func NewSHA256() hash.Hash {
	return &sha256Hash{
		evpHash: newEvpHash(
			func(ctx unsafe.Pointer) C.int { return C.CC_SHA256_Init((*C.CC_SHA256_CTX)(ctx)) },
			func(ctx unsafe.Pointer, data []byte) C.int {
				return C.CC_SHA256_Update((*C.CC_SHA256_CTX)(ctx), unsafe.Pointer(&*addr(data)), C.CC_LONG(len(data)))
			},
			func(ctx unsafe.Pointer, digest []byte) C.int {
				return C.CC_SHA256_Final(base(digest), (*C.CC_SHA256_CTX)(ctx))
			},
			C.sizeof_CC_SHA256_CTX,
			C.CC_SHA256_BLOCK_BYTES,
			C.CC_SHA256_DIGEST_LENGTH,
		),
	}
}

type sha384Hash struct {
	*evpHash
}

// NewSHA384 initializes a new SHA384 hasher.
func NewSHA384() hash.Hash {
	return &sha384Hash{
		evpHash: newEvpHash(
			func(ctx unsafe.Pointer) C.int { return C.CC_SHA384_Init((*C.CC_SHA512_CTX)(ctx)) },
			func(ctx unsafe.Pointer, data []byte) C.int {
				return C.CC_SHA384_Update((*C.CC_SHA512_CTX)(ctx), unsafe.Pointer(&*addr(data)), C.CC_LONG(len(data)))
			},
			func(ctx unsafe.Pointer, digest []byte) C.int {
				return C.CC_SHA384_Final(base(digest), (*C.CC_SHA512_CTX)(ctx))
			},
			C.sizeof_CC_SHA512_CTX,
			C.CC_SHA384_BLOCK_BYTES,
			C.CC_SHA384_DIGEST_LENGTH,
		),
	}
}

type sha512Hash struct {
	*evpHash
}

// NewSHA512 initializes a new SHA512 hasher.
func NewSHA512() hash.Hash {
	return &sha512Hash{
		evpHash: newEvpHash(
			func(ctx unsafe.Pointer) C.int { return C.CC_SHA512_Init((*C.CC_SHA512_CTX)(ctx)) },
			func(ctx unsafe.Pointer, data []byte) C.int {
				return C.CC_SHA512_Update((*C.CC_SHA512_CTX)(ctx), unsafe.Pointer(&*addr(data)), C.CC_LONG(len(data)))
			},
			func(ctx unsafe.Pointer, digest []byte) C.int {
				return C.CC_SHA512_Final(base(digest), (*C.CC_SHA512_CTX)(ctx))
			},
			C.sizeof_CC_SHA512_CTX,
			C.CC_SHA512_BLOCK_BYTES,
			C.CC_SHA512_DIGEST_LENGTH,
		),
	}
}
