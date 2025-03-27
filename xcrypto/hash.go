// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <CommonCrypto/CommonCrypto.h>
import "C"
import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

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
	if len(p) > 0 {
		var pinner runtime.Pinner
		defer pinner.Unpin()
		pinner.Pin(&p[0])
	}
	result := C.CC_MD4(pbase(p), C.CC_LONG(len(p)), base(sum[:]))
	if result == nil {
		panic("commoncrypto: MD4 failed")
	}
	return
}

func MD5(p []byte) (sum [16]byte) {
	return cryptokit.MD5(p)
}

func SHA1(p []byte) (sum [20]byte) {
	return cryptokit.SHA1(p)
}

func SHA224(p []byte) (sum [28]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		defer pinner.Unpin()
		pinner.Pin(&p[0])
	}
	result := C.CC_SHA224(pbase(p), C.CC_LONG(len(p)), base(sum[:]))
	if result == nil {
		panic("commoncrypto: SHA224 failed")
	}
	return
}

func SHA256(p []byte) (sum [32]byte) {
	return cryptokit.SHA256(p)
}

func SHA384(p []byte) (sum [48]byte) {
	return cryptokit.SHA384(p)
}

func SHA512(p []byte) (sum [64]byte) {
	return cryptokit.SHA512(p)
}

// cloneHash is an interface that defines a Clone method.
//
// hash.CloneHash will probably be added in Go 1.25, see https://golang.org/issue/69521,
// but we need it now.
type cloneHash interface {
	hash.Hash
	// Clone returns a separate Hash instance with the same state as h.
	Clone() hash.Hash
}

var _ hash.Hash = (*evpHash)(nil)
var _ cloneHash = (*evpHash)(nil)

// evpHash implements generic hash methods.
type evpHash struct {
	ctx unsafe.Pointer
	// ctx2 is used in evpHash.sum to avoid changing
	// the state of ctx. Having it here allows reusing the
	// same allocated object multiple times.
	ctx2      unsafe.Pointer
	pinner    runtime.Pinner
	init      func(ctx unsafe.Pointer) C.int
	update    func(ctx unsafe.Pointer, data []byte) C.int
	final     func(ctx unsafe.Pointer, digest []byte) C.int
	blockSize int
	size      int
	ctxSize   int
}

func newEvpHash(init func(ctx unsafe.Pointer) C.int, update func(ctx unsafe.Pointer, data []byte) C.int, final func(ctx unsafe.Pointer, digest []byte) C.int, ctxSize, blockSize, size int) *evpHash {
	h := &evpHash{
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
	if h.ctx != nil {
		C.free(h.ctx)
	}
	if h.ctx2 != nil {
		C.free(h.ctx2)
	}
}

func (h *evpHash) initialize() {
	if h.ctx == nil {
		h.ctx = C.malloc(C.size_t(h.ctxSize))
		h.ctx2 = C.malloc(C.size_t(h.ctxSize))
		if h.init(h.ctx) != 1 {
			C.free(h.ctx)
			C.free(h.ctx2)
			panic("commoncrypto: initialization failed")
		}
	}
}

func (h *evpHash) Reset() {
	if h.ctx == nil {
		// The hash is not initialized yet, no need to reset.
		return
	}
	// There is no need to reset h.ctx2 because it is always reset after
	// use in evpHash.sum.
	h.init(h.ctx)
	runtime.KeepAlive(h)
}

func (h *evpHash) Write(p []byte) (int, error) {
	h.initialize()
	if len(p) > 0 {
		defer h.pinner.Unpin()
		h.pinner.Pin(&p[0])
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
	h.initialize()
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
	h.initialize()
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
	h.initialize()
	digest := make([]byte, h.size)
	C.memcpy(h.ctx2, h.ctx, C.size_t(h.ctxSize))
	h.final(h.ctx2, digest)
	return append(b, digest...)
}

func (h *evpHash) MarshalBinary() ([]byte, error) {
	return nil, errors.New("xcrypto: hash state is not marshallable")
}

func (h *evpHash) AppendBinary(b []byte) ([]byte, error) {
	return nil, errors.New("xcrypto: hash state is not marshallable")
}

func (h *evpHash) UnmarshalBinary(data []byte) error {
	return errors.New("xcrypto: hash state is not marshallable")
}

// Clone returns a new evpHash object that is a deep clone of itself.
// The duplicate object contains all state and data contained in the
// original object at the point of duplication.
func (h *evpHash) Clone() hash.Hash {
	h.initialize()
	cloned := &evpHash{
		init:      h.init,
		update:    h.update,
		final:     h.final,
		blockSize: h.blockSize,
		size:      h.size,
		ctxSize:   h.ctxSize,
	}
	cloned.ctx = C.malloc(C.size_t(h.ctxSize))
	cloned.ctx2 = C.malloc(C.size_t(h.ctxSize))
	C.memcpy(cloned.ctx, h.ctx, C.size_t(h.ctxSize))
	C.memcpy(cloned.ctx2, h.ctx2, C.size_t(h.ctxSize))
	runtime.SetFinalizer(cloned, (*evpHash).finalize)
	runtime.KeepAlive(h)
	return cloned
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
				return C.CC_MD4_Update((*C.CC_MD4_CTX)(ctx), pbase(data), C.CC_LONG(len(data)))
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

// NewMD5 initializes a new MD5 hasher.
func NewMD5() hash.Hash {
	return cryptokit.NewMD5()
}

// NewSHA1 initializes a new SHA1 hasher.
func NewSHA1() hash.Hash {
	return cryptokit.NewSHA1()
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
				return C.CC_SHA224_Update((*C.CC_SHA256_CTX)(ctx), pbase(data), C.CC_LONG(len(data)))
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

// NewSHA256 initializes a new SHA256 hasher.
func NewSHA256() hash.Hash {
	return cryptokit.NewSHA256()
}

// NewSHA384 initializes a new SHA384 hasher.
func NewSHA384() hash.Hash {
	return cryptokit.NewSHA384()
}

// NewSHA512 initializes a new SHA512 hasher.
func NewSHA512() hash.Hash {
	return cryptokit.NewSHA512()
}
