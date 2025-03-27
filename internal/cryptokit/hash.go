// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import (
	"errors"
	"hash"
	"runtime"
	"unsafe"
)

func MD5(p []byte) (sum [16]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.MD5(base(p), C.size_t(len(p)), base(sum[:]))
	return
}

func SHA1(p []byte) (sum [20]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.SHA1(base(p), C.size_t(len(p)), base(sum[:]))
	return
}

func SHA256(p []byte) (sum [32]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.SHA256(base(p), C.size_t(len(p)), base(sum[:]))
	return
}

func SHA384(p []byte) (sum [48]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.SHA384(base(p), C.size_t(len(p)), base(sum[:]))
	return
}

func SHA512(p []byte) (sum [64]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.SHA512(base(p), C.size_t(len(p)), base(sum[:]))
	return
}

var (
	MD5BlockSize    = int(C.MD5BlockSize())
	MD5Size         = int(C.MD5Size())
	SHA1BlockSize   = int(C.SHA1BlockSize())
	SHA1Size        = int(C.SHA1Size())
	SHA256BlockSize = int(C.SHA256BlockSize())
	SHA256Size      = int(C.SHA256Size())
	SHA384BlockSize = int(C.SHA384BlockSize())
	SHA384Size      = int(C.SHA384Size())
	SHA512BlockSize = int(C.SHA512BlockSize())
	SHA512Size      = int(C.SHA512Size())
)

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

type evpHash struct {
	pinner    runtime.Pinner
	ptr       unsafe.Pointer
	blockSize int
	size      int

	writeFunc func(p0 unsafe.Pointer, p1 *C.uint8_t, p2 C.int)
	sumFunc   func(p0 unsafe.Pointer, p1 *C.uint8_t)
	resetFunc func(p0 unsafe.Pointer)
	cloneFunc func(p0 unsafe.Pointer) (r1 unsafe.Pointer)
	freeFunc  func(p0 unsafe.Pointer)
}

func newEVPHash(ptr unsafe.Pointer, blockSize, size int,
	writeFunc func(p0 unsafe.Pointer, p1 *C.uint8_t, p2 C.int),
	sumFunc func(p0 unsafe.Pointer, p1 *C.uint8_t),
	resetFunc func(p0 unsafe.Pointer),
	cloneFunc func(p0 unsafe.Pointer) (r1 unsafe.Pointer),
	freeFunc func(p0 unsafe.Pointer)) *evpHash {
	h := &evpHash{
		ptr:       ptr,
		blockSize: blockSize,
		size:      size,
		writeFunc: writeFunc,
		sumFunc:   sumFunc,
		resetFunc: resetFunc,
		cloneFunc: cloneFunc,
		freeFunc:  freeFunc,
	}

	runtime.SetFinalizer(h, (*evpHash).finalize)

	return h
}

func (h *evpHash) finalize() {
	if h.ptr != nil {
		h.freeFunc(h.ptr)
		h.ptr = nil
	}
}

func (h *evpHash) Clone() hash.Hash {
	if h.ptr == nil {
		return nil
	}

	newHash := newEVPHash(h.cloneFunc(h.ptr), h.blockSize, h.size, h.writeFunc, h.sumFunc, h.resetFunc, h.cloneFunc, h.freeFunc)

	runtime.KeepAlive(h)

	return newHash
}

func (h *evpHash) Write(p []byte) (int, error) {
	if len(p) > 0 {
		h.pinner.Pin(&p[0])
		defer h.pinner.Unpin()
	}
	h.writeFunc(h.ptr, base(p), C.int(len(p)))

	runtime.KeepAlive(h)

	return len(p), nil
}

func (h *evpHash) WriteString(s string) (int, error) {
	p := []byte(s)
	if len(p) > 0 {
		h.pinner.Pin(&p[0])
		defer h.pinner.Unpin()
	}
	h.writeFunc(h.ptr, base(p), C.int(len(p)))

	runtime.KeepAlive(h)

	return len(s), nil
}

func (h *evpHash) WriteByte(c byte) error {
	h.writeFunc(h.ptr, base([]byte{c}), C.int(1))

	runtime.KeepAlive(h)

	return nil
}

func (h *evpHash) Sum(b []byte) []byte {
	hashSlice := make([]byte, h.size, 64) // explicit cap to allow stack allocation
	h.sumFunc(h.ptr, base(hashSlice))
	runtime.KeepAlive(h)

	b = append(b, hashSlice...)
	return b
}

func (h *evpHash) MarshalBinary() ([]byte, error) {
	return nil, errors.New("cryptokit: hash state is not marshallable")
}

func (h *evpHash) AppendBinary(b []byte) ([]byte, error) {
	return nil, errors.New("cryptokit: hash state is not marshallable")
}

func (h *evpHash) UnmarshalBinary(data []byte) error {
	return errors.New("cryptokit: hash state is not marshallable")
}

func (h *evpHash) Reset() {
	h.resetFunc(h.ptr)
}

func (h *evpHash) BlockSize() int {
	return h.blockSize
}

func (h *evpHash) Size() int {
	return h.size
}

type MD5Hash struct {
	*evpHash
}

func NewMD5() hash.Hash {
	return &MD5Hash{
		evpHash: newEVPHash(
			C.NewMD5(),
			MD5BlockSize,
			MD5Size,
			func(p0 unsafe.Pointer, p1 *C.uint8_t, p2 C.int) {
				C.MD5Write(p0, p1, p2)
			},
			func(p0 unsafe.Pointer, p1 *C.uint8_t) { C.MD5Sum(p0, p1) },
			func(p0 unsafe.Pointer) { C.MD5Reset(p0) },
			func(p0 unsafe.Pointer) (r1 unsafe.Pointer) {
				return C.MD5Copy(p0)
			},
			func(p0 unsafe.Pointer) { C.MD5Free(p0) },
		),
	}
}

type SHA1Hash struct {
	*evpHash
}

// NewSHA1 initializes a new SHA1 hasher.
func NewSHA1() hash.Hash {
	return &SHA1Hash{
		evpHash: newEVPHash(
			C.NewSHA1(),
			SHA1BlockSize,
			SHA1Size,
			func(p0 unsafe.Pointer, p1 *C.uint8_t, p2 C.int) {
				C.SHA1Write(p0, p1, p2)
			},
			func(p0 unsafe.Pointer, p1 *C.uint8_t) { C.SHA1Sum(p0, p1) },
			func(p0 unsafe.Pointer) { C.SHA1Reset(p0) },
			func(p0 unsafe.Pointer) (r1 unsafe.Pointer) {
				return C.SHA1Copy(p0)
			},
			func(p0 unsafe.Pointer) { C.SHA1Free(p0) },
		),
	}
}

type SHA256Hash struct {
	*evpHash
}

// NewSHA256 initializes a new SHA256 hasher.
func NewSHA256() hash.Hash {
	return &SHA256Hash{
		evpHash: newEVPHash(
			C.NewSHA256(),
			SHA256BlockSize,
			SHA256Size,
			func(p0 unsafe.Pointer, p1 *C.uint8_t, p2 C.int) {
				C.SHA256Write(p0, p1, p2)
			},
			func(p0 unsafe.Pointer, p1 *C.uint8_t) { C.SHA256Sum(p0, p1) },
			func(p0 unsafe.Pointer) { C.SHA256Reset(p0) },
			func(p0 unsafe.Pointer) (r1 unsafe.Pointer) {
				return C.SHA256Copy(p0)
			},
			func(p0 unsafe.Pointer) { C.SHA256Free(p0) },
		),
	}
}

type SHA384Hash struct {
	*evpHash
}

// NewSHA384 initializes a new SHA384 hasher.
func NewSHA384() hash.Hash {
	return &SHA384Hash{
		evpHash: newEVPHash(
			C.NewSHA384(),
			SHA384BlockSize,
			SHA384Size,
			func(p0 unsafe.Pointer, p1 *C.uint8_t, p2 C.int) {
				C.SHA384Write(p0, p1, p2)
			},
			func(p0 unsafe.Pointer, p1 *C.uint8_t) { C.SHA384Sum(p0, p1) },
			func(p0 unsafe.Pointer) { C.SHA384Reset(p0) },
			func(p0 unsafe.Pointer) (r1 unsafe.Pointer) {
				return C.SHA384Copy(p0)
			},
			func(p0 unsafe.Pointer) { C.SHA384Free(p0) },
		),
	}
}

type SHA512Hash struct {
	*evpHash
}

// NewSHA512 initializes a new SHA512 hasher.
func NewSHA512() hash.Hash {
	return &SHA512Hash{
		evpHash: newEVPHash(
			C.NewSHA512(),
			SHA512BlockSize,
			SHA512Size,
			func(p0 unsafe.Pointer, p1 *C.uint8_t, p2 C.int) {
				C.SHA512Write(p0, p1, p2)
			},
			func(p0 unsafe.Pointer, p1 *C.uint8_t) { C.SHA512Sum(p0, p1) },
			func(p0 unsafe.Pointer) { C.SHA512Reset(p0) },
			func(p0 unsafe.Pointer) (r1 unsafe.Pointer) {
				return C.SHA512Copy(p0)
			},
			func(p0 unsafe.Pointer) { C.SHA512Free(p0) },
		),
	}
}
