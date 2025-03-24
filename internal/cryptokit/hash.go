// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import (
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

type evpHash struct {
	pinner    runtime.Pinner
	ptr       unsafe.Pointer
	blockSize int
	size      int

	writeFunc func(p0 unsafe.Pointer, p1 *_Ctype_uint8_t, p2 _Ctype_int) (r1 _Ctype_int)
	sumFunc   func(p0 unsafe.Pointer, p1 *_Ctype_uint8_t) (r1 _Ctype_int)
	resetFunc func(p0 unsafe.Pointer) (r1 _Ctype_int)
	copyFunc  func(p0 unsafe.Pointer) (r1 unsafe.Pointer)
	freeFunc  func(p0 unsafe.Pointer) (r1 _Ctype_int)
}

func (h *evpHash) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		h.pinner.Pin(&p[0])
		defer h.pinner.Unpin()
	}
	if h.writeFunc(h.ptr, base(p), C.int(len(p))) != 0 {
		return len(p), nil
	}
	return 0, err
}
func (h *evpHash) Reset() {

}

func (h *evpHash) Sum(b []byte) []byte {
	if len(b) < h.size {
		b = make([]byte, h.size)
	}
	if h.sumFunc(h.ptr, base(b)) != 0 {
		return b[:h.size]
	}
	return nil
}

func (h *evpHash) BlockSize() int {
	return h.blockSize
}

func (h *evpHash) Size() int {
	return h.size
}

type md5Hash struct {
	*evpHash
}

func NewMD5() hash.Hash {
	C.NewMD5()
	return &md5Hash{
		evpHash: &evpHash{
			ptr:       C.NewMD5(),
			blockSize: C.MD5BlockSize(),
			size:      C.MD5Size(),
			writeFunc: C.MD5Write,
			sumFunc:   C.MD5Sum,
			resetFunc: C.MD5Reset,
			copyFunc:  C.MD5Copy,
			freeFunc:  C.MD5Free,
		},
	}
}

type sha1Hash struct {
	*evpHash
}

func NewSHA1() hash.Hash {
	return nil
}

type sha256Hash struct {
	*evpHash
}

func NewSHA256() hash.Hash {
	return nil
}

type sha384Hash struct {
	*evpHash
}

func NewSHA384() hash.Hash {
	return nil
}

type sha512Hash struct {
	*evpHash
}

func NewSHA512() hash.Hash {
	return nil
}
