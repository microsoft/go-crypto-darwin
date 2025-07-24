// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import (
	"errors"
	"fmt"
	"hash"
	"runtime"
	"unsafe"
)

func MD5(p []byte) (sum [16]byte) {
	C.MD5((*C.uint8_t)(&*addrNeverEmpty(p)), C.size_t(len(p)), base(sum[:]))
	return
}

func SHA1(p []byte) (sum [20]byte) {
	C.SHA1((*C.uint8_t)(&*addrNeverEmpty(p)), C.size_t(len(p)), base(sum[:]))
	return
}

func SHA256(p []byte) (sum [32]byte) {
	C.SHA256((*C.uint8_t)(&*addrNeverEmpty(p)), C.size_t(len(p)), base(sum[:]))
	return
}

func SHA384(p []byte) (sum [48]byte) {
	C.SHA384((*C.uint8_t)(&*addrNeverEmpty(p)), C.size_t(len(p)), base(sum[:]))
	return
}

func SHA512(p []byte) (sum [64]byte) {
	C.SHA512((*C.uint8_t)(&*addrNeverEmpty(p)), C.size_t(len(p)), base(sum[:]))
	return
}

const (
	md5    = 1
	sha1   = 2
	sha256 = 3
	sha384 = 4
	sha512 = 5
)

var (
	MD5BlockSize    = int(C.hashBlockSize(md5))
	MD5Size         = int(C.hashSize(md5))
	SHA1BlockSize   = int(C.hashBlockSize(sha1))
	SHA1Size        = int(C.hashSize(sha1))
	SHA256BlockSize = int(C.hashBlockSize(sha256))
	SHA256Size      = int(C.hashSize(sha256))
	SHA384BlockSize = int(C.hashBlockSize(sha384))
	SHA384Size      = int(C.hashSize(sha384))
	SHA512BlockSize = int(C.hashBlockSize(sha512))
	SHA512Size      = int(C.hashSize(sha512))
)

var _ hash.Hash = (*evpHash)(nil)
var _ HashCloner = (*evpHash)(nil)

type evpHash struct {
	ptr           unsafe.Pointer
	hashAlgorithm C.int
	blockSize     int
	size          int
}

func newEVPHash(hashAlgorithm C.int, blockSize, size int) *evpHash {
	h := &evpHash{
		ptr:           C.hashNew(hashAlgorithm),
		hashAlgorithm: hashAlgorithm,
		blockSize:     blockSize,
		size:          size,
	}

	runtime.SetFinalizer(h, (*evpHash).finalize)

	return h
}

func (h *evpHash) finalize() {
	if h.ptr != nil {
		C.hashFree(h.hashAlgorithm, h.ptr)
		h.ptr = nil
	}
}

func (h *evpHash) Clone() (HashCloner, error) {
	if h.ptr == nil {
		panic("cryptokit: hash already finalized")
	}

	newHash := &evpHash{
		ptr:           C.hashCopy(h.hashAlgorithm, h.ptr),
		hashAlgorithm: h.hashAlgorithm,
		blockSize:     h.blockSize,
		size:          h.size,
	}

	runtime.SetFinalizer(newHash, (*evpHash).finalize)

	runtime.KeepAlive(h)

	return newHash, nil
}

func (h *evpHash) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	C.hashWrite(h.hashAlgorithm, h.ptr, (*C.uint8_t)(&*addrNeverEmpty(p)), C.int(len(p)))

	runtime.KeepAlive(h)

	return len(p), nil
}

func (h *evpHash) WriteString(s string) (int, error) {
	if len(s) == 0 {
		return 0, nil
	}
	C.hashWrite(h.hashAlgorithm, h.ptr, (*C.uchar)(unsafe.Pointer(unsafe.StringData(s))), C.int(len(s)))

	runtime.KeepAlive(h)

	return len(s), nil
}

func (h *evpHash) WriteByte(c byte) error {
	C.hashWrite(h.hashAlgorithm, h.ptr, base([]byte{c}), 1)

	runtime.KeepAlive(h)

	return nil
}

func (h *evpHash) Sum(b []byte) []byte {
	hashSlice := make([]byte, h.size, 64) // explicit cap to allow stack allocation
	C.hashSum(h.hashAlgorithm, h.ptr, base(hashSlice))
	runtime.KeepAlive(h)

	b = append(b, hashSlice...)
	return b
}

func (h *evpHash) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("cryptokit: hash state is not marshallable: %w", errors.ErrUnsupported)
}

func (h *evpHash) AppendBinary(b []byte) ([]byte, error) {
	return nil, fmt.Errorf("cryptokit: hash state is not marshallable: %w", errors.ErrUnsupported)
}

func (h *evpHash) UnmarshalBinary(data []byte) error {
	return fmt.Errorf("cryptokit: hash state is not marshallable: %w", errors.ErrUnsupported)
}

func (h *evpHash) Reset() {
	C.hashReset(h.hashAlgorithm, h.ptr)
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
	return MD5Hash{
		evpHash: newEVPHash(
			C.int(md5),
			MD5BlockSize,
			MD5Size,
		),
	}
}

type SHA1Hash struct {
	*evpHash
}

// NewSHA1 initializes a new SHA1 hasher.
func NewSHA1() hash.Hash {
	return SHA1Hash{
		evpHash: newEVPHash(
			sha1,
			SHA1BlockSize,
			SHA1Size,
		),
	}
}

type SHA256Hash struct {
	*evpHash
}

// NewSHA256 initializes a new SHA256 hasher.
func NewSHA256() hash.Hash {
	return SHA256Hash{
		evpHash: newEVPHash(
			sha256,
			SHA256BlockSize,
			SHA256Size,
		),
	}
}

type SHA384Hash struct {
	*evpHash
}

// NewSHA384 initializes a new SHA384 hasher.
func NewSHA384() hash.Hash {
	return SHA384Hash{
		evpHash: newEVPHash(
			sha384,
			SHA384BlockSize,
			SHA384Size,
		),
	}
}

type SHA512Hash struct {
	*evpHash
}

// NewSHA512 initializes a new SHA512 hasher.
func NewSHA512() hash.Hash {
	return SHA512Hash{
		evpHash: newEVPHash(
			sha512,
			SHA512BlockSize,
			SHA512Size,
		),
	}
}
