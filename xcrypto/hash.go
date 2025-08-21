// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin && cgo

package xcrypto

import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

const (
	md5    = 1
	sha1   = 2
	sha256 = 3
	sha384 = 4
	sha512 = 5
)

var (
	MD5BlockSize    = int(cryptokit.HashBlockSize(md5))
	MD5Size         = int(cryptokit.HashSize(md5))
	SHA1BlockSize   = int(cryptokit.HashBlockSize(sha1))
	SHA1Size        = int(cryptokit.HashSize(sha1))
	SHA256BlockSize = int(cryptokit.HashBlockSize(sha256))
	SHA256Size      = int(cryptokit.HashSize(sha256))
	SHA384BlockSize = int(cryptokit.HashBlockSize(sha384))
	SHA384Size      = int(cryptokit.HashSize(sha384))
	SHA512BlockSize = int(cryptokit.HashBlockSize(sha512))
	SHA512Size      = int(cryptokit.HashSize(sha512))
)

type evpHash struct {
	ptr           unsafe.Pointer
	hashAlgorithm int32
	blockSize     int
	size          int
}

// SupportsHash returns true if a hash.Hash implementation is supported for h.
func SupportsHash(h crypto.Hash) bool {
	switch h {
	case crypto.MD5, crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}

func newEVPHash(hashAlgorithm int32, blockSize, size int) *evpHash {
	h := &evpHash{
		ptr:           cryptokit.HashNew(hashAlgorithm),
		hashAlgorithm: hashAlgorithm,
		blockSize:     blockSize,
		size:          size,
	}

	runtime.SetFinalizer(h, (*evpHash).finalize)

	return h
}

func (h *evpHash) finalize() {
	if h.ptr != nil {
		cryptokit.HashFree(h.hashAlgorithm, h.ptr)
		h.ptr = nil
	}
}

func (h *evpHash) Clone() (HashCloner, error) {
	if h.ptr == nil {
		panic("cryptokit: hash already finalized")
	}

	newHash := &evpHash{
		ptr:           cryptokit.HashCopy(h.hashAlgorithm, h.ptr),
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
	cryptokit.HashWrite(h.hashAlgorithm, h.ptr, addrNeverEmpty(p), int32(len(p)))

	runtime.KeepAlive(h)

	return len(p), nil
}

func (h *evpHash) WriteString(s string) (int, error) {
	if len(s) == 0 {
		return 0, nil
	}
	cryptokit.HashWrite(h.hashAlgorithm, h.ptr, addrNeverEmpty([]byte(s)), int32(len(s)))

	runtime.KeepAlive(h)

	return len(s), nil
}

func (h *evpHash) WriteByte(c byte) error {
	cryptokit.HashWrite(h.hashAlgorithm, h.ptr, addr([]byte{c}), 1)

	runtime.KeepAlive(h)

	return nil
}

func (h *evpHash) Sum(b []byte) []byte {
	hashSlice := make([]byte, h.size, 64) // explicit cap to allow stack allocation
	cryptokit.HashSum(h.hashAlgorithm, h.ptr, addr(hashSlice))
	runtime.KeepAlive(h)
	b = append(b, hashSlice...)
	return b
}

type errMarshallUnsupported struct{}

func (e errMarshallUnsupported) Error() string {
	return "cryptokit: hash state is not marshallable"
}

func (e errMarshallUnsupported) Unwrap() error {
	return errors.ErrUnsupported
}

func (h *evpHash) MarshalBinary() ([]byte, error) {
	return nil, errMarshallUnsupported{}
}

func (h *evpHash) AppendBinary(b []byte) ([]byte, error) {
	return nil, errMarshallUnsupported{}
}

func (h *evpHash) UnmarshalBinary(data []byte) error {
	return errMarshallUnsupported{}
}

func (h *evpHash) Reset() {
	cryptokit.HashReset(h.hashAlgorithm, h.ptr)
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

type SHA1Hash struct {
	*evpHash
}

type SHA256Hash struct {
	*evpHash
}

type SHA384Hash struct {
	*evpHash
}

type SHA512Hash struct {
	*evpHash
}

var _ hash.Hash = (*evpHash)(nil)
var _ HashCloner = (*evpHash)(nil)

func MD5(p []byte) (sum [16]byte) {
	cryptokit.MD5(addr(p), len(p), addr(sum[:]))
	return
}

func SHA1(p []byte) (sum [20]byte) {
	cryptokit.SHA1(addr(p), len(p), addr(sum[:]))
	return
}

func SHA256(p []byte) (sum [32]byte) {
	cryptokit.SHA256(addr(p), len(p), addr(sum[:]))
	return
}

func SHA384(p []byte) (sum [48]byte) {
	cryptokit.SHA384(addr(p), len(p), addr(sum[:]))
	return
}

func SHA512(p []byte) (sum [64]byte) {
	cryptokit.SHA512(addr(p), len(p), addr(sum[:]))
	return
}

// NewMD5 initializes a new MD5 hasher.
func NewMD5() hash.Hash {
	return MD5Hash{
		evpHash: newEVPHash(
			int32(md5),
			MD5BlockSize,
			MD5Size,
		),
	}
}

// NewSHA1 initializes a new SHA1 hasher.
func NewSHA1() hash.Hash {
	return SHA1Hash{
		evpHash: newEVPHash(
			int32(sha1),
			SHA1BlockSize,
			SHA1Size,
		),
	}
}

// NewSHA256 initializes a new SHA256 hasher.
func NewSHA256() hash.Hash {
	return SHA256Hash{
		evpHash: newEVPHash(
			int32(sha256),
			SHA256BlockSize,
			SHA256Size,
		),
	}
}

// NewSHA384 initializes a new SHA384 hasher.
func NewSHA384() hash.Hash {
	return SHA384Hash{
		evpHash: newEVPHash(
			int32(sha384),
			SHA384BlockSize,
			SHA384Size,
		),
	}
}

// NewSHA512 initializes a new SHA512 hasher.
func NewSHA512() hash.Hash {
	return SHA512Hash{
		evpHash: newEVPHash(
			int32(sha512),
			SHA512BlockSize,
			SHA512Size,
		),
	}
}
