// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"sync"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

const (
	md5     = 1
	sha1    = 2
	sha256  = 3
	sha384  = 4
	sha512  = 5
	sha3256 = 6
	sha3384 = 7
	sha3512 = 8
)

type hashAlgorithm struct {
	id        int32
	ch        crypto.Hash
	size      int
	blockSize int
}

var cacheHash sync.Map // map[crypto.Hash]*hashAlgorithm

// supportsSHA3 returns true if SHA-3 is available on this macOS version.
func supportsSHA3() bool {
	return cryptokit.SupportsSHA3() == 1
}

// loadHash converts a crypto.Hash to a hashAlgorithm.
func loadHash(ch crypto.Hash, required bool) *hashAlgorithm {
	if v, ok := cacheHash.Load(ch); ok {
		if v == nil && required {
			panic("cryptokit: " + ch.String() + " not available")
		}
		return v.(*hashAlgorithm)
	}

	var hash hashAlgorithm
	hash.ch = ch
	supported := true

	switch ch {
	case crypto.MD5:
		hash.id = md5
		hash.size = int(cryptokit.HashSize(md5))
		hash.blockSize = int(cryptokit.HashBlockSize(md5))
	case crypto.SHA1:
		hash.id = sha1
		hash.size = int(cryptokit.HashSize(sha1))
		hash.blockSize = int(cryptokit.HashBlockSize(sha1))
	case crypto.SHA256:
		hash.id = sha256
		hash.size = int(cryptokit.HashSize(sha256))
		hash.blockSize = int(cryptokit.HashBlockSize(sha256))
	case crypto.SHA384:
		hash.id = sha384
		hash.size = int(cryptokit.HashSize(sha384))
		hash.blockSize = int(cryptokit.HashBlockSize(sha384))
	case crypto.SHA512:
		hash.id = sha512
		hash.size = int(cryptokit.HashSize(sha512))
		hash.blockSize = int(cryptokit.HashBlockSize(sha512))
	case crypto.SHA3_256:
		if !supportsSHA3() {
			supported = false
			break
		}
		hash.id = sha3256
		hash.size = int(cryptokit.HashSize(sha3256))
		hash.blockSize = int(cryptokit.HashBlockSize(sha3256))
	case crypto.SHA3_384:
		if !supportsSHA3() {
			supported = false
			break
		}
		hash.id = sha3384
		hash.size = int(cryptokit.HashSize(sha3384))
		hash.blockSize = int(cryptokit.HashBlockSize(sha3384))
	case crypto.SHA3_512:
		if !supportsSHA3() {
			supported = false
			break
		}
		hash.id = sha3512
		hash.size = int(cryptokit.HashSize(sha3512))
		hash.blockSize = int(cryptokit.HashBlockSize(sha3512))
	default:
		supported = false
	}

	if !supported {
		if required {
			panic("cryptokit: " + ch.String() + " not available")
		}
		cacheHash.Store(ch, (*hashAlgorithm)(nil))
		return nil
	}

	cacheHash.Store(ch, &hash)
	return &hash
}

type evpHash struct {
	ptr unsafe.Pointer
	alg *hashAlgorithm
}

// SupportsHash returns true if a hash.Hash implementation is supported for h.
func SupportsHash(h crypto.Hash) bool {
	return loadHash(h, false) != nil
}

func newEVPHash(ch crypto.Hash) *evpHash {
	alg := loadHash(ch, true)

	h := &evpHash{
		ptr: cryptokit.HashNew(alg.id),
		alg: alg,
	}

	runtime.SetFinalizer(h, (*evpHash).finalize)

	return h
}

func (h *evpHash) finalize() {
	if h.ptr != nil {
		cryptokit.HashFree(h.alg.id, h.ptr)
		h.ptr = nil
	}
}

func (h *evpHash) Clone() (HashCloner, error) {
	if h.ptr == nil {
		panic("cryptokit: hash already finalized")
	}

	newHash := &evpHash{
		ptr: cryptokit.HashCopy(h.alg.id, h.ptr),
		alg: h.alg,
	}

	runtime.SetFinalizer(newHash, (*evpHash).finalize)

	runtime.KeepAlive(h)

	return newHash, nil
}

func (h *evpHash) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	cryptokit.HashWrite(h.alg.id, h.ptr, p)

	runtime.KeepAlive(h)

	return len(p), nil
}

func (h *evpHash) WriteString(s string) (int, error) {
	if len(s) == 0 {
		return 0, nil
	}
	cryptokit.HashWrite(h.alg.id, h.ptr, unsafe.Slice(unsafe.StringData(s), len(s)))

	runtime.KeepAlive(h)

	return len(s), nil
}

func (h *evpHash) WriteByte(c byte) error {
	cryptokit.HashWrite(h.alg.id, h.ptr, unsafe.Slice(&c, 1))

	runtime.KeepAlive(h)

	return nil
}

func (h *evpHash) Sum(b []byte) []byte {
	hashSlice := make([]byte, h.alg.size, 64) // explicit cap to allow stack allocation
	cryptokit.HashSum(h.alg.id, h.ptr, hashSlice)
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
	cryptokit.HashReset(h.alg.id, h.ptr)
}

func (h *evpHash) BlockSize() int {
	return h.alg.blockSize
}

func (h *evpHash) Size() int {
	return h.alg.size
}

type DigestSHA3 struct {
	*evpHash
}

var _ hash.Hash = (*evpHash)(nil)
var _ HashCloner = (*evpHash)(nil)
var _ hash.Hash = (*DigestSHA3)(nil)
var _ HashCloner = (*DigestSHA3)(nil)

func MD5(p []byte) (sum [16]byte) {
	cryptokit.MD5(p, sum[:])
	return
}

func SHA1(p []byte) (sum [20]byte) {
	cryptokit.SHA1(p, sum[:])
	return
}

func SHA256(p []byte) (sum [32]byte) {
	cryptokit.SHA256(p, sum[:])
	return
}

func SHA384(p []byte) (sum [48]byte) {
	cryptokit.SHA384(p, sum[:])
	return
}

func SHA512(p []byte) (sum [64]byte) {
	cryptokit.SHA512(p, sum[:])
	return
}

func SumSHA3_256(p []byte) (sum [32]byte) {
	cryptokit.SHA3_256(p, sum[:])
	return
}

func SumSHA3_384(p []byte) (sum [48]byte) {
	cryptokit.SHA3_384(p, sum[:])
	return
}

func SumSHA3_512(p []byte) (sum [64]byte) {
	cryptokit.SHA3_512(p, sum[:])
	return
}

// NewMD5 initializes a new MD5 hasher.
func NewMD5() hash.Hash {
	return newEVPHash(crypto.MD5)

}

// NewSHA1 initializes a new SHA1 hasher.
func NewSHA1() hash.Hash {
	return newEVPHash(crypto.SHA1)
}

// NewSHA256 initializes a new SHA256 hasher.
func NewSHA256() hash.Hash {
	return newEVPHash(crypto.SHA256)
}

// NewSHA384 initializes a new SHA384 hasher.
func NewSHA384() hash.Hash {
	return newEVPHash(crypto.SHA384)
}

// NewSHA512 initializes a new SHA512 hasher.
func NewSHA512() hash.Hash {
	return newEVPHash(crypto.SHA512)
}

// NewSHA3_256 creates a new SHA3-256 hash.
func NewSHA3_256() DigestSHA3 {
	return DigestSHA3{newEVPHash(crypto.SHA3_256)}
}

// NewSHA3_384 creates a new SHA3-384 hash.
func NewSHA3_384() DigestSHA3 {
	return DigestSHA3{newEVPHash(crypto.SHA3_384)}
}

// NewSHA3_512 creates a new SHA3-512 hash.
func NewSHA3_512() DigestSHA3 {
	return DigestSHA3{newEVPHash(crypto.SHA3_512)}
}
