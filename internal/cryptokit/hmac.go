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

var _ hash.Hash = (*cryptoKitHMAC)(nil)
var _ cloneHash = (*cryptoKitHMAC)(nil)

type cryptoKitHMAC struct {
	pinner runtime.Pinner
	ptr    unsafe.Pointer

	hashEnum int
	key      []byte

	blockSize int
	size      int
}

func NewHMAC(fh func() hash.Hash, key []byte) hash.Hash {
	h := fh()
	if h == nil {
		return nil
	}

	hashEnum := hashToHMACEnum(h)
	pinner := runtime.Pinner{}

	if len(key) > 0 {
		pinner.Pin(&key[0])
		defer pinner.Unpin()
	}

	hmac := &cryptoKitHMAC{
		pinner: pinner,
		ptr: C.initMAC(
			C.int(hashEnum),
			base(key), C.int(len(key)),
		),
		hashEnum:  hashEnum,
		key:       key,
		blockSize: h.BlockSize(),
		size:      h.Size(),
	}

	runtime.SetFinalizer(h, func(h *cryptoKitHMAC) {
		if h.ptr != nil {
			C.freeHMAC(
				C.int(h.hashEnum),
				h.ptr,
			)
		}
	})

	return hmac
}

func (h *cryptoKitHMAC) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		h.pinner.Pin(&p[0])
		defer h.pinner.Unpin()
	}

	C.updateHMAC(C.int(h.hashEnum),
		h.ptr,
		base(p), C.int(len(p)))

	runtime.KeepAlive(h)

	return len(p), nil
}

func (h *cryptoKitHMAC) Sum(b []byte) []byte {
	hashSlice := make([]byte, h.size, 64) // explicit cap to allow stack allocation
	C.finalizeHMAC(
		C.int(h.hashEnum),
		h.ptr,
		base(b),
	)
	runtime.KeepAlive(h)

	b = append(b, hashSlice...)

	return b
}

func (h *cryptoKitHMAC) MarshalBinary() ([]byte, error) {
	return nil, errors.New("cryptokit: hash state is not marshallable")
}

func (h *cryptoKitHMAC) AppendBinary(b []byte) ([]byte, error) {
	return nil, errors.New("cryptokit: hash state is not marshallable")
}

func (h *cryptoKitHMAC) UnmarshalBinary(data []byte) error {
	return errors.New("cryptokit: hash state is not marshallable")
}

func (h *cryptoKitHMAC) Clone() hash.Hash {
	panic("cryptokit: hash state is not cloneable")
}

func (h *cryptoKitHMAC) Reset() {
	if h.ptr != nil {
		C.freeHMAC(
			C.int(h.hashEnum),
			h.ptr,
		)
	}

	if len(h.key) > 0 {
		h.pinner.Pin(&h.key[0])
		defer h.pinner.Unpin()
	}

	h.ptr = C.initMAC(
		C.int(h.hashEnum),
		base(h.key), C.int(len(h.key)),
	)

	runtime.KeepAlive(h)
}

func (h *cryptoKitHMAC) Size() int {
	return h.size
}

func (h *cryptoKitHMAC) BlockSize() int {
	return h.blockSize
}

func hashToHMACEnum(h hash.Hash) int {
	switch h.(type) {
	case *MD5Hash:
		return 1
	case *SHA1Hash:
		return 2
	case *SHA256Hash:
		return 3
	case *SHA384Hash:
		return 4
	case *SHA512Hash:
		return 5
	default:
		panic("unsupported hash function")
	}
}
