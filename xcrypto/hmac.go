// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import (
	"hash"
	"runtime"
	"slices"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

var _ hash.Hash = (*cryptoKitHMAC)(nil)
var _ HashCloner = (*cryptoKitHMAC)(nil)

type cryptoKitHMAC struct {
	ptr unsafe.Pointer

	kind int
	key  []byte

	blockSize int
	size      int
}

// NewHMAC returns a new HMAC using xcrypto.
// The function h must return a hash implemented by
// CommonCrypto (for example, h could be xcrypto.NewSHA256).
// If h is not recognized, NewHMAC returns nil.
func NewHMAC(fh func() hash.Hash, key []byte) hash.Hash {
	h := fh()
	if h == nil {
		return nil
	}

	// copying the key here to ensure that it is not modified
	// while this algorithm is using it.
	key = slices.Clone(key)
	kind := hashToHMACEnum(h)
	if kind == 0 {
		// The hash function is not supported by the HMAC implementation.
		return nil
	}

	hmac := &cryptoKitHMAC{
		ptr: cryptokit.InitHMAC(
			int32(kind),
			addr(key), int32(len(key)),
		),
		kind:      kind,
		key:       key,
		blockSize: h.BlockSize(),
		size:      h.Size(),
	}

	runtime.SetFinalizer(hmac, func(h *cryptoKitHMAC) {
		cryptokit.FreeHMAC(
			int32(h.kind),
			h.ptr,
		)
	})

	return hmac
}

func (h *cryptoKitHMAC) Write(p []byte) (n int, err error) {
	cryptokit.UpdateHMAC(int32(h.kind),
		h.ptr,
		addrNeverEmpty(p), int32(len(p)),
	)
	runtime.KeepAlive(h)

	return len(p), nil
}

func (h *cryptoKitHMAC) Sum(b []byte) []byte {
	hashSlice := make([]byte, h.size, 64) // explicit cap to allow stack allocation
	cryptokit.FinalizeHMAC(
		int32(h.kind),
		h.ptr,
		addr(hashSlice),
	)
	runtime.KeepAlive(h)

	b = append(b, hashSlice...)

	return b
}

func (h *cryptoKitHMAC) Clone() (HashCloner, error) {
	if h.ptr == nil {
		panic("cryptokit: hash already finalized")
	}

	hmac := &cryptoKitHMAC{ptr: cryptokit.CopyHMAC(int32(h.kind), h.ptr), kind: h.kind, key: slices.Clone(h.key), blockSize: h.blockSize, size: h.size}

	runtime.KeepAlive(h)

	runtime.SetFinalizer(hmac, func(h *cryptoKitHMAC) {
		cryptokit.FreeHMAC(
			int32(h.kind),
			h.ptr,
		)
	})

	return hmac, nil
}

func (h *cryptoKitHMAC) Reset() {
	cryptokit.FreeHMAC(
		int32(h.kind),
		h.ptr,
	)

	h.ptr = cryptokit.InitHMAC(
		int32(h.kind),
		addrNeverEmpty(h.key), int32(len(h.key)),
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
	case MD5Hash:
		return 1
	case SHA1Hash:
		return 2
	case SHA256Hash:
		return 3
	case SHA384Hash:
		return 4
	case SHA512Hash:
		return 5
	default:
		return 0
	}
}
