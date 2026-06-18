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
var _ hash.Cloner = (*cryptoKitHMAC)(nil)

type cryptoKitHMAC struct {
	ptr unsafe.Pointer

	kind int32
	key  []byte

	blockSize int
	size      int
}

// NewHMAC returns a new HMAC using xcrypto.
// The function fh must return a hash implemented by
// CommonCrypto (for example, [NewSHA256]).
// If fh is not recognized, NewHMAC returns nil.
func NewHMAC[H hash.Hash](fh func() H, key []byte) hash.Hash {
	h, ok := any(fh()).(*Hash)
	if !ok || h == nil {
		return nil
	}

	kind := h.alg.id
	switch kind {
	case md5, sha1, sha256, sha384, sha512, sha3256, sha3384, sha3512:
		// All supported by CryptoKit's HMAC. SHA-3 only reaches this point on
		// macOS 26+, since loadHash refuses to construct a SHA-3 *Hash on older
		// systems, so no extra version check is needed here.
	default:
		// CryptoKit's HMAC only supports MD5, SHA-1, SHA-256, SHA-384, SHA-512,
		// and SHA-3 variants (on macOS 26+). Report any other hash as
		// unsupported so that NewHMAC returns nil and the caller can fall back
		// to a pure Go HMAC.
		return nil
	}

	// copying the key here to ensure that it is not modified
	// while this algorithm is using it.
	key = slices.Clone(key)

	hmac := &cryptoKitHMAC{
		ptr:       cryptokit.InitHMAC(kind, key),
		kind:      kind,
		key:       key,
		blockSize: h.alg.blockSize,
		size:      h.alg.size,
	}

	runtime.SetFinalizer(hmac, func(h *cryptoKitHMAC) {
		cryptokit.FreeHMAC(h.kind, h.ptr)
	})

	return hmac
}

func (h *cryptoKitHMAC) Write(p []byte) (n int, err error) {
	cryptokit.UpdateHMAC(h.kind, h.ptr, p)
	runtime.KeepAlive(h)

	return len(p), nil
}

func (h *cryptoKitHMAC) Sum(b []byte) []byte {
	hashSlice := make([]byte, h.size, 64) // explicit cap to allow stack allocation
	cryptokit.FinalizeHMAC(h.kind, h.ptr, hashSlice)
	runtime.KeepAlive(h)

	b = append(b, hashSlice...)

	return b
}

func (h *cryptoKitHMAC) Clone() (hash.Cloner, error) {
	if h.ptr == nil {
		panic("cryptokit: hash already finalized")
	}

	hmac := &cryptoKitHMAC{ptr: cryptokit.CopyHMAC(h.kind, h.ptr), kind: h.kind, key: slices.Clone(h.key), blockSize: h.blockSize, size: h.size}

	runtime.KeepAlive(h)

	runtime.SetFinalizer(hmac, func(h *cryptoKitHMAC) {
		cryptokit.FreeHMAC(h.kind, h.ptr)
	})

	return hmac, nil
}

func (h *cryptoKitHMAC) Reset() {
	cryptokit.FreeHMAC(h.kind, h.ptr)

	h.ptr = cryptokit.InitHMAC(h.kind, h.key)
	runtime.KeepAlive(h)
}

func (h *cryptoKitHMAC) Size() int {
	return h.size
}

func (h *cryptoKitHMAC) BlockSize() int {
	return h.blockSize
}
