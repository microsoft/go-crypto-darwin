// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin && cgo

package xcrypto

import (
	"crypto"
	"hash"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

// SupportsHash returns true if a hash.Hash implementation is supported for h.
func SupportsHash(h crypto.Hash) bool {
	switch h {
	case crypto.MD5, crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}

func MD5(p []byte) (sum [16]byte) {
	return cryptokit.MD5(p)
}

func SHA1(p []byte) (sum [20]byte) {
	return cryptokit.SHA1(p)
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

// NewMD5 initializes a new MD5 hasher.
func NewMD5() hash.Hash {
	return cryptokit.NewMD5()
}

// NewSHA1 initializes a new SHA1 hasher.
func NewSHA1() hash.Hash {
	return cryptokit.NewSHA1()
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
