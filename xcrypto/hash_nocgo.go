// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// TODO: this file should not exist, we should be using cryptokit for cgo-less hash calls

//go:build !cgo && darwin

package xcrypto

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

type sha1Hash struct {
	hash.Hash
}

type sha256Hash struct {
	hash.Hash
}

type sha384Hash struct {
	hash.Hash
}

type sha512Hash struct {
	hash.Hash
}

func NewSHA1() hash.Hash {
	return sha1Hash{sha1.New()}
}

func NewSHA256() hash.Hash {
	return sha256Hash{sha256.New()}
}

func NewSHA384() hash.Hash {
	return sha384Hash{sha512.New()}
}

func NewSHA512() hash.Hash {
	return sha512Hash{sha512.New()}
}

func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}
