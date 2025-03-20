// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import "runtime"

func MD5(p []byte) (sum [16]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.MD5(
		base(p),
		C.size_t(len(p)),
		base(sum[:]))
	return
}

func SHA1(p []byte) (sum [20]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.SHA1(
		base(p),
		C.size_t(len(p)),
		base(sum[:]))
	return
}

func SHA256(p []byte) (sum [32]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.SHA256(
		base(p),
		C.size_t(len(p)),
		base(sum[:]))
	return
}

func SHA384(p []byte) (sum [48]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.SHA384(
		base(p),
		C.size_t(len(p)),
		base(sum[:]))
	return
}

func SHA512(p []byte) (sum [64]byte) {
	if len(p) > 0 {
		var pinner runtime.Pinner
		pinner.Pin(&p[0])
		defer pinner.Unpin()
	}
	C.SHA512(
		base(p),
		C.size_t(len(p)),
		base(sum[:]))
	return
}
