// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import "unsafe"

func SHA1(p []byte) (sum [20]byte) {
	C.SHA1(
		(*C.uint8_t)(unsafe.Pointer(&p[0])),
		C.size_t(len(p)),
		(*C.uint8_t)(unsafe.Pointer(&sum[0])))
	return
}

func SHA256(p []byte) (sum [32]byte) {
	C.SHA256(
		(*C.uint8_t)(unsafe.Pointer(&p[0])),
		C.size_t(len(p)),
		(*C.uint8_t)(unsafe.Pointer(&sum[0])))
	return
}

func SHA384(p []byte) (sum [48]byte) {
	C.SHA384(
		(*C.uint8_t)(unsafe.Pointer(&p[0])),
		C.size_t(len(p)),
		(*C.uint8_t)(unsafe.Pointer(&sum[0])))
	return
}

func SHA512(p []byte) (sum [64]byte) {
	C.SHA512(
		(*C.uint8_t)(unsafe.Pointer(&p[0])),
		C.size_t(len(p)),
		(*C.uint8_t)(unsafe.Pointer(&sum[0])))
	return
}
