// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"
import "unsafe"

func MD5(p []byte) (sum [16]byte) {
	ptr := unsafe.Pointer(nil)
	if len(p) > 0 {
		ptr = unsafe.Pointer(&p[0])
	}

	C.MD5(
		(*C.uint8_t)(ptr),
		C.size_t(len(p)),
		(*C.uint8_t)(unsafe.Pointer(&sum[0])))
	return
}

func SHA1(p []byte) (sum [20]byte) {
	ptr := unsafe.Pointer(nil)
	if len(p) > 0 {
		ptr = unsafe.Pointer(&p[0])
	}

	C.SHA1(
		(*C.uint8_t)(ptr),
		C.size_t(len(p)),
		(*C.uint8_t)(unsafe.Pointer(&sum[0])))
	return
}

func SHA256(p []byte) (sum [32]byte) {
	ptr := unsafe.Pointer(nil)
	if len(p) > 0 {
		ptr = unsafe.Pointer(&p[0])
	}

	C.SHA256(
		(*C.uint8_t)(ptr),
		C.size_t(len(p)),
		(*C.uint8_t)(unsafe.Pointer(&sum[0])))
	return
}

func SHA384(p []byte) (sum [48]byte) {
	ptr := unsafe.Pointer(nil)
	if len(p) > 0 {
		ptr = unsafe.Pointer(&p[0])
	}

	C.SHA384(
		(*C.uint8_t)(ptr),
		C.size_t(len(p)),
		(*C.uint8_t)(unsafe.Pointer(&sum[0])))
	return
}

func SHA512(p []byte) (sum [64]byte) {
	ptr := unsafe.Pointer(nil)
	if len(p) > 0 {
		ptr = unsafe.Pointer(&p[0])
	}

	C.SHA512(
		(*C.uint8_t)(ptr),
		C.size_t(len(p)),
		(*C.uint8_t)(unsafe.Pointer(&sum[0])))
	return
}
