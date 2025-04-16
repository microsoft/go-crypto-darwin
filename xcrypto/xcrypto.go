// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #cgo CFLAGS: -Wno-deprecated-declarations
// #cgo LDFLAGS: -framework Security -framework CoreFoundation
import "C"
import "unsafe"

var zero byte

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(addr(b)))
}

func sbase(b []byte) *C.char {
	return (*C.char)(unsafe.Pointer(addr(b)))
}

func pbase(b []byte) unsafe.Pointer {
	return unsafe.Pointer(addr(b))
}

func addr(b []byte) *byte {
	return unsafe.SliceData(b)
}
