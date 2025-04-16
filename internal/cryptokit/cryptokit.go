// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #cgo CFLAGS: -Wno-deprecated-declarations
// #cgo LDFLAGS: -framework Security -framework CoreFoundation -L /Library/Developer/CommandLineTools/usr/lib/swift/macosx ${SRCDIR}/CryptoKit.o
import "C"
import "unsafe"

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(addr(b)))
}

var zero byte

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
// If b is empty, it returns a pointer to a zero byte
// so that it can always be dereferenced.
func addr(b []byte) *byte {
	if len(b) == 0 {
		return &zero
	}
	return unsafe.SliceData(b)
}
