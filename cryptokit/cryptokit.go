// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #cgo CFLAGS: -Wno-deprecated-declarations
// #cgo LDFLAGS: -L /Library/Developer/CommandLineTools/usr/lib/swift/macosx ${SRCDIR}/CryptoKit.o
import "C"
import "unsafe"

// base returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
func base(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func sbase(b []byte) *C.char {
	if len(b) == 0 {
		return nil
	}
	return (*C.char)(unsafe.Pointer(&b[0]))
}

func pbase(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}
