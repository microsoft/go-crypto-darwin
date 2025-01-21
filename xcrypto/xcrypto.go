// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #cgo CFLAGS: -Wno-deprecated-declarations
// #cgo LDFLAGS: -framework Security -framework CoreFoundation
import "C"
import "unsafe"

// noescape hides a pointer from escape analysis. noescape is
// the identity function but escape analysis doesn't think the
// output depends on the input. noescape is inlined and currently
// compiles down to zero instructions.
// USE CAREFULLY!
//
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

var zero byte

// addr converts p to its base addr, including a noescape along the way.
// If p is nil, addr returns a non-nil pointer, so that the result can always
// be dereferenced.
//
//go:nosplit
func addr(p []byte) *byte {
	if len(p) == 0 {
		return &zero
	}
	return (*byte)(noescape(unsafe.Pointer(&p[0])))
}

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
