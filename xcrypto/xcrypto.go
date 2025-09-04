// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import "unsafe"

var zero byte

func pbase(b []byte) unsafe.Pointer {
	return unsafe.Pointer(addr(b))
}

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

// addrNeverEmpty returns the address of the underlying array in b,
// being careful not to panic when b has zero length.
// If b is empty, it returns a pointer to a zero byte
// so that it can always be dereferenced.
func addrNeverEmpty(b []byte) *byte {
	if len(b) == 0 {
		return &zero
	}
	return unsafe.SliceData(b)
}
