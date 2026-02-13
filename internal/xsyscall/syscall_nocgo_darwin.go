// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cgo

package xsyscall

import (
	"unsafe"

	_ "github.com/microsoft/go-crypto-darwin/internal/fakecgo"
)

//go:cgo_import_dynamic _ _ "/usr/lib/libSystem.B.dylib"

func dlsym(handle unsafe.Pointer, symbol string, optional bool) uintptr {
	r0 := Dlsym(handle, unsafe.StringData(symbol))
	if r0 == nil {
		if !optional {
			panic("cannot get required symbol " + symbol)
		}
		return 0
	}
	return uintptr(r0)
}
