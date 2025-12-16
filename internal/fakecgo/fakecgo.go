// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2022 The Ebitengine Authors

//go:build !cgo && darwin

package fakecgo

import "unsafe"

// argset matches runtime/cgocall.go:argset.
type argset struct {
	args   *uintptr
	retval uintptr
}

//go:nosplit
//go:norace
func (a *argset) arg(i int) unsafe.Pointer {
	// this indirection is to avoid go vet complaining about possible misuse of unsafe.Pointer
	return *(*unsafe.Pointer)(unsafe.Add(unsafe.Pointer(a.args), uintptr(i)*unsafe.Sizeof(uintptr(0))))
}
