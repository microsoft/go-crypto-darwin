// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cgo

package security

import (
	_ "unsafe"
)

//go:linkname syscall_syscallN syscall.syscalln

//go:noescape
func syscall_syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr)

//go:nosplit
func syscallN(_ uintptr, fn uintptr, args ...uintptr) (r1, r2 uintptr) {
	return syscall_syscallN(fn, args...)
}
