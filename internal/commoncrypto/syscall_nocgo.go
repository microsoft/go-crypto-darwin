// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cgo

package commoncrypto

import (
	"syscall"
	_ "unsafe"
)

//go:linkname syscall_syscallN syscall.syscalln

//go:noescape
func syscall_syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr)

//go:nosplit
func syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	r1, r2 = syscall_syscallN(fn, args...)
	return r1, r2, 0
}
