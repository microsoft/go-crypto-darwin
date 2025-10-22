// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cgo

package security

import (
	"syscall"
	_ "unsafe"
)

//go:linkname syscall_syscallN syscall.syscalln
//go:linkname entersyscall runtime.entersyscall
//go:linkname exitsyscall runtime.exitsyscall

//go:noescape
func syscall_syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr)
func entersyscall()
func exitsyscall()

//go:nosplit
func syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	entersyscall()
	r1, r2 = syscall_syscallN(fn, args...)
	exitsyscall()
	return r1, r2, 0
}
