// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cgo && darwin

package commoncrypto

import (
	"syscall"
	"unsafe"
)

// libcCallInfo is a structure used to pass parameters to the system call.
// r1 and r2 capture the two pointer-sized return registers produced by the
// underlying libc/system call. Many ABIs and the Go runtime's syscall
// convention allow a system call to return up to two pointer-sized
// values (r1, r2) plus an errno. We store both return registers here so the
// assembly helper can populate them and Go callers can inspect them.
type libcCallInfo struct {
	fn     uintptr
	n      uintptr // number of parameters
	args   uintptr // parameters
	r1, r2 uintptr // return values
}

// libcCallN is a wrapper around the libc call with variable arguments.
//
//go:nosplit
func syscallN(fn uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	libcArgs := libcCallInfo{
		fn: fn,
		n:  uintptr(len(args)),
	}
	if libcArgs.n != 0 {
		libcArgs.args = uintptr(noescape(unsafe.Pointer(&args[0])))
	}
	entersyscall()
	syscallNRaw(unsafe.Pointer(&libcArgs))
	exitsyscall()
	return libcArgs.r1, libcArgs.r2, 0
}

//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

//go:noescape
func syscallNRaw(args unsafe.Pointer)
