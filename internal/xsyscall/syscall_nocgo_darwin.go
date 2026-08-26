// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cgo && (amd64 || arm64)

package xsyscall

import (
	"syscall"
	"unsafe"
)

// The cgo-less backend uses Darwin's runtime-managed libc call path instead of
// runtime.cgocall. Calling runtime.cgocall would require setting runtime.iscgo
// and providing the runtime/cgo initialization, TLS, thread, and callback
// hooks, even though the generated framework calls never call back into Go.
//
// Go's Darwin implementation of syscall.syscall6 enters a syscall, switches to
// the system stack through runtime.libcCall, and preserves scheduler and
// profiler state around the host call. Go 1.26 blocks external linknames to the
// underlying variadic syscall.syscalln, while syscall.syscall6 remains an
// explicit compatibility linkname used by x/sys.
//
// syscall.syscall6 cannot forward an arbitrary number of arguments directly,
// so SyscallN passes it two meaningful values: the address of the
// architecture-specific dispatcher as the function to call and a
// *libcCallInfo as the dispatcher's first argument. The runtime invokes that
// dispatcher with the host ABI. The dispatcher loads the real function and
// arguments from libcCallInfo, places them in host ABI registers and stack
// slots, and calls the foreign function. Its result registers flow back through
// syscall.syscall6 as r1 and r2.
//
// This path supports only integer and pointer-sized arguments and results. It
// does not support floating-point, vector, aggregate, variadic, or callback
// arguments. All called functions must return before their argument storage can
// become unreachable.

//go:linkname syscall_syscall6 syscall.syscall6

//go:noescape
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname noescape
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

// maxSyscallArgs is coupled to the fixed outgoing-argument frames in
// asm_darwin_amd64.s and asm_darwin_arm64.s. Update all three together.
const maxSyscallArgs = 32

type libcCallInfo struct {
	fn   uintptr
	n    uintptr // number of parameters
	args uintptr // parameters
}

var syscallNSystemStack_trampoline byte
var syscallNSystemStackABIInternal = uintptr(unsafe.Pointer(&syscallNSystemStack_trampoline))

// SyscallN calls fn using the host ABI. fn must not call back into Go. The
// errType parameter used by generated wrappers is intentionally ignored because
// these framework calls return errors directly rather than through libc errno.
//
// All its parameters and return values must be uintptr in order
// for the Go compiler to automatically set the //go:uintptrkeepalive
// directive (which we can't set manually here).
// See https://github.com/golang/go/blob/9a5a1202f4c4d5a7048b149b65c3e5b82a2de9aa/src/cmd/compile/internal/escape/call.go#L275.
//
//go:nosplit
func SyscallN(_ uintptr, fn uintptr, args ...uintptr) (r1, r2 uintptr) {
	if len(args) > maxSyscallArgs {
		panic("xsyscall: too many arguments")
	}
	libcArgs := libcCallInfo{
		fn: fn,
		n:  uintptr(len(args)),
	}
	if libcArgs.n != 0 {
		libcArgs.args = uintptr(noescape(unsafe.Pointer(&args[0])))
	}
	r1, r2, _ = syscall_syscall6(syscallNSystemStackABIInternal, uintptr(unsafe.Pointer(&libcArgs)), 0, 0, 0, 0, 0)
	return r1, r2
}

// Shim syscallN calls SyscallN.
//
//go:nosplit
func syscallN(errType uintptr, fn uintptr, args ...uintptr) (r1, r2 uintptr) {
	return SyscallN(errType, fn, args...)
}
