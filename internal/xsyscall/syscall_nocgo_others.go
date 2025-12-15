// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cgo && !(amd64 || arm64)

package xsyscall

// Implement a mock version of SyscallN for unsupported architectures.
// This will simply panic to indicate that the syscall is not supported.

//go:nosplit
func SyscallN(errType uintptr, fn uintptr, args ...uintptr) (r1, r2 uintptr) {
	panic("SyscallN is not supported on this architecture")
}
