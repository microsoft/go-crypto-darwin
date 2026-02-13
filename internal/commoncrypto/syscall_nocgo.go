// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !cgo

package commoncrypto

import (
	"github.com/microsoft/go-crypto-darwin/internal/xsyscall"
)

//go:nosplit
func syscallN(errType uintptr, fn uintptr, args ...uintptr) (r1, r2 uintptr) {
	return xsyscall.SyscallN(errType, fn, args...)
}
