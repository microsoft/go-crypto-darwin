// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !asan

package xcrypto_test

func Asan() bool {
	return false
}
