// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build go1.24 && darwin

package xcrypto

// The following noescape and nocallback directives are used to prevent the Go
// compiler from allocating function parameters on the heap. See
// https://github.com/golang/go/blob/0733682e5ff4cd294f5eccb31cbe87a543147bc6/src/cmd/cgo/doc.go#L439-L461
//
// If possible, write a C wrapper function to optimize a call rather than using
// this feature so the optimization will work for all supported Go versions.
//
// This is just a performance optimization. Only add functions that have been
// observed to benefit from these directives, not every function that is merely
// expected to meet the noescape/nocallback criteria.

/*
#cgo noescape SecRandomCopyBytes
#cgo nocallback SecRandomCopyBytes
#cgo noescape CC_MD4
#cgo nocallback CC_MD4
#cgo noescape CC_SHA224
#cgo nocallback CC_SHA224
*/
import "C"
