// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build cgo && darwin

package cryptokit

// #cgo CFLAGS: -Wno-deprecated-declarations
// #cgo LDFLAGS: -framework Security -framework CoreFoundation
import "C"
