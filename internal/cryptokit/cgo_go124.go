// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build go1.24 && darwin

package cryptokit

// See xcrypto/cgo_go124.go for context.

/*
#cgo noescape MD5
#cgo nocallback MD5
#cgo noescape SHA1
#cgo nocallback SHA1
#cgo noescape SHA256
#cgo nocallback SHA256
#cgo noescape SHA384
#cgo nocallback SHA384
#cgo noescape SHA512
#cgo nocallback SHA512
*/
import "C"
