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

#cgo noescape hashWrite
#cgo noescape hashSum
#cgo nocallback hashNew
#cgo nocallback hashWrite
#cgo nocallback hashSum
#cgo nocallback hashReset
#cgo nocallback hashSize
#cgo nocallback hashBlockSize
#cgo nocallback hashCopy
#cgo nocallback hashFree

#cgo noescape updateHMAC
#cgo noescape finalizeHMAC
#cgo nocallback initHMAC
#cgo nocallback freeHMAC
#cgo nocallback updateHMAC
#cgo nocallback finalizeHMAC
*/
import "C"
