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

#cgo noescape SHA512
#cgo nocallback SHA512

#cgo noescape SHA512
#cgo nocallback SHA512

#cgo noescape SHA512
#cgo nocallback SHA512

// #cgo noescape MD5Write
// #cgo noescape MD5Sum
// #cgo nocallback NewMD5
// #cgo nocallback MD5Write
// #cgo nocallback MD5Sum
// #cgo nocallback MD5Reset
// #cgo nocallback MD5Size
// #cgo nocallback MD5BlockSize
// #cgo nocallback MD5Copy
// #cgo nocallback MD5Free

// #cgo noescape SHA1Write
// #cgo noescape SHA1Sum
// #cgo nocallback NewSHA1
// #cgo nocallback SHA1Write
// #cgo nocallback SHA1Sum
// #cgo nocallback SHA1Reset
// #cgo nocallback SHA1Size
// #cgo nocallback SHA1BlockSize
// #cgo nocallback SHA1Copy
// #cgo nocallback SHA1Free

// #cgo noescape SHA256Write
// #cgo noescape SHA256Sum
// #cgo nocallback NewSHA256
// #cgo nocallback SHA256Write
// #cgo nocallback SHA256Sum
// #cgo nocallback SHA256Reset
// #cgo nocallback SHA256Size
// #cgo nocallback SHA256BlockSize
// #cgo nocallback SHA256Copy
// #cgo nocallback SHA256Free

// #cgo noescape SHA384Write
// #cgo noescape SHA384Sum
// #cgo nocallback NewSHA384
// #cgo nocallback SHA384Write
// #cgo nocallback SHA384Sum
// #cgo nocallback SHA384Reset
// #cgo nocallback SHA384Size
// #cgo nocallback SHA384BlockSize
// #cgo nocallback SHA384Copy
// #cgo nocallback SHA384Free

// #cgo noescape SHA512Write
// #cgo noescape SHA512Sum
// #cgo nocallback NewSHA512
// #cgo nocallback SHA512Write
// #cgo nocallback SHA512Sum
// #cgo nocallback SHA512Reset
// #cgo nocallback SHA512Size
// #cgo nocallback SHA512BlockSize
// #cgo nocallback SHA512Copy
// #cgo nocallback SHA512Free
*/
import "C"
