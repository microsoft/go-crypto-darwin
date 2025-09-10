// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build cgo && darwin

package cryptokit

//go:generate go run ../../cmd/mkcgo -out zcryptokit.go -mode all -package cryptokit shims.h
//go:generate go run ../../cmd/genswiftimports

// #cgo CFLAGS: -Wno-deprecated-declarations
// #cgo LDFLAGS: -framework Security -framework CoreFoundation -L /Library/Developer/CommandLineTools/usr/lib/swift/macosx
import "C"
