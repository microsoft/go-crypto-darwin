// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build cgo && darwin

package cryptokit

//go:generate go run ../../cmd/mkcgo -out zcryptokit.go -mode all -package cryptokit shims.h
// TODO replace this path with go once upstream CLs are merged
//go:generate /Users/gadams/go/bin/go run ../../cmd/genswiftimports -go /Users/gadams/go/bin/go

// #cgo CFLAGS: -Wno-deprecated-declarations
// #cgo LDFLAGS: -framework Security -framework CoreFoundation -L /Library/Developer/CommandLineTools/usr/lib/swift/macosx
import "C"
