// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import "C"
import (
	"hash"

	"github.com/microsoft/go-crypto-darwin/internal/cryptokit"
)

// NewHMAC returns a new HMAC using xcrypto.
// The function h must return a hash implemented by
// CommonCrypto (for example, h could be xcrypto.NewSHA256).
// If h is not recognized, NewHMAC returns nil.
func NewHMAC(fh func() hash.Hash, key []byte) hash.Hash {
	return cryptokit.NewHMAC(fh, key)
}
