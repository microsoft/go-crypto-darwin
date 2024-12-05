// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bbig

import (
	"math/big"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func Enc(b *big.Int) xcrypto.BigInt {
	// Return the input directly since BigInt is now *big.Int
	return b
}

func Dec(b xcrypto.BigInt) *big.Int {
	// Return the input directly since BigInt is now *big.Int
	return b
}
