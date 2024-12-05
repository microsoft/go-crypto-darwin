// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bbig

import (
	"math/big"

	"github.com/microsoft/go-crypto-darwin/commoncrypto"
)

func Enc(b *big.Int) commoncrypto.BigInt {
	// Return the input directly since BigInt is now *big.Int
	return b
}

func Dec(b commoncrypto.BigInt) *big.Int {
	// Return the input directly since BigInt is now *big.Int
	return b
}
