// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bbig

import (
	"math/big"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func Enc(b *big.Int) xcrypto.BigInt {
	if b == nil {
		return nil
	}
	x := b.Bytes()
	if len(x) == 0 {
		return xcrypto.BigInt{}
	}
	return x
}

func Dec(b xcrypto.BigInt) *big.Int {
	if b == nil {
		return nil
	}
	if len(b) == 0 {
		return new(big.Int)
	}
	return new(big.Int).SetBytes(b)
}
