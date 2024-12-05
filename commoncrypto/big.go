// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commoncrypto

import "math/big"

// This file does not have build constraints to
// facilitate using BigInt in Go crypto.
// Go crypto references BigInt unconditionally,
// even if it is not finally used.

// A BigInt is the raw words from a BigInt.
// This definition allows us to avoid importing math/big.
// Conversion between BigInt and *big.Int is in bbig.
type BigInt = *big.Int
