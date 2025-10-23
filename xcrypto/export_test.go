// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto

var CurveToKeySizeInBytes = curveToKeySizeInBytes
var EncodeToUncompressedAnsiX963Key = encodeToUncompressedAnsiX963Key
var ErrOpen = errOpen
var NormalizeBigInt = normalizeBigInt

// MLKEM constants for testing against the stdlib
var (
	SharedKeySizeMLKEM            = sharedKeySizeMLKEM
	SeedSizeMLKEM                 = seedSizeMLKEM
	CiphertextSizeMLKEM768        = ciphertextSizeMLKEM768
	EncapsulationKeySizeMLKEM768  = encapsulationKeySizeMLKEM768
	CiphertextSizeMLKEM1024       = ciphertextSizeMLKEM1024
	EncapsulationKeySizeMLKEM1024 = encapsulationKeySizeMLKEM1024
)
