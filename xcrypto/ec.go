// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

func curveToKeySizeInBits(curve string) int {
	switch curve {
	case "P-256":
		return 256
	case "P-384":
		return 384
	case "P-521":
		return 521
	default:
		return 0
	}
}

func curveToKeySizeInBytes(curve string) int {
	switch curve {
	case "P-256":
		return (256 + 7) / 8
	case "P-384":
		return (384 + 7) / 8
	case "P-521":
		return (521 + 7) / 8
	default:
		return 0
	}
}
