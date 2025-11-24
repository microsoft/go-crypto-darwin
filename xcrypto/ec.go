// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

import "errors"

// curveToID maps a curve name to its corresponding CryptoKit curve ID.
func curveToID(curve string) (int32, error) {
	switch curve {
	case "P-256":
		return 1, nil
	case "P-384":
		return 2, nil
	case "P-521":
		return 3, nil
	case "X25519":
		return 0, nil
	default:
		return -1, errors.New("unsupported curve")
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
	case "X25519":
		return 32
	default:
		return 0
	}
}
