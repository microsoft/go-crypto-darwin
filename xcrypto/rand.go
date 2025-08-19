// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build cgo && darwin

package xcrypto

import (
	"errors"
	"unsafe"

	"github.com/microsoft/go-crypto-darwin/internal/security"
)

type randReader int

func (randReader) Read(b []byte) (int, error) {
	// Note: RAND_bytes should never fail; the return value exists only for historical reasons.
	// We check it even so.
	if len(b) == 0 {
		return 0, nil
	}
	if security.SecRandomCopyBytes(security.KSecRandomDefault, len(b), unsafe.Pointer(&b[0])) != 0 {
		return 0, errors.New("crypto/rand: unable to read from source")
	}
	return len(b), nil
}

const RandReader = randReader(0)
