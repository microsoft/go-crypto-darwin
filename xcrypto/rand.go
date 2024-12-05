// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package xcrypto

// #include <Security/SecRandom.h>
import "C"
import (
	"errors"
	"unsafe"
)

type randReader int

func (randReader) Read(b []byte) (int, error) {
	// Note: RAND_bytes should never fail; the return value exists only for historical reasons.
	// We check it even so.
	if len(b) > 0 && C.SecRandomCopyBytes(C.kSecRandomDefault, C.size_t(len(b)), unsafe.Pointer(&b[0])) != 0 {
		return 0, errors.New("crypto/rand: unable to read from source")
	}
	return len(b), nil
}

const RandReader = randReader(0)
