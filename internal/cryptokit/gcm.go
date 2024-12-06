// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "cryptokit.h"
import "C"

// EncryptAESGCM performs AES-GCM encryption using Swift.
func EncryptAESGCM(key, plaintext, nonce, additionalData, ciphertext, tag []byte) int {
	err := C.encryptAESGCM(
		base(key), C.size_t(len(key)),
		base(plaintext), C.size_t(len(plaintext)),
		base(nonce), C.size_t(len(nonce)),
		base(additionalData), C.size_t(len(additionalData)),
		base(ciphertext), C.size_t(len(ciphertext)),
		base(tag),
	)
	return int(err)
}

// DecryptAESGCM performs AES-GCM decryption using Swift.
func DecryptAESGCM(key, ciphertext, nonce, additionalData, tag, plaintext []byte) (int, int) {
	var decSize C.size_t
	err := (C.decryptAESGCM(
		base(key), C.size_t(len(key)),
		base(ciphertext), C.size_t(len(ciphertext)),
		base(nonce), C.size_t(len(nonce)),
		base(additionalData), C.size_t(len(additionalData)),
		base(tag), C.size_t(len(tag)),
		base(plaintext), &decSize,
	))
	return int(decSize), int(err)
}
