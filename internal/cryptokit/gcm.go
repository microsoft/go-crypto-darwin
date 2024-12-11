// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build darwin

package cryptokit

// #include "CryptoKit.h"
import "C"

// EncryptAESGCM performs AES-GCM encryption using Swift.
func EncryptAESGCM(key, plaintext, nonce, additionalData, ciphertext, tag []byte) int {
	err := C.encryptAESGCM(
		base(key), C.long(len(key)),
		base(plaintext), C.long(len(plaintext)),
		base(nonce), C.long(len(nonce)),
		base(additionalData), C.long(len(additionalData)),
		base(ciphertext), C.long(len(ciphertext)),
		base(tag),
	)
	return int(err)
}

// DecryptAESGCM performs AES-GCM decryption using Swift.
func DecryptAESGCM(key, ciphertext, nonce, additionalData, tag, plaintext []byte) (int, int) {
	var decSize C.long
	err := C.decryptAESGCM(
		base(key), C.long(len(key)),
		base(ciphertext), C.long(len(ciphertext)),
		base(nonce), C.long(len(nonce)),
		base(additionalData), C.long(len(additionalData)),
		base(tag), C.long(len(tag)),
		base(plaintext), &decSize,
	)
	return int(decSize), int(err)
}
