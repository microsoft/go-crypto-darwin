// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build cgo

package xcrypto_test

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"strings"
	"testing"

	"github.com/microsoft/go-crypto-darwin/internal/cryptotest"
	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

const (
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
)

func TestNewGCMNonce(t *testing.T) {
	ci, err := xcrypto.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	c := ci.(interface {
		NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
	})
	_, err = c.NewGCM(gcmStandardNonceSize-1, gcmTagSize-1)
	if err == nil {
		t.Error("expected error for non-standard tag and nonce size at the same time, got none")
	}
	_, err = c.NewGCM(gcmStandardNonceSize-1, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for non-standard nonce size with standard tag size, got: %#v", err)
	}
	_, err = c.NewGCM(gcmStandardNonceSize, gcmTagSize-1)
	if err != nil {
		t.Errorf("expected no error for standard tag size, got: %#v", err)
	}
	_, err = c.NewGCM(gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for standard tag / nonce size, got: %#v", err)
	}
}

func TestSealAndOpen(t *testing.T) {
	ci, err := xcrypto.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithTagSize(ci, gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9}
	plainText := []byte{0x01, 0x02, 0x03}
	additionalData := []byte{0x05, 0x05, 0x07}
	sealed := gcm.Seal(nil, nonce, plainText, additionalData)
	decrypted, err := gcm.Open(nil, nonce, sealed, additionalData)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
	}
	// Test with no additional data.
	sealed = gcm.Seal(nil, nonce, plainText, []byte{})
	decrypted, err = gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
	}
}

func TestSealAndOpenTLS(t *testing.T) {
	tests := []struct {
		name string
		tls  string
		mask func(n *[12]byte)
	}{
		{"1.2", "1.2", nil},
		{"1.3", "1.3", nil},
		{"1.3_masked", "1.3", func(n *[12]byte) {
			// Arbitrary mask in the high bits.
			n[9] ^= 0x42
			// Mask the very first bit. This makes sure that if Seal doesn't
			// handle the mask, the counter appears to go backwards and panics
			// when it shouldn't.
			n[11] ^= 0x1
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ci, err := xcrypto.NewAESCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			var gcm cipher.AEAD
			switch tt.tls {
			case "1.2":
				gcm, err = xcrypto.NewGCMTLS(ci)
			case "1.3":
				gcm, err = xcrypto.NewGCMTLS13(ci)
			}
			if err != nil {
				t.Fatal(err)
			}
			nonce := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			nonce1 := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
			nonce9 := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
			nonce10 := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}
			nonceMax := [12]byte{0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255}
			if tt.mask != nil {
				for _, m := range []*[12]byte{&nonce, &nonce1, &nonce9, &nonce10, &nonceMax} {
					tt.mask(m)
				}
			}
			plainText := []byte{0x01, 0x02, 0x03}
			var additionalData []byte
			switch tt.tls {
			case "1.2":
				additionalData = make([]byte, 13)
			case "1.3":
				additionalData = []byte{23, 3, 3, 0, 0}
			}
			additionalData[len(additionalData)-2] = byte(len(plainText) >> 8)
			additionalData[len(additionalData)-1] = byte(len(plainText))
			sealed := gcm.Seal(nil, nonce[:], plainText, additionalData)
			assertPanic(t, func() {
				gcm.Seal(nil, nonce[:], plainText, additionalData)
			})
			sealed1 := gcm.Seal(nil, nonce1[:], plainText, additionalData)
			gcm.Seal(nil, nonce10[:], plainText, additionalData)
			assertPanic(t, func() {
				gcm.Seal(nil, nonce9[:], plainText, additionalData)
			})
			assertPanic(t, func() {
				gcm.Seal(nil, nonceMax[:], plainText, additionalData)
			})
			if bytes.Equal(sealed, sealed1) {
				t.Errorf("different nonces should produce different outputs\ngot: %#v\nexp: %#v", sealed, sealed1)
			}
			decrypted, err := gcm.Open(nil, nonce[:], sealed, additionalData)
			if err != nil {
				t.Error(err)
			}
			decrypted1, err := gcm.Open(nil, nonce1[:], sealed1, additionalData)
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(decrypted, plainText) {
				t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
			}
			if !bytes.Equal(decrypted, decrypted1) {
				t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, decrypted1)
			}
		})
	}
}

func TestSealAndOpenAuthenticationError(t *testing.T) {
	ci, err := xcrypto.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithTagSize(ci, gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9}
	plainText := []byte{0x01, 0x02, 0x03}
	additionalData := []byte{0x05, 0x05, 0x07}
	sealed := gcm.Seal(nil, nonce, plainText, additionalData)
	_, err = gcm.Open(nil, nonce, sealed, nil)
	if !strings.Contains(err.Error(), "cipher: message authentication failed") {
		t.Errorf("expected authentication error, got: %#v", err)
	}
}

func TestSealPanic(t *testing.T) {
	ci, err := xcrypto.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithTagSize(ci, gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	assertPanic(t, func() {
		gcm.Seal(nil, make([]byte, gcmStandardNonceSize-1), []byte{0x01, 0x02, 0x03}, nil)
	})
	assertPanic(t, func() {
		// maxInt is implemented as math.MaxInt, but this constant
		// is only available since go1.17.
		// TODO: use math.MaxInt once go1.16 is no longer supported.
		maxInt := int((^uint(0)) >> 1)
		gcm.Seal(nil, make([]byte, gcmStandardNonceSize), make([]byte, maxInt), nil)
	})
}

// Test GCM against the general cipher.AEAD interface tester.
func TestAESGCMAEAD(t *testing.T) {
	minTagSize := 12

	for _, keySize := range []int{128, 192, 256} {
		// Use AES as underlying block cipher at different key sizes for GCM.
		t.Run(fmt.Sprintf("AES-%d", keySize), func(t *testing.T) {
			rng := newRandReader(t)

			key := make([]byte, keySize/8)
			rng.Read(key)

			block, err := xcrypto.NewAESCipher(key)
			if err != nil {
				panic(err)
			}

			// Test GCM with the current AES block with the standard nonce and tag
			// sizes.
			cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCM(block) })

			// Test non-standard tag sizes.
			t.Run("MinTagSize", func(t *testing.T) {
				cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCMWithTagSize(block, minTagSize) })
			})

			// Test non-standard nonce sizes.
			for _, nonceSize := range []int{1, 16, 100} {
				t.Run(fmt.Sprintf("NonceSize-%d", nonceSize), func(t *testing.T) {

					cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCMWithNonceSize(block, nonceSize) })
				})
			}
		})
	}
}
