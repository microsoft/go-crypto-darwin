// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cryptokit_test

import (
	"bytes"
	"crypto/cipher"
	"math"
	"testing"

	"github.com/microsoft/go-crypto-darwin/commoncrypto"
	"github.com/microsoft/go-crypto-darwin/cryptokit"
)

var key = []byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D")

const (
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
)

func TestNewGCMNonce(t *testing.T) {
	block, err := commoncrypto.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cryptokit.NewGCM(key, block, gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	if g.NonceSize() != gcmStandardNonceSize {
		t.Errorf("unexpected nonce size\ngot: %#v\nexp: %#v",
			g.NonceSize(), gcmStandardNonceSize)
	}
	if g.Overhead() != gcmTagSize {
		t.Errorf("unexpected tag size\ngot: %#v\nexp: %#v",
			g.Overhead(), gcmTagSize)
	}

	_, err = cryptokit.NewGCM(key, block, gcmStandardNonceSize-1, gcmTagSize-1)
	if err == nil {
		t.Error("expected error for non-standard tag and nonce size at the same time, got none")
	}
	_, err = cryptokit.NewGCM(key, block, gcmStandardNonceSize-1, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for non-standard nonce size with standard tag size, got: %#v", err)
	}
	_, err = cryptokit.NewGCM(key, block, gcmStandardNonceSize, gcmTagSize-1)
	if err != nil {
		t.Errorf("expected no error for standard tag size, got: %#v", err)
	}
	_, err = cryptokit.NewGCM(key, block, gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for standard tag / nonce size, got: %#v", err)
	}
}

func TestSealAndOpen(t *testing.T) {
	for _, tt := range aesGCMTests {
		t.Run(tt.description, func(t *testing.T) {
			ci, err := commoncrypto.NewAESCipher(tt.key)
			if err != nil {
				t.Fatalf("NewAESCipher() err = %v", err)
			}
			gcm, err := cipher.NewGCM(ci)
			if err != nil {
				t.Fatalf("cipher.NewGCM() err = %v", err)
			}

			sealed := gcm.Seal(nil, tt.nonce, tt.plaintext, tt.aad)
			if !bytes.Equal(sealed, tt.ciphertext) {
				t.Errorf("unexpected sealed result\ngot: %#v\nexp: %#v", sealed, tt.ciphertext)
			}

			decrypted, err := gcm.Open(nil, tt.nonce, tt.ciphertext, tt.aad)
			if err != nil {
				t.Errorf("gcm.Open() err = %v", err)
			}
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, tt.plaintext)
			}

			// Test that open fails if the ciphertext is modified.
			tt.ciphertext[0] ^= 0x80
			_, err = gcm.Open(nil, tt.nonce, tt.ciphertext, tt.aad)
			if err != cryptokit.ErrOpen {
				t.Errorf("expected authentication error for tampered message\ngot: %#v", err)
			}
			tt.ciphertext[0] ^= 0x80

			// Test that the ciphertext can be opened using a fresh context
			// which was not previously used to seal the same message.
			gcm, err = cipher.NewGCM(ci)
			if err != nil {
				t.Fatalf("cipher.NewGCM() err = %v", err)
			}
			decrypted, err = gcm.Open(nil, tt.nonce, tt.ciphertext, tt.aad)
			if err != nil {
				t.Errorf("fresh GCM instance: gcm.Open() err = %v", err)
			}
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("fresh GCM instance: unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestSealAndOpen_Empty(t *testing.T) {
	key := []byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D")
	ci, err := commoncrypto.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(ci)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9}
	sealed := gcm.Seal(nil, nonce, []byte{}, []byte{})
	decrypted, err := gcm.Open(nil, nonce, sealed, []byte{})
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, []byte{}) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, []byte{})
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
			ci, err := commoncrypto.NewAESCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			var gcm cipher.AEAD
			switch tt.tls {
			case "1.2":
				gcm, err = commoncrypto.NewGCMTLS(ci)
			case "1.3":
				gcm, err = commoncrypto.NewGCMTLS13(ci)
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
	ci, err := commoncrypto.NewAESCipher(key)
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
	if err == nil {
		t.Errorf("expected authentication error, got: %#v", err)
	}
}

func assertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	f()
}

func TestSealPanic(t *testing.T) {
	ci, err := commoncrypto.NewAESCipher([]byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D"))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(ci)
	if err != nil {
		t.Fatal(err)
	}
	assertPanic(t, func() {
		gcm.Seal(nil, make([]byte, gcm.NonceSize()-1), []byte{0x01, 0x02, 0x03}, nil)
	})
	assertPanic(t, func() {
		gcm.Seal(nil, make([]byte, gcm.NonceSize()), make([]byte, math.MaxInt), nil)
	})
}

func BenchmarkAESGCM_Open(b *testing.B) {
	const length = 64
	const keySize = 128 / 8
	buf := make([]byte, length)

	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	key := make([]byte, keySize)
	var nonce [12]byte
	var ad [13]byte
	c, _ := commoncrypto.NewAESCipher(key)
	aesgcm, _ := cipher.NewGCM(c)
	var out []byte

	ct := aesgcm.Seal(nil, nonce[:], buf, ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ = aesgcm.Open(out[:0], nonce[:], ct, ad[:])
	}
}

func BenchmarkAESGCM_Seal(b *testing.B) {
	const length = 64
	const keySize = 128 / 8
	buf := make([]byte, length)

	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	key := make([]byte, keySize)
	var nonce [12]byte
	var ad [13]byte
	c, _ := commoncrypto.NewAESCipher(key)
	aesgcm, _ := cipher.NewGCM(c)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aesgcm.Seal(out[:0], nonce[:], buf, ad[:])
	}
}
