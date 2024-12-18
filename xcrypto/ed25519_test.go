// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func TestNewKeyFromSeedEd25519(t *testing.T) {
	seed := bytes.Repeat([]byte{0x01}, ed25519.SeedSize)
	priv, err := xcrypto.NewPrivateKeyEd25519FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	data, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	priv2 := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(data, []byte(priv2)) {
		t.Errorf("private key mismatch got %x want %x", data, priv2)
	}
}

func TestEd25519SignVerify(t *testing.T) {
	private := xcrypto.GenerateKeyEd25519()
	public := private.Public()
	message := []byte("test message")
	sig, err := xcrypto.SignEd25519(private, message)
	if err != nil {
		t.Fatal(err)
	}
	if xcrypto.VerifyEd25519(public, message, sig) != nil {
		t.Errorf("valid signature rejected")
	}
	if ed25519.Verify(ed25519.PublicKey(public), message, sig) != true {
		t.Errorf("valid signature rejected")
	}
	wrongMessage := []byte("wrong message")
	if xcrypto.VerifyEd25519(public, wrongMessage, sig) == nil {
		t.Errorf("signature of different message accepted")
	}
	message = []byte("")
	sig, err = xcrypto.SignEd25519(private, message)
	if err != nil {
		t.Fatal(err)
	}
	if xcrypto.VerifyEd25519(public, message, sig) != nil {
		t.Errorf("valid signature rejected")
	}
}

func TestEd25519Malleability(t *testing.T) {
	// https://tools.ietf.org/html/rfc8032#section-5.1.7 adds an additional test
	// that s be in [0, order). This prevents someone from adding a multiple of
	// order to s and obtaining a second valid signature for the same message.
	msg := []byte{0x54, 0x65, 0x73, 0x74}
	sig := []byte{
		0x7c, 0x38, 0xe0, 0x26, 0xf2, 0x9e, 0x14, 0xaa, 0xbd, 0x05, 0x9a,
		0x0f, 0x2d, 0xb8, 0xb0, 0xcd, 0x78, 0x30, 0x40, 0x60, 0x9a, 0x8b,
		0xe6, 0x84, 0xdb, 0x12, 0xf8, 0x2a, 0x27, 0x77, 0x4a, 0xb0, 0x67,
		0x65, 0x4b, 0xce, 0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f, 0x6f, 0x5d,
		0xaf, 0xc0, 0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57, 0x33,
		0x36, 0xa5, 0xc5, 0x1e, 0xb6, 0xf9, 0x46, 0xb3, 0x1d,
	}
	publicKey := []byte{
		0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5,
		0x22, 0xab, 0xbe, 0xe6, 0x85, 0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34,
		0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36, 0x9e, 0xf5, 0x49, 0xfa,
	}

	pub, err := xcrypto.NewPublicKeyEd25519(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if xcrypto.VerifyEd25519(pub, msg, sig) == nil {
		t.Fatal("non-canonical signature accepted")
	}
}

func BenchmarkEd25519GenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		xcrypto.GenerateKeyEd25519()
	}
}

func BenchmarkEd25519NewKeyFromSeed(b *testing.B) {
	seed := make([]byte, ed25519.SeedSize)
	for i := 0; i < b.N; i++ {
		_, err := xcrypto.NewPrivateKeyEd25519FromSeed(seed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEd25519Signing(b *testing.B) {
	priv := xcrypto.GenerateKeyEd25519()
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xcrypto.SignEd25519(priv, message)
	}
}

func BenchmarkEd25519Verification(b *testing.B) {
	priv := xcrypto.GenerateKeyEd25519()
	pub := priv.Public()
	message := []byte("Hello, world!")
	signature, err := xcrypto.SignEd25519(priv, message)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xcrypto.VerifyEd25519(pub, message, signature)
	}
}
