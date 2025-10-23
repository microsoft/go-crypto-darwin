// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

type encapsulationKey interface {
	Bytes() []byte
	Encapsulate() ([]byte, []byte)
}

type decapsulationKey[E encapsulationKey] interface {
	Bytes() []byte
	Decapsulate([]byte) ([]byte, error)
	EncapsulationKey() E
}

func TestMLKEMRoundTrip(t *testing.T) {
	if !xcrypto.SupportsMLKEM() {
		t.Skip("ML-KEM not supported on this platform")
	}
	t.Run("768", func(t *testing.T) {
		testRoundTrip(t, xcrypto.GenerateKey768, xcrypto.NewEncapsulationKey768, xcrypto.NewDecapsulationKey768)
	})
	t.Run("1024", func(t *testing.T) {
		testRoundTrip(t, xcrypto.GenerateKey1024, xcrypto.NewEncapsulationKey1024, xcrypto.NewDecapsulationKey1024)
	})
}

func testRoundTrip[E encapsulationKey, D decapsulationKey[E]](
	t *testing.T, generateKey func() (D, error),
	newEncapsulationKey func([]byte) (E, error),
	newDecapsulationKey func([]byte) (D, error)) {
	dk, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	Ke, c := ek.Encapsulate()
	Kd, err := dk.Decapsulate(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke, Kd) {
		t.Fail()
	}

	ek1, err := newEncapsulationKey(ek.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ek.Bytes(), ek1.Bytes()) {
		t.Fail()
	}
	dk1, err := newDecapsulationKey(dk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dk.Bytes(), dk1.Bytes()) {
		t.Fail()
	}
	Ke1, c1 := ek1.Encapsulate()
	Kd1, err := dk1.Decapsulate(c1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke1, Kd1) {
		t.Fail()
	}

	dk2, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dk.EncapsulationKey().Bytes(), dk2.EncapsulationKey().Bytes()) {
		t.Fail()
	}
	if bytes.Equal(dk.Bytes(), dk2.Bytes()) {
		t.Fail()
	}

	Ke2, c2 := dk.EncapsulationKey().Encapsulate()
	if bytes.Equal(c, c2) {
		t.Fail()
	}
	if bytes.Equal(Ke, Ke2) {
		t.Fail()
	}
}

func TestMLKEMBadLengths(t *testing.T) {
	if !xcrypto.SupportsMLKEM() {
		t.Skip("ML-KEM not supported on this platform")
	}
	t.Run("768", func(t *testing.T) {
		testBadLengths(t, xcrypto.GenerateKey768, xcrypto.NewEncapsulationKey768, xcrypto.NewDecapsulationKey768)
	})
	t.Run("1024", func(t *testing.T) {
		testBadLengths(t, xcrypto.GenerateKey1024, xcrypto.NewEncapsulationKey1024, xcrypto.NewDecapsulationKey1024)
	})
}

func testBadLengths[E encapsulationKey, D decapsulationKey[E]](
	t *testing.T, generateKey func() (D, error),
	newEncapsulationKey func([]byte) (E, error),
	newDecapsulationKey func([]byte) (D, error)) {
	dk, err := generateKey()
	dkBytes := dk.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	ekBytes := dk.EncapsulationKey().Bytes()
	_, c := ek.Encapsulate()

	for i := 0; i < len(dkBytes)-1; i++ {
		if _, err := newDecapsulationKey(dkBytes[:i]); err == nil {
			t.Errorf("expected error for dk length %d", i)
		}
	}
	dkLong := dkBytes
	for i := 0; i < 100; i++ {
		dkLong = append(dkLong, 0)
		if _, err := newDecapsulationKey(dkLong); err == nil {
			t.Errorf("expected error for dk length %d", len(dkLong))
		}
	}

	for i := 0; i < len(ekBytes)-1; i++ {
		if _, err := newEncapsulationKey(ekBytes[:i]); err == nil {
			t.Errorf("expected error for ek length %d", i)
		}
	}
	ekLong := ekBytes
	for i := 0; i < 100; i++ {
		ekLong = append(ekLong, 0)
		if _, err := newEncapsulationKey(ekLong); err == nil {
			t.Errorf("expected error for ek length %d", len(ekLong))
		}
	}

	for i := 0; i < len(c)-1; i++ {
		if _, err := dk.Decapsulate(c[:i]); err == nil {
			t.Errorf("expected error for c length %d", i)
		}
	}
	cLong := c
	for i := 0; i < 100; i++ {
		cLong = append(cLong, 0)
		if _, err := dk.Decapsulate(cLong); err == nil {
			t.Errorf("expected error for c length %d", len(cLong))
		}
	}
}

// TestAccumulated accumulates 10k (or 100, or 1M) random vectors and checks the
// hash of the result, to avoid checking in 150MB of test vectors.
// NOTE: This test is skipped for CryptoKit implementation because it relies on
// internal deterministic APIs (EncapsulateInternal) that are not available.
func TestMLKEMAccumulated(t *testing.T) {
	t.Skip("TestMLKEMAccumulated requires deterministic encapsulation (EncapsulateInternal) which is not available in CryptoKit implementation")
}

func BenchmarkMLKEMKeyGen(b *testing.B) {
	if !xcrypto.SupportsMLKEM() {
		b.Skip("ML-KEM not supported on this platform")
	}
	var d, z [32]byte
	rand.Read(d[:])
	rand.Read(z[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dk, err := xcrypto.GenerateKey768()
		if err != nil {
			b.Fatal(err)
		}
		sink ^= dk.EncapsulationKey().Bytes()[0]
	}
}

func BenchmarkMLKEMEncaps(b *testing.B) {
	if !xcrypto.SupportsMLKEM() {
		b.Skip("ML-KEM not supported on this platform")
	}
	seed := make([]byte, xcrypto.SeedSize)
	rand.Read(seed)
	var m [32]byte
	rand.Read(m[:])
	dk, err := xcrypto.NewDecapsulationKey768(seed)
	if err != nil {
		b.Fatal(err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ek, err := xcrypto.NewEncapsulationKey768(ekBytes)
		if err != nil {
			b.Fatal(err)
		}
		K, c := ek.Encapsulate()
		sink ^= c[0] ^ K[0]
	}
}

func BenchmarkMLKEMDecaps(b *testing.B) {
	if !xcrypto.SupportsMLKEM() {
		b.Skip("ML-KEM not supported on this platform")
	}
	dk, err := xcrypto.GenerateKey768()
	if err != nil {
		b.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	_, c := ek.Encapsulate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		K, _ := dk.Decapsulate(c)
		sink ^= K[0]
	}
}

func BenchmarkMLKEMRoundTrip(b *testing.B) {
	if !xcrypto.SupportsMLKEM() {
		b.Skip("ML-KEM not supported on this platform")
	}
	dk, err := xcrypto.GenerateKey768()
	if err != nil {
		b.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	ekBytes := ek.Bytes()
	_, c := ek.Encapsulate()
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Alice", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dkS, err := xcrypto.GenerateKey768()
			if err != nil {
				b.Fatal(err)
			}
			ekS := dkS.EncapsulationKey().Bytes()
			sink ^= ekS[0]

			Ks, err := dk.Decapsulate(c)
			if err != nil {
				b.Fatal(err)
			}
			sink ^= Ks[0]
		}
	})
	b.Run("Bob", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ek, err := xcrypto.NewEncapsulationKey768(ekBytes)
			if err != nil {
				b.Fatal(err)
			}
			Ks, cS := ek.Encapsulate()
			if err != nil {
				b.Fatal(err)
			}
			sink ^= cS[0] ^ Ks[0]
		}
	})
}

// Test that the constants match the ML-KEM specification (NIST FIPS 203).
func TestMLKEMConstantSizes(t *testing.T) {
	if xcrypto.SharedKeySize != 32 {
		t.Errorf("SharedKeySize mismatch: got %d, want %d", xcrypto.SharedKeySize, 32)
	}

	if xcrypto.SeedSize != 64 {
		t.Errorf("SeedSize mismatch: got %d, want %d", xcrypto.SeedSize, 64)
	}

	if xcrypto.CiphertextSize768 != 1088 {
		t.Errorf("CiphertextSize768 mismatch: got %d, want %d", xcrypto.CiphertextSize768, 1088)
	}

	if xcrypto.EncapsulationKeySize768 != 1184 {
		t.Errorf("EncapsulationKeySize768 mismatch: got %d, want %d", xcrypto.EncapsulationKeySize768, 1184)
	}

	if xcrypto.CiphertextSize1024 != 1568 {
		t.Errorf("CiphertextSize1024 mismatch: got %d, want %d", xcrypto.CiphertextSize1024, 1568)
	}

	if xcrypto.EncapsulationKeySize1024 != 1568 {
		t.Errorf("EncapsulationKeySize1024 mismatch: got %d, want %d", xcrypto.EncapsulationKeySize1024, 1568)
	}
}
