// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"math/big"
	"strconv"
	"testing"

	"github.com/microsoft/go-crypto-darwin/bbig"
	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func TestRSAKeyGeneration(t *testing.T) {
	for _, size := range []int{2048, 3072} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			_, _, _, _, _, _, _, _, err := xcrypto.GenerateKeyRSA(size)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testRSAEncryptDecryptPKCS1(t *testing.T, priv *xcrypto.PrivateKeyRSA, pub *xcrypto.PublicKeyRSA) {
	msg := []byte("hi!")
	enc, err := xcrypto.EncryptRSAPKCS1(pub, msg)
	if err != nil {
		t.Fatalf("EncryptPKCS1v15: %v", err)
	}
	dec, err := xcrypto.DecryptRSAPKCS1(priv, enc)
	if err != nil {
		t.Fatalf("DecryptPKCS1v15: %v", err)
	}
	if !bytes.Equal(dec, msg) {
		t.Fatalf("got:%x want:%x", dec, msg)
	}
}

func TestRSAEncryptDecryptPKCS1(t *testing.T) {
	for _, size := range []int{2048, 3072} {
		size := size
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			t.Parallel()
			priv, pub := newRSAKey(t, size)
			testRSAEncryptDecryptPKCS1(t, priv, pub)
		})
	}
}

func TestRSAEncryptDecryptOAEP(t *testing.T) {
	sha256 := xcrypto.NewSHA256()
	msg := []byte("hi!")
	label := []byte("ho!")
	priv, pub := newRSAKey(t, 2048)
	enc, err := xcrypto.EncryptRSAOAEP(sha256, pub, msg, label)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := xcrypto.DecryptRSAOAEP(sha256, priv, enc, label)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("got:%x want:%x", dec, msg)
	}
	sha1 := xcrypto.NewSHA1()
	_, err = xcrypto.DecryptRSAOAEP(sha1, priv, enc, label)
	if err == nil {
		t.Error("decrypt failure expected due to hash mismatch")
	}
}

func TestRSAEncryptDecryptOAEP_EmptyLabel(t *testing.T) {
	sha256 := xcrypto.NewSHA256()
	msg := []byte("hi!")
	label := []byte("")
	priv, pub := newRSAKey(t, 2048)
	enc, err := xcrypto.EncryptRSAOAEP(sha256, pub, msg, label)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := xcrypto.DecryptRSAOAEP(sha256, priv, enc, label)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("got:%x want:%x", dec, msg)
	}
	sha1 := xcrypto.NewSHA1()
	_, err = xcrypto.DecryptRSAOAEP(sha1, priv, enc, label)
	if err == nil {
		t.Error("decrypt failure expected due to hash mismatch")
	}
}

func TestRSAEncryptDecryptOAEP_WrongLabel(t *testing.T) {
	t.Skip("Skipping test as CommonCrypto does not support custom label")
	sha256 := xcrypto.NewSHA256()
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	enc, err := xcrypto.EncryptRSAOAEP(sha256, pub, msg, []byte("ho!"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := xcrypto.DecryptRSAOAEP(sha256, priv, enc, []byte("wrong!"))
	if err == nil {
		t.Errorf("error expected")
	}
	if dec != nil {
		t.Errorf("got:%x want: nil", dec)
	}
}

func TestRSASignVerifyPKCS1v15(t *testing.T) {
	sha256 := xcrypto.NewSHA256()
	priv, pub := newRSAKey(t, 2048)
	msg := []byte("hi!")
	sha256.Write(msg)
	hashed := sha256.Sum(nil)
	signed, err := xcrypto.SignRSAPKCS1v15(priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	err = xcrypto.VerifyRSAPKCS1v15(pub, crypto.SHA256, hashed, signed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRSASignVerifyPKCS1v15_Unhashed(t *testing.T) {
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	signed, err := xcrypto.SignRSAPKCS1v15(priv, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	err = xcrypto.VerifyRSAPKCS1v15(pub, 0, msg, signed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRSASignVerifyPKCS1v15_Invalid(t *testing.T) {
	sha256 := xcrypto.NewSHA256()
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	sha256.Write(msg)
	hashed := sha256.Sum(nil)
	signed, err := xcrypto.SignRSAPKCS1v15(priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	err = xcrypto.VerifyRSAPKCS1v15(pub, crypto.SHA256, msg, signed)
	if err == nil {
		t.Fatal("error expected")
	}
}

func TestRSASignVerifyRSAPSS(t *testing.T) {
	// Test cases taken from
	// https://github.com/golang/go/blob/54182ff54a687272dd7632c3a963e036ce03cb7c/src/crypto/rsa/pss_test.go#L200.
	const keyBits = 2048
	var saltLengthCombinations = []struct {
		signSaltLength, verifySaltLength int
		good                             bool
	}{
		{rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthAuto, true},
		{rsa.PSSSaltLengthEqualsHash, rsa.PSSSaltLengthAuto, true},
		{rsa.PSSSaltLengthEqualsHash, rsa.PSSSaltLengthEqualsHash, true},
		// {rsa.PSSSaltLengthEqualsHash, 8, false}, - Custom Salt length not supported
		// {rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash, false}, - Custom Salt length not supported
		{8, 8, true},
		{rsa.PSSSaltLengthAuto, keyBits/8 - 2 - 32, true}, // simulate Go PSSSaltLengthAuto algorithm (32 = sha256 size)
		// {rsa.PSSSaltLengthAuto, 20, false}, - Custom Salt length not supported
		// {rsa.PSSSaltLengthAuto, -2, false}, - Custom Salt length not supported
	}
	sha256 := xcrypto.NewSHA256()
	priv, pub := newRSAKey(t, keyBits)
	sha256.Write([]byte("testing"))
	hashed := sha256.Sum(nil)
	for i, test := range saltLengthCombinations {
		signed, err := xcrypto.SignRSAPSS(priv, crypto.SHA256, hashed, test.signSaltLength)
		if err != nil {
			t.Errorf("#%d: error while signing: %s", i, err)
			continue
		}
		err = xcrypto.VerifyRSAPSS(pub, crypto.SHA256, hashed, signed, test.verifySaltLength)
		if (err == nil) != test.good {
			t.Errorf("#%d: bad result, wanted: %t, got: %s", i, test.good, err)
		}
	}
}

func newRSAKey(t *testing.T, size int) (*xcrypto.PrivateKeyRSA, *xcrypto.PublicKeyRSA) {
	t.Helper()
	N, E, D, P, Q, Dp, Dq, Qinv, err := xcrypto.GenerateKeyRSA(size)
	if err != nil {
		t.Fatalf("GenerateKeyRSA(%d): %v", size, err)
	}
	return newRSAKeyFromParams(t, N, E, D, P, Q, Dp, Dq, Qinv)
}

func newRSAKeyFromParams(t *testing.T, N, E, D, P, Q, Dp, Dq, Qinv xcrypto.BigInt) (*xcrypto.PrivateKeyRSA, *xcrypto.PublicKeyRSA) {
	t.Helper()
	priv, err := xcrypto.NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		t.Fatalf("NewPrivateKeyRSA: %v", err)
	}
	pub, err := xcrypto.NewPublicKeyRSA(N, E)
	if err != nil {
		t.Fatalf("NewPublicKeyRSA: %v", err)
	}
	return priv, pub
}

func fromBase36(base36 string) *big.Int {
	i, ok := new(big.Int).SetString(base36, 36)
	if !ok {
		panic("bad number: " + base36)
	}
	return i
}

func BenchmarkEncryptRSAPKCS1(b *testing.B) {
	b.StopTimer()
	// Public key length should be at least of 2048 bits, else OpenSSL will report an error when running in FIPS mode.
	n := fromBase36("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557")
	test2048PubKey, err := xcrypto.NewPublicKeyRSA(bbig.Enc(n), bbig.Enc(big.NewInt(3)))
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := xcrypto.EncryptRSAPKCS1(test2048PubKey, []byte("testing")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateKeyRSA(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, _, _, _, err := xcrypto.GenerateKeyRSA(2048)
		if err != nil {
			b.Fatal(err)
		}
	}
}
