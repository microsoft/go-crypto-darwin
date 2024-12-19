// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
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
			_, err := xcrypto.GenerateKeyRSA(size)
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

type PublicKey struct {
	N *big.Int
	E int
}

func bigFromHex(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("bad hex: " + hex)
	}
	return n
}

func fromHex(hexStr string) []byte {
	s, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return s
}

func TestBoringVerify(t *testing.T) {
	encodedKey, err := asn1.Marshal(pkcs1PublicKey{
		Modulus:  bigFromHex("c4fdf7b40a5477f206e6ee278eaef888ca73bf9128a9eef9f2f1ddb8b7b71a4c07cfa241f028a04edb405e4d916c61d6beabc333813dc7b484d2b3c52ee233c6a79b1eea4e9cc51596ba9cd5ac5aeb9df62d86ea051055b79d03f8a4fa9f38386f5bd17529138f3325d46801514ea9047977e0829ed728e68636802796801be1"),
		Exponent: 65537,
	})
	if err != nil {
		t.Fatal(err)
	}

	pub, err := xcrypto.NewPublicKeyRSA(encodedKey)
	if err != nil {
		t.Fatal(err)
	}

	hash := fromHex("019c5571724fb5d0e47a4260c940e9803ba05a44")
	paddedHash := fromHex("3021300906052b0e03021a05000414019c5571724fb5d0e47a4260c940e9803ba05a44")

	// signature is one byte shorter than key.N.
	sig := fromHex("5edfbeb6a73e7225ad3cc52724e2872e04260d7daf0d693c170d8c4b243b8767bc7785763533febc62ec2600c30603c433c095453ede59ff2fcabeb84ce32e0ed9d5cf15ffcbc816202b64370d4d77c1e9077d74e94a16fb4fa2e5bec23a56d7a73cf275f91691ae1801a976fcde09e981a2f6327ac27ea1fecf3185df0d56")

	err = xcrypto.VerifyRSAPKCS1v15(pub, 0, paddedHash, sig)
	if err == nil {
		t.Errorf("raw: expected verification error")
	}

	err = xcrypto.VerifyRSAPKCS1v15(pub, crypto.SHA1, hash, sig)
	if err == nil {
		t.Errorf("sha1: expected verification error")
	}
}

type pkcs1PrivateKey struct {
	Version         int
	Modulus         *big.Int
	PublicExponent  int
	PrivateExponent *big.Int
	Prime1          *big.Int
	Prime2          *big.Int
	Exponent1       *big.Int
	Exponent2       *big.Int
	Coefficient     *big.Int
}

type pkcs1PublicKey struct {
	Modulus  *big.Int
	Exponent int
}

func newRSAKey(t *testing.T, size int) (*xcrypto.PrivateKeyRSA, *xcrypto.PublicKeyRSA) {
	t.Helper()
	privKeyDER, err := xcrypto.GenerateKeyRSA(size)
	if err != nil {
		t.Fatalf("GenerateKeyRSA(%d): %v", size, err)
	}
	var parsedKey pkcs1PrivateKey
	_, err = asn1.Unmarshal(privKeyDER, &parsedKey)
	if err != nil {
		t.Fatalf("asn1.Unmarshal: %v", err)
	}
	// Assign values
	N := parsedKey.Modulus
	E := parsedKey.PublicExponent
	D := parsedKey.PrivateExponent
	P := parsedKey.Prime1
	Q := parsedKey.Prime2
	Dp := parsedKey.Exponent1
	Dq := parsedKey.Exponent2
	Qinv := parsedKey.Coefficient

	pk := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: bbig.Dec(N),
			E: E,
		},
		D:      bbig.Dec(D),
		Primes: []*big.Int{bbig.Dec(P), bbig.Dec(Q)},
		Precomputed: rsa.PrecomputedValues{
			Dp:   bbig.Dec(Dp),
			Dq:   bbig.Dec(Dq),
			Qinv: bbig.Dec(Qinv),
		},
	}
	// Verify the key
	if err := pk.Validate(); err != nil {
		t.Fatalf("rsa.PrivateKey.Validate: %v", err)
	}
	priv, err := xcrypto.NewPrivateKeyRSA(privKeyDER)
	if err != nil {
		t.Fatalf("NewPrivateKeyRSA: %v", err)
	}
	asn1Data, err := asn1.Marshal(pkcs1PublicKey{
		Modulus:  N,
		Exponent: E,
	})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	pub, err := xcrypto.NewPublicKeyRSA(asn1Data)
	if err != nil {
		t.Fatalf("NewPublicKeyRSA: %v", err)
	}
	return priv, pub
}

func BenchmarkEncryptRSAPKCS1(b *testing.B) {
	b.StopTimer()
	// Public key length should be at least of 2048 bits, else OpenSSL will report an error when running in FIPS mode.
	pkey, err := xcrypto.GenerateKeyRSA(2048)
	if err != nil {
		b.Fatal(err)
	}
	var parsedKey pkcs1PrivateKey
	_, err = asn1.Unmarshal(pkey, &parsedKey)
	if err != nil {
		b.Fatalf("asn1.Unmarshal: %v", err)
	}
	encodedKey, err := asn1.Marshal(pkcs1PublicKey{
		Modulus:  parsedKey.Modulus,
		Exponent: parsedKey.PublicExponent,
	})
	if err != nil {
		b.Fatal(err)
	}
	test2048PubKey, err := xcrypto.NewPublicKeyRSA(encodedKey)
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
		_, err := xcrypto.GenerateKeyRSA(2048)
		if err != nil {
			b.Fatal(err)
		}
	}
}
