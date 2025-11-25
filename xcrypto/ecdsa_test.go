// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/microsoft/go-crypto-darwin/bbig"
	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

func testAllCurves(t *testing.T, f func(*testing.T, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		// {"P224", elliptic.P224()}, // P224 is not supported by CommonCrypto
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestECDSAKeyGeneration(t *testing.T) {
	testAllCurves(t, testECDSAKeyGeneration)
}

func testECDSAKeyGeneration(t *testing.T, c elliptic.Curve) {
	priv, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func TestECDSASignAndVerify(t *testing.T) {
	testAllCurves(t, testECDSASignAndVerify)
}

func testECDSASignAndVerify(t *testing.T, c elliptic.Curve) {
	key, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hi!")
	hashed := xcrypto.SHA256(msg)

	priv, err := xcrypto.NewPrivateKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y), bbig.Enc(key.D))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := xcrypto.NewPublicKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y))
	if err != nil {
		t.Fatal(err)
	}

	signed, err := xcrypto.SignMarshalECDSA(priv, hashed[:])
	if err != nil {
		t.Fatal(err)
	}

	if !xcrypto.VerifyECDSA(pub, hashed[:], signed) {
		t.Errorf("Verify failed")
	}
	// Alter the signature to intentionally make it invalid. Change the last
	// byte (rather than the first) to avoid corrupting the DER encoding, which
	// would cause some OpenSSL providers, such as SymCrypt-OpenSSL, to write a
	// noisy warning to stderr.
	signed[len(signed)-1] ^= 0xff
	if xcrypto.VerifyECDSA(pub, hashed[:], signed) {
		t.Errorf("Verify succeeded despite intentionally invalid hash!")
	}
}

func generateKeycurve(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	x, y, d, err := xcrypto.GenerateKeyECDSA(c.Params().Name)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: bbig.Dec(x), Y: bbig.Dec(y)}, D: bbig.Dec(d)}, nil
}

// ecdsaSignature represents an ECDSA signature in ASN.1 DER format
type ecdsaSignature struct {
	R, S *big.Int
}

func encodeECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

func decodeECDSASignature(sig []byte) (r, s *big.Int, err error) {
	var ecdsaSig ecdsaSignature
	_, err = asn1.Unmarshal(sig, &ecdsaSig)
	if err != nil {
		return nil, nil, err
	}
	return ecdsaSig.R, ecdsaSig.S, nil
}

func TestECDSAInteropStdlibSign(t *testing.T) {
	testAllCurves(t, testECDSAInteropStdlibSign)
}

func testECDSAInteropStdlibSign(t *testing.T, c elliptic.Curve) {
	// Generate key with xcrypto
	key, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("interoperability test message")
	hashed := xcrypto.SHA256(msg)

	// Sign with standard library
	r, s, err := ecdsa.Sign(xcrypto.RandReader, key, hashed[:])
	if err != nil {
		t.Fatal(err)
	}

	// First, verify with standard library to ensure signature is valid
	if !ecdsa.Verify(&key.PublicKey, hashed[:], r, s) {
		t.Fatal("stdlib failed to verify its own signature - this should not happen")
	}

	// Verify with xcrypto
	pub, err := xcrypto.NewPublicKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y))
	if err != nil {
		t.Fatal(err)
	}

	// Marshal signature in ASN.1 DER format as expected by xcrypto
	sig, err := encodeECDSASignature(r, s)
	if err != nil {
		t.Fatal(err)
	}

	if !xcrypto.VerifyECDSA(pub, hashed[:], sig) {
		t.Errorf("xcrypto failed to verify signature created by stdlib")
		t.Logf("curve: %s, r: %x, s: %x", key.Params().Name, r, s)
		t.Logf("pub.X: %x, pub.Y: %x", key.X, key.Y)
		t.Logf("sig: %x", sig)
	}
}

func TestECDSAInteropStdlibVerify(t *testing.T) {
	testAllCurves(t, testECDSAInteropStdlibVerify)
}

func testECDSAInteropStdlibVerify(t *testing.T, c elliptic.Curve) {
	// Generate key with xcrypto
	key, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("interoperability test message")
	hashed := xcrypto.SHA256(msg)

	// Sign with xcrypto
	priv, err := xcrypto.NewPrivateKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y), bbig.Enc(key.D))
	if err != nil {
		t.Fatal(err)
	}

	signed, err := xcrypto.SignMarshalECDSA(priv, hashed[:])
	if err != nil {
		t.Fatal(err)
	}

	// Decode signature to get r and s
	r, s, err := decodeECDSASignature(signed)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with standard library
	if !ecdsa.Verify(&key.PublicKey, hashed[:], r, s) {
		t.Errorf("stdlib failed to verify signature created by xcrypto")
	}
}

func TestECDSAInteropStdlibKey(t *testing.T) {
	testAllCurves(t, testECDSAInteropStdlibKey)
}

func testECDSAInteropStdlibKey(t *testing.T, c elliptic.Curve) {
	// Generate key with standard library
	key, err := ecdsa.GenerateKey(c, xcrypto.RandReader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("key interoperability test")
	hashed := xcrypto.SHA256(msg)

	// Convert to xcrypto keys
	priv, err := xcrypto.NewPrivateKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y), bbig.Enc(key.D))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := xcrypto.NewPublicKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y))
	if err != nil {
		t.Fatal(err)
	}

	// Sign with xcrypto using stdlib-generated key
	signed, err := xcrypto.SignMarshalECDSA(priv, hashed[:])
	if err != nil {
		t.Fatal(err)
	}

	// Verify with xcrypto
	if !xcrypto.VerifyECDSA(pub, hashed[:], signed) {
		t.Errorf("xcrypto failed to verify its own signature using stdlib-generated key")
	}

	// Also verify with standard library
	r, s, err := decodeECDSASignature(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.Verify(&key.PublicKey, hashed[:], r, s) {
		t.Errorf("stdlib failed to verify xcrypto signature using stdlib-generated key")
	}
}
