// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commoncrypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/microsoft/go-crypto-darwin/bbig"
	"github.com/microsoft/go-crypto-darwin/commoncrypto"
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
	hashed := commoncrypto.SHA256(msg)

	priv, err := commoncrypto.NewPrivateKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y), bbig.Enc(key.D))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := commoncrypto.NewPublicKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y))
	if err != nil {
		t.Fatal(err)
	}

	signed, err := commoncrypto.SignMarshalECDSA(priv, hashed[:])
	if err != nil {
		t.Fatal(err)
	}

	if !commoncrypto.VerifyECDSA(pub, hashed[:], signed) {
		t.Errorf("Verify failed")
	}
	// Alter the signature to intentionally make it invalid. Change the last
	// byte (rather than the first) to avoid corrupting the DER encoding, which
	// would cause some OpenSSL providers, such as SymCrypt-OpenSSL, to write a
	// noisy warning to stderr.
	signed[len(signed)-1] ^= 0xff
	if commoncrypto.VerifyECDSA(pub, hashed[:], signed) {
		t.Errorf("Verify succeeded despite intentionally invalid hash!")
	}
}

func generateKeycurve(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	x, y, d, err := commoncrypto.GenerateKeyECDSA(c.Params().Name)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: bbig.Dec(x), Y: bbig.Dec(y)}, D: bbig.Dec(d)}, nil
}
