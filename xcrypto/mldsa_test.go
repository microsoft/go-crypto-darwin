// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

type mldsaTestCase struct {
	name string
	seed string
	msg  string
}

type mldsaExternalMuTestCase struct {
	name   string
	params xcrypto.MLDSAParameters
	seed   string
	mu     string
}

var mldsaParameterTests = []struct {
	name   string
	params xcrypto.MLDSAParameters
}{
	{"65", xcrypto.MLDSA65()},
	{"87", xcrypto.MLDSA87()},
}

var mldsaACVPTestCases = []mldsaTestCase{
	// From crypto/internal/fips140/mldsa/mldsa_test.go TestACVPRejectionKATs.
	{"Path/ML-DSA-65/1", "464756A985E5DF03739D95DD309C1ED9C5B04254CC294E7E7EB9B9365EE15117", "491101BBA044DE6E44A63796C33CDA051BB05A60725B87AF4BA9DB940C03AC09"},
	{"Path/ML-DSA-65/2", "235A48DB4CA7916B884F424A8586EFD517E87C64AECEC0FCE9A3CC212BA1522E", "F8CE85CB2EC474FFBF5A3FFAE029CE6F4526B8D597655067F97F438B81071E9B"},
	{"Path/ML-DSA-65/3", "E13131B705A760305FEFFEBFE99082E2691A444BBEFCC3EDF67D909886200207", "CD365512C7E61BBAA130800B37F3BB46AAF1BEEF3742EA8A9010A6DD4576ED0B"},
	{"Path/ML-DSA-65/4", "0A4793E040A4BC0D0F37643D12C1EA1F10648724609936C76E0EC83E37209E92", "6D9C7A795E48D80A892CBF4D4558429787277E3806EB5D0BCE1640EEBBBF9AEC"},
	{"Path/ML-DSA-65/5", "F865B889E5022D54BABC81CA67E7EB39F1AC42F92CF5295C3DA5C9667DB1B924", "047AFAADBE020ED2D766DA85317DEDE80BE550545F0B21E3F555A990F8004258"},
	{"Path/ML-DSA-87/1", "0D58219132746BE077DFE821E9F8FD87857B28AB91D6A567E312A73E2636032C", "3AA49EF72D010AEC19383BA1E83EC2DD3DCC207A96FFCEB9FFA269E3E3D66400"},
	{"Path/ML-DSA-87/2", "146C47AB9F88408EB76A813294D533B29D7E0FDA75DA5A4E7C69EB61EFEEBB78", "82C44F998A8D24F056084D0E80ECFD8434493385A284C69974923C270D397782"},
	{"Path/ML-DSA-87/3", "049D9B0B646A2AC7F50B63CE5E4BFE44C9B87634F4FF6C14C513E388B8A1F808", "FEBC9F8AE159002BE1A11D395959DD7FC20718135690CDAA2BCFB5801C02AB89"},
	{"Path/ML-DSA-87/4", "9823DDDE446A8EA883DAD3AC6477F79839FDC2D2DEF2416BE0A8B71CFBC3F5C6", "F7592C97C1A96A2F4053588F5CDAD4C50BF7C3752709854FA27779B445DD2BA2"},
	{"Path/ML-DSA-87/5", "AE213FE8589B414F53780D8B9B6837179967E13CB474C5AD365C043778D2BC90", "19C1913BA76FF04596BB7CC80FD825A5AEDEF5D5AD61CEDB5203E6D7EDB18877"},
	{"Count/ML-DSA-65/64a", "26B605C78AC762FA1634C6F91DD117C4FBFF7F3A7E7781F0CC83B6281F04AD7F", "C9B07E7DDC0274468F312F5C692A54AC73D1E34D8638E20A2CD3C788F27D4355"},
	{"Count/ML-DSA-65/73", "9191CF381BEE17475C011986EFB6AFB1EFA6997442FD33427353F1DA1AA39FC0", "E616E36E81AA1EC39262109421AE0DDDA5E3B5A8F4A252BCA27AE882538DF618"},
	{"Count/ML-DSA-65/66", "516912C7B90A3DBE009B7478DBCAF0F5C5C9ED9699A20D0CA56CC516E5A444CD", "9247CA75F9456226A0C783DABCC33FF5B4B489575ADED543E74B29B45F9C8EF2"},
	{"Count/ML-DSA-65/65", "D4B841F882D50AB9E590066BAFABA0F0D04D32641C0B978E54CCAA69A6E8D2C4", "175231657B0F3C7065947999467C342064F29BFAEB553E97561407D5560E3AEB"},
	{"Count/ML-DSA-65/64b", "5492EB8D811072C030A30CC66B23A173059EBA0D4868CCB92FBE2510B4A5915F", "33D2753ED87D0003B44C1AF5F72EB931F559C6B4931AF7E249F65D3FA7613295"},
	{"Count/ML-DSA-87/64a", "B5C07ECEFE9E7C3B885FDEF032BDF9F807B4011E2DFE6806C088D2081631C8EB", "D1D5C2D167D6E62906790A5FEDF5A0A754CFAF47E6A11AEB93FB8C41934C31F8"},
	{"Count/ML-DSA-87/65", "E8FC3C9FAD711DDA2946334FBBD331468D6E9AB48EB86DCD03F300A17AEBC5E5", "3B435F7A2CE431C7AB8EAE0991C5DAC610827C99D27803046FBC6C567D6B71F2"},
	{"Count/ML-DSA-87/64b", "151F80886D6CE8C3B428964FE02C40CA0C8EFFA100EE089E54D785344FCCF719", "C628CE94D2AA99AA50CF15B147D4F9A9C62A3D4612152DE0A502C377F472D614"},
	{"Count/ML-DSA-87/64c", "48BEFFB4C97E59E474E1906F39888BE5AE62F6A011C05EF6A6B8D1E54F2171B7", "D2756A8FB4E47F796AF704ED0FC8C6E573D42DFAB443B329F00F8DB2FF12C465"},
	{"Count/ML-DSA-87/69", "FE2DA9DD93A077FCB6452AC88D0A5762EB896BAAAC6CE7D01CB1370BA8322390", "A86B29ADF2300D2636E21D4A350CD18E55A254379C3659A7A95D8734CEC1F005"},
}

var mldsaExternalMuTestCases = []mldsaExternalMuTestCase{
	// From crypto/internal/fips140/mldsa/mldsa_test.go BenchmarkCAST.
	{"CAST/ML-DSA-65", xcrypto.MLDSA65(), "F215BA2280D86F142012FC05FFC04F2C7D22FF5DD7D69AA0EFB081E3A53E9318", "35cdb7dddbed44af4641bac659f46598ed769ea9693fd4ed2152b84c45811d2e66eded1eb20cde1c1f4b82642a330d8e86ac432a2aefaa56cd9b2b5f4affd450"},
}

func TestMLDSARoundTrip(t *testing.T) {
	t.Parallel()
	for _, test := range mldsaParameterTests {
		t.Run(test.name, func(t *testing.T) {
			if !xcrypto.SupportsMLDSA(test.params) {
				t.Skip("ML-DSA not supported on this platform")
			}
			testMLDSARoundTrip(t, test.params)
		})
	}
}

func testMLDSARoundTrip(t *testing.T, params xcrypto.MLDSAParameters) {
	t.Parallel()

	generated1, err := xcrypto.GenerateKeyMLDSA(params)
	if err != nil {
		t.Fatal(err)
	}
	generated2, err := xcrypto.GenerateKeyMLDSA(params)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(generated1.Bytes(), generated2.Bytes()) {
		t.Error("two generated private keys are equal")
	}
	if bytes.Equal(generated1.PublicKey().Bytes(), generated2.PublicKey().Bytes()) {
		t.Error("two generated public keys are equal")
	}

	for _, testCase := range mldsaACVPTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			seed := mldsaFromHexBytes(testCase.seed)
			privateKey, err := xcrypto.NewPrivateKeyMLDSA(params, seed)
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}
			if !bytes.Equal(privateKey.Bytes(), seed) {
				t.Error("private key seed changed")
			}

			publicKey := privateKey.PublicKey()
			publicKeyBytes := publicKey.Bytes()
			if len(publicKeyBytes) != params.PublicKeySize() {
				t.Fatalf("public key length = %d, want %d", len(publicKeyBytes), params.PublicKeySize())
			}
			reparsedPublicKey, err := xcrypto.NewPublicKeyMLDSA(params, publicKeyBytes)
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}
			if !bytes.Equal(reparsedPublicKey.Bytes(), publicKeyBytes) {
				t.Error("reparsed public key changed")
			}

			message := mldsaFromHexBytes(testCase.msg)
			signature, err := privateKey.Sign(message, "")
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(signature) != params.SignatureSize() {
				t.Fatalf("signature length = %d, want %d", len(signature), params.SignatureSize())
			}
			if err := reparsedPublicKey.Verify(message, signature, ""); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			wrongMessage := append([]byte(nil), message...)
			wrongMessage[0] ^= 0x80
			if err := reparsedPublicKey.Verify(wrongMessage, signature, ""); err == nil {
				t.Error("Verify passed on wrong message")
			}

			contextSignature, err := privateKey.Sign(message, "context")
			if err != nil {
				t.Fatalf("Sign with context: %v", err)
			}
			if err := reparsedPublicKey.Verify(message, contextSignature, "context"); err != nil {
				t.Fatalf("Verify with context: %v", err)
			}
			if err := reparsedPublicKey.Verify(message, contextSignature, "wrong context"); err == nil {
				t.Error("Verify passed with wrong context")
			}

			mu := append(mldsaFromHexBytes(testCase.msg), mldsaFromHexBytes(testCase.msg)...)
			externalSignature, err := privateKey.SignExternalMu(mu)
			if err != nil {
				t.Skipf("SignExternalMu: %v", err)
			}
			if len(externalSignature) != params.SignatureSize() {
				t.Fatalf("external signature length = %d, want %d", len(externalSignature), params.SignatureSize())
			}
			if err := reparsedPublicKey.VerifyExternalMu(mu, externalSignature); err != nil {
				t.Fatalf("VerifyExternalMu: %v", err)
			}
			wrongMu := append([]byte(nil), mu...)
			wrongMu[0] ^= 0x80
			if err := reparsedPublicKey.VerifyExternalMu(wrongMu, externalSignature); err == nil {
				t.Error("VerifyExternalMu passed on wrong message")
			}
		})
	}
}

func TestMLDSABadLengths(t *testing.T) {
	t.Parallel()
	for _, test := range mldsaParameterTests {
		t.Run(test.name, func(t *testing.T) {
			if !xcrypto.SupportsMLDSA(test.params) {
				t.Skip("ML-DSA not supported on this platform")
			}
			testMLDSABadLengths(t, test.params)
		})
	}
}

func TestMLDSAExternalMuCASTVectors(t *testing.T) {
	t.Parallel()
	for _, test := range mldsaExternalMuTestCases {
		t.Run(test.name, func(t *testing.T) {
			if !xcrypto.SupportsMLDSA(test.params) {
				t.Skip("ML-DSA not supported on this platform")
			}
			t.Parallel()
			privateKey, err := xcrypto.NewPrivateKeyMLDSA(test.params, mldsaFromHexBytes(test.seed))
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}
			publicKey := privateKey.PublicKey()
			mu := mldsaFromHexBytes(test.mu)

			signature, err := privateKey.SignExternalMu(mu)
			if err != nil {
				t.Skipf("SignExternalMu: %v", err)
			}
			if len(signature) != test.params.SignatureSize() {
				t.Fatalf("signature length = %d, want %d", len(signature), test.params.SignatureSize())
			}
			if err := publicKey.VerifyExternalMu(mu, signature); err != nil {
				t.Fatalf("VerifyExternalMu: %v", err)
			}
			wrongMu := append([]byte(nil), mu...)
			wrongMu[0] ^= 0x80
			if err := publicKey.VerifyExternalMu(wrongMu, signature); err == nil {
				t.Error("VerifyExternalMu passed on wrong message")
			}
		})
	}
}

func testMLDSABadLengths(t *testing.T, params xcrypto.MLDSAParameters) {
	t.Parallel()
	privateKey, err := xcrypto.GenerateKeyMLDSA(params)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBytes := privateKey.Bytes()
	publicKeyBytes := privateKey.PublicKey().Bytes()
	publicKey, err := xcrypto.NewPublicKeyMLDSA(params, publicKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("message")
	signature, err := privateKey.Sign(message, "")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := xcrypto.NewPrivateKeyMLDSA(params, privateKeyBytes[:len(privateKeyBytes)-1]); err == nil {
		t.Error("NewPrivateKey accepted a short seed")
	}
	if _, err := xcrypto.NewPrivateKeyMLDSA(params, append(privateKeyBytes, 0)); err == nil {
		t.Error("NewPrivateKey accepted a long seed")
	}
	if _, err := xcrypto.NewPublicKeyMLDSA(params, publicKeyBytes[:len(publicKeyBytes)-1]); err == nil {
		t.Error("NewPublicKey accepted a short encoding")
	}
	if _, err := xcrypto.NewPublicKeyMLDSA(params, append(publicKeyBytes, 0)); err == nil {
		t.Error("NewPublicKey accepted a long encoding")
	}
	if err := publicKey.Verify(message, signature[:params.SignatureSize()-1], ""); err == nil {
		t.Error("Verify accepted a short signature")
	}
	if err := publicKey.Verify(message, append(signature, 0), ""); err == nil {
		t.Error("Verify accepted a long signature")
	}
	if _, err := privateKey.Sign(message, string(make([]byte, 256))); err == nil {
		t.Error("Sign accepted a long context")
	}
	if _, err := privateKey.SignExternalMu(make([]byte, 63)); err == nil {
		t.Error("SignExternalMu accepted a short mu")
	}
	if err := publicKey.VerifyExternalMu(make([]byte, 63), signature); err == nil {
		t.Error("VerifyExternalMu accepted a short mu")
	}
}

func BenchmarkMLDSAKeyGen(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			if !xcrypto.SupportsMLDSA(test.params) {
				b.Skip("ML-DSA not supported on this platform")
			}
			b.ReportAllocs()
			for b.Loop() {
				privateKey, err := xcrypto.GenerateKeyMLDSA(test.params)
				if err != nil {
					b.Fatal(err)
				}
				sink ^= privateKey.Bytes()[0]
			}
		})
	}
}

func BenchmarkMLDSAPublicKey(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			privateKey := newBenchmarkMLDSAPrivateKey(b, test.params)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				publicKey := privateKey.PublicKey()
				sink ^= publicKey.Bytes()[0]
			}
		})
	}
}

func BenchmarkMLDSASign(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			privateKey := newBenchmarkMLDSAPrivateKey(b, test.params)
			message := []byte("testing")
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				signature, err := privateKey.Sign(message, "")
				if err != nil {
					b.Fatal(err)
				}
				sink ^= signature[0]
			}
		})
	}
}

func BenchmarkMLDSAVerify(b *testing.B) {
	for _, test := range mldsaParameterTests {
		b.Run(test.name, func(b *testing.B) {
			privateKey := newBenchmarkMLDSAPrivateKey(b, test.params)
			publicKey := privateKey.PublicKey()
			message := []byte("testing")
			signature, err := privateKey.Sign(message, "")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := publicKey.Verify(message, signature, ""); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func newBenchmarkMLDSAPrivateKey(b *testing.B, params xcrypto.MLDSAParameters) *xcrypto.PrivateKeyMLDSA {
	b.Helper()
	if !xcrypto.SupportsMLDSA(params) {
		b.Skipf("%s not supported on this platform", params)
	}
	seed := make([]byte, 32)
	privateKey, err := xcrypto.NewPrivateKeyMLDSA(params, seed)
	if err != nil {
		b.Fatal(err)
	}
	return privateKey
}

func mldsaFromHexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
