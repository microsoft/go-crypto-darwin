// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xcrypto_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/microsoft/go-crypto-darwin/xcrypto"
)

// TestEd25519Vectors runs a very large set of test vectors that exercise all
// combinations of low-order points, low-order components, and non-canonical
// encodings. These vectors lock in unspecified and spec-divergent behaviors in
// edge cases that are not security relevant in most contexts, but that can
// cause issues in consensus applications if changed.
//
// Our behavior matches the "classic" unwritten verification rules of the
// "ref10" reference implementation.
//
// Note that although we test for these edge cases, they are not covered by the
// Go 1 Compatibility Promise. Applications that need stable verification rules
// should use github.com/hdevalence/ed25519consensus.
//
// See https://hdevalence.ca/blog/2020-10-04-its-25519am for more details.
func TestEd25519Vectors(t *testing.T) {
	jsonVectors := downloadEd25519Vectors(t)
	var vectors []struct {
		A, R, S, M string
		Flags      []string
	}
	if err := json.Unmarshal(jsonVectors, &vectors); err != nil {
		t.Fatal(err)
	}
	for i, v := range vectors {
		expectedToVerify := true
		for _, f := range v.Flags {
			switch f {
			// We use the simplified verification formula that doesn't multiply
			// by the cofactor, so any low order residue will cause the
			// signature not to verify.
			//
			// This is allowed, but not required, by RFC 8032.
			case "LowOrderResidue":
				expectedToVerify = false
			// Our point decoding allows non-canonical encodings (in violation
			// of RFC 8032) but R is not decoded: instead, R is recomputed and
			// compared bytewise against the canonical encoding.
			case "NonCanonicalR":
				expectedToVerify = false
			// Not passing with Cryptokit
			case "NonCanonicalA":
				expectedToVerify = !isMacOS14OrAbove()
			}
			if !expectedToVerify {
				break
			}
		}

		publicKey := decodeHex(t, v.A)
		pub, err := xcrypto.NewPublicKeyEd25519(publicKey)
		if err != nil {
			t.Fatalf("#%d: failed to create public key: %v", i, err)
		}
		signature := append(decodeHex(t, v.R), decodeHex(t, v.S)...)
		message := []byte(v.M)

		didVerify := xcrypto.VerifyEd25519(pub, message, signature) == nil
		if didVerify && !expectedToVerify {
			t.Errorf("#%d: vector with flags %s unexpectedly verified", i, v.Flags)
		}
		if !didVerify && expectedToVerify {
			t.Errorf("#%d: vector with flags %s unexpectedly rejected", i, v.Flags)
		}
	}
}

func downloadEd25519Vectors(t *testing.T) []byte {
	// Download the JSON test file from the GOPROXY with `go mod download`,
	// pinning the version so test and module caching works as expected.
	path := "filippo.io/mostly-harmless/ed25519vectors"
	version := "v0.0.0-20210322192420-30a2d7243a94"
	dir := fetchModule(t, path, version)

	jsonVectors, err := os.ReadFile(filepath.Join(dir, "ed25519vectors.json"))
	if err != nil {
		t.Fatalf("failed to read ed25519vectors.json: %v", err)
	}
	return jsonVectors
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Errorf("invalid hex: %v", err)
	}
	return b
}

// fetchModule fetches the module at the given version and returns the directory
// containing its source tree. It skips the test if fetching modules is not
// possible in this environment.
func fetchModule(t *testing.T, module, version string) string {
	goTool := "go"

	// If the default GOMODCACHE doesn't exist, use a temporary directory
	// instead. (For example, run.bash sets GOPATH=/nonexist-gopath.)
	out, err := exec.Command(goTool, "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("%s env GOMODCACHE: %v\n%s", goTool, err, out)
	}
	modcacheOk := false
	if gomodcache := string(bytes.TrimSpace(out)); gomodcache != "" {
		if _, err := os.Stat(gomodcache); err == nil {
			modcacheOk = true
		}
	}
	if !modcacheOk {
		t.Setenv("GOMODCACHE", t.TempDir())
		// Allow t.TempDir() to clean up subdirectories.
		t.Setenv("GOFLAGS", os.Getenv("GOFLAGS")+" -modcacherw")
	}

	t.Logf("fetching %s@%s\n", module, version)

	output, err := exec.Command(goTool, "mod", "download", "-json", module+"@"+version).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to download %s@%s: %s\n%s\n", module, version, err, output)
	}
	var j struct {
		Dir string
	}
	if err := json.Unmarshal(output, &j); err != nil {
		t.Fatalf("failed to parse 'go mod download': %s\n%s\n", err, output)
	}

	return j.Dir
}
