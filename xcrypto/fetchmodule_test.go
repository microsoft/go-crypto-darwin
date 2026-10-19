// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package xcrypto_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestFetchModuleRetries(t *testing.T) {
	const testDirEnv = "GO_CRYPTO_DARWIN_FETCH_MODULE_TEST_DIR"
	if dir := os.Getenv(testDirEnv); dir != "" {
		got := fetchModule(t, "example.com/test-vectors", "v1.0.0")
		if want := filepath.Join(dir, "cache"); got != want {
			t.Fatalf("fetchModule returned %q, want %q", got, want)
		}
		return
	}

	for _, tt := range []struct {
		name         string
		failures     int
		wantAttempts string
		wantFailure  bool
	}{
		{"first-attempt", 0, "1\n", false},
		{"transient-failures", 2, "3\n", false},
		{"persistent-failures", 3, "3\n", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "cache"), 0700); err != nil {
				t.Fatal(err)
			}
			const script = `#!/bin/sh
dir="$GO_CRYPTO_DARWIN_FETCH_MODULE_TEST_DIR"
case "$1:$2" in
env:GOMODCACHE)
	printf '%s\n' "$dir/cache"
	;;
mod:download)
	attempts=0
	if [ -f "$dir/attempts" ]; then
		read -r attempts < "$dir/attempts"
	fi
	attempts=$((attempts + 1))
	printf '%s\n' "$attempts" > "$dir/attempts"
	if [ "$attempts" -le "$GO_CRYPTO_DARWIN_FETCH_MODULE_FAILURES" ]; then
		echo 'simulated download failure' >&2
		exit 1
	fi
	printf '{"Dir":"%s"}\n' "$dir/cache"
	;;
*)
	echo 'unexpected go command' >&2
	exit 1
	;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(os.Args[0], "-test.run=^TestFetchModuleRetries$", "-test.v")
			cmd.Env = append(os.Environ(),
				testDirEnv+"="+dir,
				"GO_CRYPTO_DARWIN_FETCH_MODULE_FAILURES="+strconv.Itoa(tt.failures),
				"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
			)
			output, err := cmd.CombinedOutput()
			if tt.wantFailure {
				if _, ok := err.(*exec.ExitError); !ok {
					t.Fatalf("expected test process to fail, got %v\n%s", err, output)
				}
				if !bytes.Contains(output, []byte("failed to download example.com/test-vectors@v1.0.0 after 3 attempts")) {
					t.Fatalf("missing final download error:\n%s", output)
				}
			} else if err != nil {
				t.Fatalf("test process failed: %v\n%s", err, output)
			}

			attempts, err := os.ReadFile(filepath.Join(dir, "attempts"))
			if err != nil {
				t.Fatal(err)
			}
			if string(attempts) != tt.wantAttempts {
				t.Fatalf("download attempts = %q, want %q\n%s", attempts, tt.wantAttempts, output)
			}
		})
	}
}
