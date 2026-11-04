package importcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const checker = "github.com/microsoft/go-infra/cmd/check-imports@v0.0.12"

func TestBackendImportsAllowed(t *testing.T) {
	runChecker(t,
		"-pkg", "./internal/xsyscall", "-allow", "syscall,unsafe",
		"-pkg", "./internal/commoncrypto", "-allow", "runtime,unsafe",
		"-pkg", "./internal/cryptokit", "-allow", "runtime,unsafe",
		"-pkg", "./internal/security", "-allow", "runtime,unsafe",
		"-pkg", "./bbig", "-allow", "math/big",
		"-pkg", "./xcrypto",
	)
}

func TestCheckerRejectsDisallowedImport(t *testing.T) {
	output := runCheckerExpectError(t, "-pkg", "./bbig", "-allow", "")
	if !strings.Contains(string(output), "FAIL: ./bbig imports disallowed package: math/big") {
		t.Fatalf("checker did not report the forbidden import:\n%s", output)
	}
}

func runChecker(t *testing.T, args ...string) {
	t.Helper()
	output, err := runCheckerCommand(args...)
	if err != nil {
		t.Fatalf("checker failed: %v\n%s", err, output)
	}
}

func runCheckerExpectError(t *testing.T, args ...string) []byte {
	t.Helper()
	output, err := runCheckerCommand(args...)
	if err == nil {
		t.Fatalf("checker unexpectedly accepted the imports:\n%s", output)
	}
	return output
}

func runCheckerCommand(args ...string) ([]byte, error) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, os.ErrNotExist
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(testFile), "../.."))
	commandArgs := append([]string{"run", checker}, args...)
	cmd := exec.Command("go", commandArgs...)
	cmd.Dir = repoRoot
	cmd.Env = withEnv(os.Environ(), "CGO_ENABLED", "0")
	return cmd.CombinedOutput()
}

func withEnv(env []string, name, value string) []string {
	prefix := name + "="
	filtered := env[:0]
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, prefix+value)
}
