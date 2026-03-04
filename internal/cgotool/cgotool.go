// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package cgotool provides versioned package paths for the cgo code generation tools.
package cgotool

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// openSSLVersion returns the version of github.com/golang-fips/openssl/v2
// pinned in internal/cgotool/openssl/go.mod.
func openSSLVersion() (string, error) {
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("finding module root: %w", err)
	}
	gomodPath := strings.TrimSpace(string(gomod))
	if gomodPath == "" || gomodPath == "/dev/null" {
		return "", fmt.Errorf("finding module root: no go.mod found; run this command within the module")
	}
	toolDir := filepath.Join(filepath.Dir(gomodPath), "internal", "cgotool", "openssl")
	out, err := exec.Command("go", "-C", toolDir, "list", "-m", "-f", "{{.Version}}", "github.com/golang-fips/openssl/v2").Output()
	if err != nil {
		return "", fmt.Errorf("getting openssl version: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// MkcgoPackage returns the versioned package path for the mkcgo tool.
func MkcgoPackage() (string, error) {
	v, err := openSSLVersion()
	if err != nil {
		return "", err
	}
	return "github.com/golang-fips/openssl/v2/cmd/mkcgo@" + v, nil
}

// CheckheaderPackage returns the versioned package path for the checkheader tool.
func CheckheaderPackage() (string, error) {
	v, err := openSSLVersion()
	if err != nil {
		return "", err
	}
	return "github.com/golang-fips/openssl/v2/cmd/checkheader@" + v, nil
}
