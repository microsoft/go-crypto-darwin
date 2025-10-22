// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	if runtime.GOOS != "darwin" {
		// This tool only works on macOS
		return
	}

	// Intercept and modify the shims file
	modifiedPath, err := modifyShimsFile(os.Args[1])
	if err != nil {
		log.Fatalf("failed to modify shims file: %v", err)
	}

	// Clean up temp file when done
	defer os.Remove(modifiedPath)

	args := []string{
		"go",
		"run",
		"github.com/golang-fips/openssl/v2/cmd/checkheader@8bbf74f9e05a46abff41b180288784eb0188eb9c",
		"-shim", modifiedPath,
	}
	args = append(args, os.Args[1:]...)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to run checkheader: %v", err)
	}
}

// modifyShimsFile copies the shims file to a temp location and modifies.
func modifyShimsFile(shimsPath string) (string, error) {
	// Read original file
	content, err := os.ReadFile(shimsPath)
	if err != nil {
		return "", err
	}

	contentStr := string(content)
	type mod struct {
		old, new string
	}
	mods := []mod{
		// SecRandomCopyBytes accepts a void*, but the cgo compiler is not smart enough
		// to see that that pointer is comming from a Go slice without references to
		// unpinned Go memory. We change the signature to use "unsigned char *" instead.
		{
			old: "int SecRandomCopyBytes(SecRandomRef rnd, size_t count, unsigned char *bytes)",
			new: "int SecRandomCopyBytes(SecRandomRef rnd, size_t count, void *bytes)",
		},
	}
	modifiedContent := contentStr
	for _, m := range mods {
		modifiedContent = strings.ReplaceAll(modifiedContent, m.old, m.new)
	}

	// Create temp file with same basename
	basename := filepath.Base(shimsPath)
	tempFile, err := os.CreateTemp("", "checkheader-shims-"+basename+"-*.h")
	if err != nil {
		return "", err
	}

	// Write modified content
	if _, err := tempFile.WriteString(modifiedContent); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return "", err
	}

	if err := tempFile.Close(); err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}
