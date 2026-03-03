// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"log"
	"os"
	"os/exec"

	"github.com/microsoft/go-crypto-darwin/internal/cgotool"
)

const copyright = "// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT License.\n"

func main() {
	tempFile, err := os.CreateTemp("", "mkcgo-test-copyright*.txt")
	if err != nil {
		log.Fatalf("failed to create copyright file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	if _, err := tempFile.WriteString(copyright); err != nil {
		log.Fatalf("failed to write copyright file: %v", err)
	}

	pkg, err := cgotool.MkcgoPackage()
	if err != nil {
		log.Fatalf("failed to get mkcgo package: %v", err)
	}
	args := []string{"go", "run", pkg}
	args = append(args, "-copyright", tempFile.Name())
	args = append(args, os.Args[1:]...)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to run mkcgo: %v", err)
	}
}
