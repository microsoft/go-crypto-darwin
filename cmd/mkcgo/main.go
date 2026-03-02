// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"log"
	"os"
	"os/exec"
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

	args := []string{"go", "run", "github.com/golang-fips/openssl/v2/cmd/mkcgo@4ae711d471f5fa72e2d4cbd712d75e08c95caafa"}
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
