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

	args := []string{"go", "run", "github.com/golang-fips/openssl/v2/cmd/mkcgo@0cb9b49edfa384c9af615113fb59c5002e3728e2"}
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
