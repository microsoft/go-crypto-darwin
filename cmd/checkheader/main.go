// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"log"
	"os"
	"os/exec"
	"runtime"
)

func main() {
	if runtime.GOOS != "darwin" {
		// This tool only works on macOS
		return
	}
	args := []string{"go", "run", "github.com/golang-fips/openssl/v2/cmd/checkheader@40b26b14957cadd2f76ccb58a6ea467ea4a45f56"}
	args = append(args, os.Args[1:]...)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to run mkcgo: %v", err)
	}
}
