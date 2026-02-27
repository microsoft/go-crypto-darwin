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
	args := []string{
		"go",
		"run",
		"github.com/golang-fips/openssl/v2/cmd/checkheader@3ee423e8052c14eb5261a0aa1722ccd70b9ca6e6",
		"-shim", os.Args[1],
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
