// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"log"
	"os"
	"os/exec"
	"runtime"

	"github.com/microsoft/go-crypto-darwin/internal/cgotool"
)

func main() {
	if runtime.GOOS != "darwin" {
		// This tool only works on macOS
		return
	}
	pkg, err := cgotool.CheckheaderPackage()
	if err != nil {
		log.Fatalf("failed to get checkheader package: %v", err)
	}
	args := []string{
		"go",
		"run",
		pkg,
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
