//go:build ignore

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
)

const baseURL = "https://raw.githubusercontent.com/ebitengine/purego/main/internal/fakecgo"

var filesToSkip = makeSet(
	"update_tool.go",
	"generate.go",
	"fakecgo.go",
)

var noTagModification = makeSet(
	"libcgo_darwin.go",
	"symbols_darwin.go",
)

func makeSet(items ...string) map[string]bool {
	s := make(map[string]bool)
	for _, item := range items {
		s[item] = true
	}
	return s
}

func main() {
	files, err := os.ReadDir(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading directory: %v\n", err)
		os.Exit(1)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()

		if filesToSkip[name] {
			continue
		}

		fmt.Printf("Updating %s...\n", name)
		if err := updateFile(name); err != nil {
			fmt.Fprintf(os.Stderr, "Error updating %s: %v\n", name, err)
			os.Exit(1)
		}
	}
	fmt.Println("Done.")
}

func updateFile(name string) error {
	url := fmt.Sprintf("%s/%s", baseURL, name)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	if !noTagModification[name] {
		content = modifyBuildTags(content)
	}

	// Preserve file permissions if possible, but 0644 is standard for source files.
	// The original script uses curl -o which overwrites.
	if err := os.WriteFile(name, content, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func modifyBuildTags(content []byte) []byte {
	lines := bytes.Split(content, []byte("\n"))
	for i, line := range lines {
		if bytes.HasPrefix(line, []byte("//go:build")) {
			lines[i] = []byte("//go:build !cgo && darwin")
		}
	}
	return bytes.Join(lines, []byte("\n"))
}
