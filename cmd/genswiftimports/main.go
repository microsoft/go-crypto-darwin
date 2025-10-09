// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

var (
	pkg    = flag.String("pkg", "cryptokit", "package name for generated file")
	xcrDir = flag.String("xcrypto", "./xcrypto", "path to package to build test binary for (relative to repo root)")
)

func main() {
	flag.Parse()
	if runtime.GOOS != "darwin" {
		// This tool only works on macOS
		return
	}
	baseName := "z" + *pkg + "_swift"
	fmt.Fprintf(os.Stderr, "generating bindings for package %s (base %s)\n", *pkg, baseName)

	// create a temporary directory to hold the test binary so we don't
	// accidentally write xcrypto.test into the current working directory.
	tmpdir, err := os.MkdirTemp("", "genswiftimports-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create tempdir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpdir)

	repoRoot := findRepoRoot()
	var outDir string
	if repoRoot != "" {
		// use repoRoot/internal/cryptokit as the output directory
		outDir = filepath.Join(repoRoot, "internal", "cryptokit")
	} else {
		outDir = filepath.Join("internal", "cryptokit")
	}

	// delete any existing generated arch files before proceeding so generation always
	// starts with a clean slate. Ignore missing-file errors.
	for _, arch := range []string{"arm64", "amd64"} {
		archOut := filepath.Join(outDir, baseName+"_"+arch+".go")
		if err := os.Remove(archOut); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: failed to remove existing file %s: %v\n", archOut, err)
		}
	}

	// If the configured xcrDir doesn't exist as given, try to use <repoRoot>/xcrypto.
	if _, err := os.Stat(*xcrDir); os.IsNotExist(err) {
		if repoRoot := repoRoot; repoRoot != "" {
			candidate := filepath.Join(repoRoot, "xcrypto")
			if _, err := os.Stat(candidate); err == nil {
				*xcrDir = candidate
			}
		}
	}

	// architectures to generate for
	arches := []string{"arm64", "amd64"}
	for _, arch := range arches {
		fmt.Fprintf(os.Stderr, "generating for arch: %s\n", arch)

		// create a tiny tmpdir per-arch
		archTmp, err := os.MkdirTemp(tmpdir, "arch-")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create arch tmpdir: %v\n", err)
			continue
		}
		defer os.RemoveAll(archTmp)

		// discover missing symbols for this arch (CGO disabled)
		missing := detectMissingSymbolsForArch(*xcrDir, archTmp, arch)
		fmt.Fprintf(os.Stderr, "detected %d missing symbols for %s\n", len(missing), arch)

		// build the test binary for this arch with cgo enabled into archTmp
		outBin := filepath.Join(archTmp, "xcrypto.test")
		cmd := exec.Command("go", "test", "-c", "-o", outBin, *xcrDir)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1", "GOARCH="+arch)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "error building test binary for %s: %v\n", arch, err)
			continue
		}

		// run objdump on the arch-specific binary
		outBytes, err := exec.Command("objdump", "--macho", "--bind", outBin).Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running objdump for %s: %v\n", arch, err)
			continue
		}

		symbols := parseObjdump(outBytes)

		// build per-arch output filename: e.g. zcryptokit_swift_arm64.go
		archOut := filepath.Join(outDir, baseName+"_"+arch+".go")
		buildTag := fmt.Sprintf("!cgo && darwin && %s", arch)

		// create final lines
		finalLines := []string{}
		for _, name := range missing {
			if name == "syscall.syscallN" {
				// syscall.syscallN is added in go 1.26, so it can appear as a missing symbol
				// when running this tool with go 1.25. Ignore it.
				continue
			}
			dylib := symbols[name]
			finalLines = append(finalLines, fmt.Sprintf("//go:cgo_import_dynamic %s %s \"%s\"", name, name, dylib))
		}

		if err := writeLinesWithTag(archOut, *pkg, buildTag, finalLines); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", archOut, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d lines)\n", archOut, len(finalLines))
	}
}

func findRepoRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for p := wd; ; p = filepath.Dir(p) {
		if p == "/" || p == "." || p == filepath.Dir(p) {
			break
		}
		if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
			return p
		}
	}
	return ""
}

func detectMissingSymbolsForArch(xcrDir, tmpdir, arch string) []string {
	outFile := filepath.Join(tmpdir, "xcrypto.test")
	cmd := exec.Command("go", "test", "-ldflags=-e", "-c", "-o", outFile, xcrDir)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH="+arch)
	out, err := cmd.CombinedOutput()
	if err == nil {
		// build succeeded with CGO disabled; nothing missing
		return nil
	}

	text := string(out)
	// look for patterns like: relocation target swift_getWitnessTable not defined
	re := regexp.MustCompile(`relocation target\s+([^\s]+)\s+not\s+defined`)
	m := re.FindAllStringSubmatch(text, -1)
	var needed []string
	for _, sym := range m {
		needed = append(needed, sym[1])
	}
	// also catch patterns like: undefined: symbol
	re2 := regexp.MustCompile(`undefined:\s*([^\s]+)`)
	m2 := re2.FindAllStringSubmatch(text, -1)
	for _, sym := range m2 {
		needed = append(needed, sym[1])
	}
	// also catch adddynsym missed symbol messages like: missed symbol (Extname=$s9CryptoKit...)
	re3 := regexp.MustCompile(`missed symbol \(Extname=([^)]*)\)`)
	m3 := re3.FindAllStringSubmatch(text, -1)
	for _, sym := range m3 {
		needed = append(needed, sym[1])
	}
	slices.Sort(needed)
	return needed
}

func parseObjdump(data []byte) map[string]string {
	s := make(map[string]string)

	// quick heuristic to extract symbol names and dylibs from objdump output
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var tableStarted bool
	for scanner.Scan() {
		line := scanner.Text()
		if !tableStarted {
			if strings.Contains(line, "dylib") && strings.Contains(line, "symbol") {
				// Table header
				tableStarted = true
			}
			continue
		}
		columns := strings.Fields(line)
		if len(columns) < 6 {
			continue
		}
		sym := normalizeSym(columns[len(columns)-1])
		dylib := dylibPath(columns[len(columns)-2])
		s[sym] = dylib
	}
	return s
}

func normalizeSym(sym string) string {
	// objdump or the Mach-O symbol table produce names with a leading single
	// underscore. Strip it.
	if strings.HasPrefix(sym, "_") {
		return sym[1:]
	}
	return sym
}

func dylibPath(dylib string) string {
	// common heuristics used in the handwritten file
	switch dylib {
	case "CryptoKit":
		return "/System/Library/Frameworks/CryptoKit.framework/Versions/A/CryptoKit"
	case "Foundation":
		return "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"
	case "libswiftCore":
		return "/usr/lib/swift/libswiftCore.dylib"
	case "libSystem":
		return "/usr/lib/libSystem.B.dylib"
	default:
		return ""
	}
}

func writeLinesWithTag(path, pkg, buildTag string, lines []string) error {
	// ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "// Copyright (c) Microsoft Corporation.")
	fmt.Fprintln(w, "// Licensed under the MIT License.")
	fmt.Fprintln(w, "// Code generated by genswiftimports. DO NOT EDIT.")
	fmt.Fprintln(w)
	// write arch-specific build tag
	fmt.Fprintf(w, "//go:build %s\n", buildTag)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "package %s\n", pkg)
	fmt.Fprintln(w)

	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}
