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
	"sort"
	"strings"
)

var (
	pkg    = flag.String("pkg", "cryptokit", "package name for generated file")
	xcrDir = flag.String("xcrypto", "./xcrypto", "path to package to build test binary for (relative to repo root)")
)

func main() {
	flag.Parse()
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
		outBytes, err := exec.Command("objdump", "--macho", "--bind", "--dylibs-used", outBin).Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error running objdump for %s: %v\n", arch, err)
			continue
		}

		parsedAll := parseObjdump(outBytes)
		parsedMap := map[string]binding{}
		for _, b := range parsedAll {
			parsedMap[b.sym] = b
		}

		// Add any missing symbols not present in objdump
		for sym := range missing {
			if _, ok := parsedMap[sym]; !ok {
				parsedMap[sym] = binding{sym: sym, dylib: guessDylib(sym)}
			}
		}

		// Add required Swift runtime symbols if absent
		requiredSwift := []string{
			"swift_allocBox",
			"swift_allocObject",
			"swift_errorRelease",
			"swift_getTypeByMangledNameInContext",
			"swift_getTypeByMangledNameInContextInMetadataState",
			"swift_getWitnessTable",
			"swift_release",
			"swift_retain",
			"swift_slowAlloc",
			"swift_slowDealloc",
			"swift_unexpectedError",
		}
		for _, rs := range requiredSwift {
			if _, ok := parsedMap[rs]; !ok {
				parsedMap[rs] = binding{sym: rs, dylib: "/usr/lib/swift/libswiftCore.dylib"}
			}
		}

		// convert map->slice and sort
		parsed := make([]binding, 0, len(parsedMap))
		for _, b := range parsedMap {
			parsed = append(parsed, b)
		}
		sort.Slice(parsed, func(i, j int) bool { return parsed[i].sym < parsed[j].sym })

		// build per-arch output filename: e.g. zcryptokit_swift_arm64.go
		archOut := filepath.Join(outDir, baseName+"_"+arch+".go")
		buildTag := fmt.Sprintf("!cgo && darwin && %s", arch)

		// create final lines
		finalLines := []string{}
		for _, b := range parsed {
			if b.dylib != "" {
				finalLines = append(finalLines, fmt.Sprintf("//go:cgo_import_dynamic %s %s \"%s\"", b.sym, b.sym, b.dylib))
			} else {
				finalLines = append(finalLines, fmt.Sprintf("//go:cgo_import_dynamic %s", b.sym))
			}
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

func detectMissingSymbolsForArch(xcrDir, tmpdir, arch string) map[string]bool {
	outFile := filepath.Join(tmpdir, "xcrypto.test")
	cmd := exec.Command("go", "test", "-ldflags=-e", "-c", "-o", outFile, xcrDir)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH="+arch)
	out, err := cmd.CombinedOutput()
	if err == nil {
		// build succeeded with CGO disabled; nothing missing
		return map[string]bool{}
	}

	text := string(out)
	// look for patterns like: relocation target swift_getWitnessTable not defined
	re := regexp.MustCompile(`relocation target\s+([^\s]+)\s+not\s+defined`)
	m := re.FindAllStringSubmatch(text, -1)
	needed := map[string]bool{}
	for _, sm := range m {
		sym := normalizeSym(sm[1])
		needed[sym] = true
	}
	// also catch patterns like: undefined: symbol
	re2 := regexp.MustCompile(`undefined:\s*([^\s]+)`)
	m2 := re2.FindAllStringSubmatch(text, -1)
	for _, sm := range m2 {
		sym := normalizeSym(sm[1])
		needed[sym] = true
	}
	// also catch adddynsym missed symbol messages like: missed symbol (Extname=$s9CryptoKit...)
	re3 := regexp.MustCompile(`missed symbol \(Extname=([^)]*)\)`)
	m3 := re3.FindAllStringSubmatch(text, -1)
	for _, sm := range m3 {
		sym := normalizeSym(sm[1])
		needed[sym] = true
	}
	return needed
}

// symbol->dylib mapping
type binding struct {
	sym   string
	dylib string // may be empty
}

func parseObjdump(data []byte) []binding {
	s := make(map[string]string)

	// quick heuristic to extract symbol names and dylibs from objdump output
	scanner := bufio.NewScanner(bytes.NewReader(data))
	reSym := regexp.MustCompile(`[$@A-Za-z_][A-Za-z0-9_.$@]*`)
	rePath := regexp.MustCompile(`(/[^ \t\n\r'"]+)`)

	for scanner.Scan() {
		line := scanner.Text()
		// try to find dylib path on this line
		dylib := ""
		if m := rePath.FindStringSubmatch(line); len(m) > 0 {
			dylib = m[1]
		}

		for _, token := range reSym.FindAllString(line, -1) {
			n := normalizeSym(token)
			// accept tokens that look like Swift/C symbols (contain $ or contain lowercase/underscore key names)
			if !strings.Contains(n, "$") && !strings.HasPrefix(n, "swift_") && !strings.HasPrefix(n, "__") && n != "memcpy" {
				continue
			}
			// record mapping, prefer explicit dylib if found
			if dylib != "" {
				s[n] = dylib
			} else if _, ok := s[n]; !ok {
				// record empty mapping for now
				s[n] = ""
			}
		}
	}

	// also heuristically add some well-known C symbols found in many Swift objects
	known := []string{"__stack_chk_fail", "__stack_chk_guard", "__chkstk_darwin", "memcpy"}
	for _, k := range known {
		if _, ok := s[k]; !ok {
			s[k] = "" // allow heuristic mapping later
		}
	}

	// convert map to slice and sort
	out := make([]binding, 0, len(s))
	for sym, dylib := range s {
		heur := guessDylib(sym)
		mapped := ""
		if dylib == "" {
			mapped = heur
		} else if heur != "" && heur != dylib {
			// prefer heuristic mapping for known Swift modules (CryptoKit/Foundation/Swift core)
			mapped = heur
		} else {
			mapped = dylib
		}
		out = append(out, binding{sym: sym, dylib: mapped})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].sym < out[j].sym })
	return out
}

func normalizeSym(sym string) string {
	// objdump or the Mach-O symbol table sometimes produce names with a leading
	// single underscore for symbols that actually start with '$'. The handwritten
	// file uses the '$' prefix without that underscore. Strip a single leading
	// underscore only when it precedes a '$' to normalize to the canonical form.
	if strings.HasPrefix(sym, "_$") {
		return sym[1:]
	}
	return sym
}

func guessDylib(sym string) string {
	// common heuristics used in the handwritten file
	switch {
	case strings.HasPrefix(sym, "$s9CryptoKit"):
		return "/System/Library/Frameworks/CryptoKit.framework/Versions/A/CryptoKit"
	case strings.HasPrefix(sym, "$s10Foundation") || strings.Contains(sym, "Foundation"):
		return "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"
	case strings.HasPrefix(sym, "swift_") || strings.HasPrefix(sym, "$sSW") || strings.HasPrefix(sym, "$sSN") || strings.HasPrefix(sym, "$ss") || strings.HasPrefix(sym, "$sSS") || strings.HasPrefix(sym, "$sS"):
		return "/usr/lib/swift/libswiftCore.dylib"
	case sym == "memcpy", strings.HasPrefix(sym, "__"), strings.HasSuffix(sym, "_darwin"):
		return "/usr/lib/libSystem.B.dylib"
	default:
		return ""
	}
}

func writeLinesWithTag(path, pkg, buildTag string, lines []string) error {
	// post-process lines to ensure known Swift/CryptoKit symbols point at the
	// heuristic dylib rather than an incorrect framework (this helps fix
	// cases where objdump attributed a symbol to the wrong dylib).
	processed := make([]string, 0, len(lines))
	re := regexp.MustCompile(`^//go:cgo_import_dynamic\s+([^\s]+)`) // capture symbol token
	for _, line := range lines {
		if m := re.FindStringSubmatch(line); len(m) > 1 {
			sym := normalizeSym(m[1])
			heur := guessDylib(sym)
			if heur != "" && !strings.Contains(line, heur) {
				reQuoted := regexp.MustCompile(`"([^\\"]+)"`)
				matches := reQuoted.FindAllStringSubmatchIndex(line, -1)
				if len(matches) > 0 {
					last := matches[len(matches)-1]
					line = line[:last[0]] + `"` + heur + `"` + line[last[1]:]
				} else {
					// append heuristic dylib
					line = line + " \"" + heur + "\""
				}
			}
		}
		processed = append(processed, line)
	}

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

	for _, l := range processed {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}
