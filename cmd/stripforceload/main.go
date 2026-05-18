// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// stripforceload removes Swift FORCE_LOAD relocations from Mach-O object files
// (.syso). These auto-linking hints cause Go's internal linker
// (used when CGO_ENABLED=0) to fail with "unexpected reloc for dynamic symbol"
// errors on Go versions before 1.27. The required dynamic imports are already
// declared via //go:cgo_import_dynamic directives in the generated Go files,
// so removing these relocations is sufficient.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

const (
	headerSize64  = 32
	segCmdSize64  = 72
	sectionSize64 = 80
	relocSize     = 8
	nlistSize64   = 16
	lcSegment64   = 0x19
	lcSymtab      = 0x2
	mhMagic64     = 0xFEEDFACF
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: stripforceload <file.syso>\n")
		os.Exit(1)
	}

	filename := os.Args[1]

	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", filename, err)
		os.Exit(1)
	}

	bo := binary.LittleEndian

	// Validate Mach-O 64-bit header.
	if len(data) < headerSize64 {
		fmt.Fprintf(os.Stderr, "file too small for Mach-O header\n")
		os.Exit(1)
	}
	magic := bo.Uint32(data[0:4])
	if magic != mhMagic64 {
		fmt.Fprintf(os.Stderr, "not a 64-bit Mach-O file (magic=0x%x)\n", magic)
		os.Exit(1)
	}
	ncmds := bo.Uint32(data[16:20])

	// Walk load commands to collect section headers and the symbol table location.
	type sectionInfo struct {
		headerOffset uint32 // offset of section_64 in the file
		segname      string
		sectname     string
		reloff       uint32
		nreloc       uint32
	}
	var sections []sectionInfo
	var symoff, nsyms, stroff, strsize uint32

	off := uint32(headerSize64)
	for i := uint32(0); i < ncmds; i++ {
		if int(off+8) > len(data) {
			break
		}
		cmd := bo.Uint32(data[off : off+4])
		cmdsize := bo.Uint32(data[off+4 : off+8])

		switch cmd {
		case lcSegment64:
			if int(off+68) > len(data) {
				break
			}
			nsects := bo.Uint32(data[off+64 : off+68])
			sectOff := off + uint32(segCmdSize64)
			for s := uint32(0); s < nsects; s++ {
				so := sectOff + s*sectionSize64
				if int(so+sectionSize64) > len(data) {
					break
				}
				sectname := strings.TrimRight(string(data[so:so+16]), "\x00")
				segname := strings.TrimRight(string(data[so+16:so+32]), "\x00")
				reloff := bo.Uint32(data[so+56 : so+60])
				nreloc := bo.Uint32(data[so+60 : so+64])
				sections = append(sections, sectionInfo{
					headerOffset: so,
					segname:      segname,
					sectname:     sectname,
					reloff:       reloff,
					nreloc:       nreloc,
				})
			}
		case lcSymtab:
			if int(off+24) > len(data) {
				break
			}
			symoff = bo.Uint32(data[off+8 : off+12])
			nsyms = bo.Uint32(data[off+12 : off+16])
			stroff = bo.Uint32(data[off+16 : off+20])
			strsize = bo.Uint32(data[off+20 : off+24])
		}

		off += cmdsize
	}

	if nsyms == 0 {
		fmt.Fprintf(os.Stderr, "no symbol table found\n")
		return
	}

	// Validate symbol table and string table bounds.
	if int64(stroff)+int64(strsize) > int64(len(data)) {
		fmt.Fprintf(os.Stderr, "string table extends beyond file bounds\n")
		os.Exit(1)
	}
	if int64(symoff)+int64(nsyms)*nlistSize64 > int64(len(data)) {
		fmt.Fprintf(os.Stderr, "symbol table extends beyond file bounds\n")
		os.Exit(1)
	}

	// Read string table and identify FORCE_LOAD symbol indices.
	strtab := data[stroff : stroff+strsize]
	forceLoadSyms := make(map[uint32]bool)

	for i := uint32(0); i < nsyms; i++ {
		nlistOff := symoff + i*nlistSize64
		if int(nlistOff+4) > len(data) {
			break
		}
		strx := bo.Uint32(data[nlistOff : nlistOff+4])
		name := readCString(strtab, strx)
		if strings.Contains(name, "FORCE_LOAD") {
			forceLoadSyms[i] = true
		}
	}

	if len(forceLoadSyms) == 0 {
		fmt.Fprintf(os.Stderr, "no FORCE_LOAD symbols found in %s\n", filename)
		return
	}

	// Remove relocations that reference FORCE_LOAD symbols.
	totalRemoved := 0
	for _, sect := range sections {
		if sect.nreloc == 0 {
			continue
		}

		writeIdx := uint32(0)
		removed := 0
		for r := uint32(0); r < sect.nreloc; r++ {
			roff := sect.reloff + r*relocSize
			if int(roff+relocSize) > len(data) {
				break
			}
			rInfo := bo.Uint32(data[roff+4 : roff+8])
			symnum := rInfo & 0x00FFFFFF
			extern := (rInfo >> 27) & 1

			if extern == 1 && forceLoadSyms[symnum] {
				removed++
				continue
			}

			// Keep: copy to compacted position.
			woff := sect.reloff + writeIdx*relocSize
			if woff != roff {
				copy(data[woff:woff+relocSize], data[roff:roff+relocSize])
			}
			writeIdx++
		}

		if removed > 0 {
			// Zero the freed relocation slots.
			for i := writeIdx; i < sect.nreloc; i++ {
				zoff := sect.reloff + i*relocSize
				bo.PutUint32(data[zoff:zoff+4], 0)
				bo.PutUint32(data[zoff+4:zoff+8], 0)
			}

			// Update nreloc in the section header.
			bo.PutUint32(data[sect.headerOffset+60:sect.headerOffset+64], writeIdx)

			fmt.Fprintf(os.Stderr, "  %s,%s: removed %d FORCE_LOAD relocs (%d → %d)\n",
				sect.segname, sect.sectname, removed, sect.nreloc, writeIdx)
			totalRemoved += removed
		}
	}

	if totalRemoved == 0 {
		fmt.Fprintf(os.Stderr, "no FORCE_LOAD relocations found in %s\n", filename)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", filename, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "stripforceload: %s: removed %d FORCE_LOAD relocation(s)\n", filename, totalRemoved)
}

func readCString(strtab []byte, offset uint32) string {
	if int(offset) >= len(strtab) {
		return ""
	}
	end := offset
	for int(end) < len(strtab) && strtab[end] != 0 {
		end++
	}
	return string(strtab[offset:end])
}
