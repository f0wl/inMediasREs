package utilimr

import (
	"debug/elf"
	"io"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

// ELFAnalysis handles the analysis of ELF Binaries
func ELFAnalysis() (imp []string, sym []elf.ImportedSymbol) {

	f := ioReader(os.Args[1])
	_elf, err := elf.NewFile(f)
	check(err)

	// Read and decode ELF identifier
	var ident [16]uint8
	f.ReadAt(ident[0:], 0)
	check(err)

	if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {

		if ident[0] != '\x4D' || ident[1] != 'M' || ident[2] != 'Z' {
			PEAnalysis()
		}
	}

	imp, err = _elf.ImportedLibraries()
	sym, err = _elf.ImportedSymbols()

	return imp, sym

}
