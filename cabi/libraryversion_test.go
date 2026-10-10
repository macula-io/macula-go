package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A binding with a release floor reads the library's release at load
// (macula-go#18). An untagged build says "devel"; a released one says the tag
// build.sh stamped into it.

func TestAnUnstampedBuildSaysDevel(t *testing.T) {
	if got := libraryVersionString(); got != "devel" {
		t.Fatalf("library version = %q, want devel", got)
	}
}

func TestTheLibraryReturnsTheStampedRelease(t *testing.T) {
	cc := cCompiler(t)
	dir := t.TempDir()
	library := filepath.Join(dir, "libmacula.so")
	build := exec.Command("go", "build", "-buildmode=c-shared",
		"-ldflags=-X main.libraryVersion=v9.8.7", "-o", library, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build -buildmode=c-shared: %v", err)
	}
	src := filepath.Join(dir, "version.c")
	prog := `#include <stdio.h>
#include "macula.h"
int main(void) { printf("%s\n", macula_library_version()); return 0; }
`
	if err := os.WriteFile(src, []byte(prog), 0o600); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	bin := filepath.Join(dir, "version")
	compile := exec.Command(cc, "-I", wd, "-o", bin, src, library, "-Wl,-rpath,"+dir)
	compile.Stderr = os.Stderr
	if err := compile.Run(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	out, err := exec.Command(bin).Output()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "v9.8.7" {
		t.Fatalf("macula_library_version() = %q, want the stamped v9.8.7", got)
	}
}
