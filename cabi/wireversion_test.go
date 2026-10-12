package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/frame"
)

// A binding reads the wire its library speaks at load, so every FFI SDK can
// prove which wire it links (macula-go#30, macula docs/design/WIRE_1_0.md).

func TestTheLibrarySpeaksWireOnePointZero(t *testing.T) {
	if frame.WireVersion != "1.0" {
		t.Fatalf("frame.WireVersion = %q, want 1.0", frame.WireVersion)
	}
	if got := wireVersionString(); got != frame.WireVersion {
		t.Fatalf("wire version = %q, want %q", got, frame.WireVersion)
	}
}

func TestTheLibraryReturnsItsWireVersionToC(t *testing.T) {
	cc := cCompiler(t)
	dir := t.TempDir()
	library := filepath.Join(dir, "libmacula.so")
	build := exec.Command("go", "build", "-buildmode=c-shared", "-o", library, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build -buildmode=c-shared: %v", err)
	}
	src := filepath.Join(dir, "wire.c")
	prog := `#include <stdio.h>
#include <string.h>
#include "macula.h"
int main(void) {
  const char *wire = macula_wire_version();
  printf("%s %s\n", wire, strcmp(wire, MACULA_WIRE_VERSION) == 0 ? "matches" : "differs");
  return 0;
}
`
	if err := os.WriteFile(src, []byte(prog), 0o600); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	bin := filepath.Join(dir, "wire")
	compile := exec.Command(cc, "-I", wd, "-o", bin, src, library, "-Wl,-rpath,"+dir)
	compile.Stderr = os.Stderr
	if err := compile.Run(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	out, err := exec.Command(bin).Output()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "1.0 matches" {
		t.Fatalf("macula_wire_version() = %q, want 1.0, matching the header's MACULA_WIRE_VERSION", got)
	}
}
