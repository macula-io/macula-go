package main

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

// These tests build the library as a binding gets it (-buildmode=c-shared)
// and hold it to macula.h: the header declares exactly the exported
// functions, and a C program using the header alone works against in-process
// stations. They need a C compiler. MACULA_ABI_TEST=required (CI sets it)
// makes a missing compiler a failure instead of a skip.

func cCompiler(t *testing.T) string {
	t.Helper()
	for _, name := range []string{os.Getenv("CC"), "cc", "gcc", "clang"} {
		if name == "" {
			continue
		}
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	if os.Getenv("MACULA_ABI_TEST") == "required" {
		t.Fatal("no C compiler, and MACULA_ABI_TEST=required")
	}
	t.Skip("no C compiler")
	return ""
}

// buildLibrary builds the c-shared library and its cgo header into dir.
func buildLibrary(t *testing.T, dir string) (library, cgoHeader string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the C ABI test runs on unix-like systems; the release builds the Windows DLL")
	}
	library = filepath.Join(dir, "libmacula.so")
	build := exec.Command("go", "build", "-buildmode=c-shared", "-o", library, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build -buildmode=c-shared: %v", err)
	}
	return library, filepath.Join(dir, "libmacula.h")
}

// prototypeLine matches one declaration: a return type, a name, a parameter
// list.
var prototypeLine = regexp.MustCompile(`^(?:extern\s+)?([A-Za-z_][\w\s\*]*?)\s*\b(macula_\w+)\s*\(([^)]*)\)\s*;`)

// signatures reads every macula_ function a header declares, as a
// normalized "return(param types)" per name: no names, no const, arrays as
// pointers, macula_handle as uintptr_t.
func signatures(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Join continuation lines so each declaration is one line.
	text := regexp.MustCompile(`,\s*\n\s*`).ReplaceAllString(string(raw), ", ")
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		m := prototypeLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		var params []string
		for _, p := range strings.Split(m[3], ",") {
			if p = normalizeType(p, true); p != "" && p != "void" {
				params = append(params, p)
			}
		}
		out[m[2]] = normalizeType(m[1], false) + "(" + strings.Join(params, ",") + ")"
	}
	return out
}

var (
	arraySuffix = regexp.MustCompile(`\[\w*\]\s*$`)
	identifier  = regexp.MustCompile(`[A-Za-z_]\w*\s*$`)
)

func normalizeType(t string, isParam bool) string {
	t = strings.TrimSpace(t)
	pointer := false
	if isParam && arraySuffix.MatchString(t) {
		t = arraySuffix.ReplaceAllString(t, "")
		pointer = true
	}
	stars := strings.Count(t, "*")
	t = strings.ReplaceAll(t, "*", " ")
	t = strings.ReplaceAll(t, "const", " ")
	fields := strings.Fields(t)
	if isParam && len(fields) > 1 && identifier.MatchString(fields[len(fields)-1]) {
		fields = fields[:len(fields)-1] // the parameter's name
	}
	base := strings.Join(fields, " ")
	if base == "macula_handle" {
		base = "uintptr_t"
	}
	if pointer {
		stars++
	}
	return base + strings.Repeat("*", stars)
}

func TestTheHeaderDeclaresExactlyTheExports(t *testing.T) {
	cCompiler(t)
	_, cgoHeader := buildLibrary(t, t.TempDir())
	exported := signatures(t, cgoHeader)
	declared := signatures(t, "macula.h")
	if len(exported) == 0 || len(declared) == 0 {
		t.Fatalf("read %d exports and %d declarations", len(exported), len(declared))
	}
	var names []string
	for name := range exported {
		names = append(names, name)
	}
	for name := range declared {
		if _, ok := exported[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if exported[name] != declared[name] {
			t.Errorf("%s: exported %q, macula.h declares %q", name, exported[name], declared[name])
		}
	}
}

func TestACProgramDrivesTheLibrary(t *testing.T) {
	cc := cCompiler(t)
	dir := t.TempDir()
	library, _ := buildLibrary(t, dir)
	program := filepath.Join(dir, "abi_test")
	compile := exec.Command(cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I.", "-o", program,
		filepath.Join("testdata", "abi_test.c"), library, "-lpthread", "-Wl,-rpath,"+dir)
	compile.Stderr = os.Stderr
	if err := compile.Run(); err != nil {
		t.Fatalf("compile abi_test.c: %v", err)
	}

	a := teststation.Start(t, profile.PQPure, "abi a")
	b := teststation.Start(t, profile.PQPure, "abi b")
	teststation.ShareDHT(a, b)
	realm := teststation.NewRealm(t, profile.PQPure, "abi", "mcl-abi")
	f := fleet{stations: []*teststation.Station{a, b}, realm: realm}

	keys := t.TempDir()
	run := exec.Command(program, keys, f.seedsJSON(a), hex.EncodeToString(realm.ID[:]), f.optionsJSON())
	out, err := run.CombinedOutput()
	if err != nil || !strings.HasSuffix(strings.TrimSpace(string(out)), "ok") {
		t.Fatalf("abi_test: %v\n%s", err, out)
	}
}
