package identity

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// entryNames is the names dir holds, sorted.
func entryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

// A Save that fails leaves the directory as it found it. Here path is a
// directory that isn't empty, so the rename fails after the key was written.
func TestAFailedSaveLeavesTheDirectoryAsItWas(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")
	if err := os.MkdirAll(filepath.Join(path, "held"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	before := entryNames(t, dir)

	if err := sharedKey(t, pureIdentityKey).Save(path); err == nil {
		t.Fatal("Save onto a directory that isn't empty succeeded, want an error")
	}
	if after := entryNames(t, dir); !slices.Equal(after, before) {
		t.Fatalf("the directory holds %q after the failed Save, want %q as before", after, before)
	}
	if inside := entryNames(t, path); !slices.Equal(inside, []string{"held"}) {
		t.Fatalf("the directory at path holds %q after the failed Save, want only what it held", inside)
	}
}
