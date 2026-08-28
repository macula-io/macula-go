package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSatisfiesDefaultPuzzle(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !kp.HasValidPuzzle(DefaultPuzzleDifficulty) {
		t.Errorf("Generate()'d identity does not satisfy its own default difficulty")
	}
	if len(kp.NodeID()) != 32 {
		t.Errorf("NodeID length = %d, want 32", len(kp.NodeID()))
	}
}

func TestLeadingZeroBitsCounting(t *testing.T) {
	cases := []struct {
		hash [32]byte
		want uint32
	}{
		{[32]byte{0x00, 0x00, 0xFF}, 16},
		{[32]byte{0xFF}, 0},
		{[32]byte{0x0F}, 4},
		{[32]byte{0x01}, 7},
		{[32]byte{}, 256}, // all-zero hash
	}
	for _, c := range cases {
		got := leadingZeroBits(c.hash)
		if got != c.want {
			t.Errorf("leadingZeroBits(% X) = %d, want %d", c.hash[:4], got, c.want)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "identity.seed")
	if err := kp.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("saved file mode = %o, want 600", info.Mode().Perm())
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(loaded.NodeID()) != string(kp.NodeID()) {
		t.Errorf("Load produced a different NodeID than the saved identity")
	}
	// A previously-valid seed must still satisfy the puzzle on reload --
	// Load must never re-grind.
	if !loaded.HasValidPuzzle(DefaultPuzzleDifficulty) {
		t.Errorf("loaded identity does not satisfy the puzzle it was minted for")
	}
}

func TestSignVerify(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	msg := []byte("macula-v2-frame\x00some canonical bytes")
	sig := kp.Sign(msg)
	if !Verify(kp.NodeID(), msg, sig) {
		t.Error("Verify: valid signature rejected")
	}
	if Verify(kp.NodeID(), []byte("tampered"), sig) {
		t.Error("Verify: accepted a signature over the wrong message")
	}
}
