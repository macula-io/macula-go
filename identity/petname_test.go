package identity

import (
	"strings"
	"testing"
)

func TestPetnameDeterministicAndShaped(t *testing.T) {
	id := "7374b0cfab4eea68e271c3815a0f78e21e913397f67345f337ddba7a3a88ab3a"
	first := Petname(id)
	if Petname(id) != first {
		t.Fatal("petname must be deterministic")
	}
	parts := strings.Split(first, "_")
	if len(parts) != 4 {
		t.Fatalf("petname shape = %q, want adjective_color_animal_suffix", first)
	}
	if len(parts[3]) != 4 {
		t.Fatalf("suffix = %q, want zero-padded four digits", parts[3])
	}
	for _, c := range parts[3] {
		if c < '0' || c > '9' {
			t.Fatalf("suffix = %q, not numeric", parts[3])
		}
	}
}

// TestPetnameMatchesReference pins the cross-SDK derivation: these
// ids' petnames must equal what macula-mcp's petname.ts and
// macula-rust's petname() produce -- one label everywhere. The second
// fixture is proven against the live roster (gentle_maroon_flamingo,
// opencode's own id, before the suffix shipped).
func TestPetnameMatchesReference(t *testing.T) {
	cases := map[string]string{
		"7374b0cfab4eea68e271c3815a0f78e21e913397f67345f337ddba7a3a88ab3a": "calm_navy_narwhal_3381",
		"d4b24382f4e033ad9e895070c914c8125c315f243c5a3713183352f65c322b03": "gentle_maroon_flamingo_3490",
	}
	for id, want := range cases {
		if got := Petname(id); got != want {
			t.Fatalf("Petname(%q) = %q, want %q -- the derivation drifted from the other SDKs", id[:12], got, want)
		}
	}
}
