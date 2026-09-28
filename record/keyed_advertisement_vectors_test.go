package record

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// keyedAdvertisementVectors is macula's test/vectors/e2e_seal_v1_advertisements.json
// (macula b51202a8, sha256 68b32ba90e9031bcff2204217a63f97ab99902fdcd98734dcc91771255e33f23),
// copied into testdata by scripts/interop/copy_e2e_seal_vectors.sh: signed
// procedure advertisements, five per profile, and the verdict macula_record's
// verify/3 reaches on each at the profile's now_ms (seal/testdata/E2E_SEAL_V1.md,
// "Keyed advertisements"). Signing is randomized, so the committed file is the
// vector.
type keyedAdvertisementVectors struct {
	Profiles map[string]struct {
		NowMs int64 `json:"now_ms"`
		Cases []struct {
			Name     string `json:"name"`
			Record   string `json:"record"`
			Verdict  string `json:"verdict"`
			KEMKey   string `json:"kem_key"`
			KEMKeyID string `json:"kem_key_id"`
		} `json:"cases"`
	} `json:"profiles"`
}

// TestKeyedAdvertisementVectors holds Verify to macula's verdicts on keyed
// advertisements (amendment A1): the key as carried and its own id is
// accepted and read back; another key's id, a key or an id alone, and a key
// of no profile's size are refused malformed. Every signature is valid, so
// only the payload's shape can refuse.
func TestKeyedAdvertisementVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "e2e_seal_v1_advertisements.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors keyedAdvertisementVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	cases := 0
	for name, p := range vectors.Profiles {
		for _, c := range p.Cases {
			cases++
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				wire, err := hex.DecodeString(c.Record)
				if err != nil {
					t.Fatal(err)
				}
				verified, err := Verify(wire, profile.Profile(name), p.NowMs)
				switch c.Verdict {
				case "malformed":
					if !errors.Is(err, ErrMalformed) {
						t.Errorf("Verify: %v, want ErrMalformed", err)
					}
				case "accepted":
					if err != nil {
						t.Fatalf("Verify: %v, want accepted", err)
					}
					ad, err := ReadProcedureAdvertisement(verified.Record())
					if err != nil {
						t.Fatalf("ReadProcedureAdvertisement: %v", err)
					}
					if hex.EncodeToString(ad.KEMKey) != c.KEMKey || !bytes.Equal(ad.KEMKeyID[:], mustHex(t, c.KEMKeyID)) {
						t.Errorf("read back kem_key %x…, kem_key_id %x; want the vector's", ad.KEMKey[:8], ad.KEMKeyID)
					}
				default:
					t.Fatalf("a verdict this test does not know: %q", c.Verdict)
				}
			})
		}
	}
	if cases != 10 {
		t.Fatalf("%d cases, want 5 under each of 2 profiles", cases)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
