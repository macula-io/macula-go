package frame

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// TestRequestFieldVectors runs the entries of macula's shared decoding rule
// vectors (cbor/testdata/decoding_rule_v1.json) that macula reads "via"
// request_fields: the bytes decoded under the rule, then read as the fields of
// a CALL under the request table, which is where a delegation chain's proofs
// are bounded.
func TestRequestFieldVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "cbor", "testdata", "decoding_rule_v1.json"))
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	var vectors struct {
		Entries []struct {
			Name, CBOR, Expect, Via string
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("vectors: %v", err)
	}
	ran := 0
	for _, e := range vectors.Entries {
		if e.Via != "request_fields" {
			continue
		}
		ran++
		t.Run(e.Name, func(t *testing.T) {
			input, err := hex.DecodeString(e.CBOR)
			if err != nil {
				t.Fatalf("hex: %v", err)
			}
			wire, err := cbor.Decode(input)
			if err != nil {
				t.Fatalf("decode: %v, want the rule to accept the bytes", err)
			}
			_, ok := readFields(wire, requestTable(frameTypeCall))
			if want := e.Expect == "accept"; ok != want {
				t.Errorf("read as a CALL's fields: %t, want %t", ok, want)
			}
		})
	}
	if ran != 5 {
		t.Fatalf("%d request_fields vectors, want macula v12.1.0's 5", ran)
	}
}

// A request carries the proofs of its delegation chain in its signed part, and
// a verifier hands them on; a request with none carries no proofs field.
func TestARequestCarriesItsProofs(t *testing.T) {
	keys := requestKeysFor(t)
	spec := callSpec(keys)
	spec.Proofs = [][]byte{[]byte("proof.one"), []byte("proof.two")}
	request := verifiedRequestOf(t, keys.caller, spec)
	if len(request.Proofs) != 2 || !bytes.Equal(request.Proofs[0], spec.Proofs[0]) || !bytes.Equal(request.Proofs[1], spec.Proofs[1]) {
		t.Errorf("proofs %q, want %q", request.Proofs, spec.Proofs)
	}
	if plain := verifiedRequestOf(t, keys.caller, callSpec(keys)); plain.Proofs != nil {
		t.Errorf("a request with no proofs verified with %q, want none", plain.Proofs)
	}
}

// SignCall refuses a proofs set every reader would refuse: more than eight,
// more than 256 KiB, or one repeated.
func TestSignCallRefusesProofsOutsideTheBound(t *testing.T) {
	keys := requestKeysFor(t)
	nine := make([][]byte, 9)
	for i := range nine {
		nine[i] = []byte{byte(i)}
	}
	cases := map[string][][]byte{
		"nine proofs":          nine,
		"over 256 KiB":         {make([]byte, 256*1024), {1}},
		"the same proof twice": {[]byte("same"), []byte("same")},
	}
	for name, proofs := range cases {
		spec := callSpec(keys)
		spec.Proofs = proofs
		if _, err := SignCall(spec, keys.caller); !errors.Is(err, ErrProofsOutOfBound) {
			t.Errorf("%s: %v, want ErrProofsOutOfBound", name, err)
		}
	}
}
