package cbor

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// decodingRuleVectors is macula's shared vector file for the post-quantum
// decoding rule, test/vectors/decoding_rule_v1.json at macula v12.1.0, copied
// unchanged into testdata. Every stack accepts and refuses exactly these
// inputs.
type decodingRuleVectors struct {
	Version int `json:"version"`
	Entries []struct {
		Name   string `json:"name"`
		CBOR   string `json:"cbor"`
		Expect string `json:"expect"`
		// Via is how macula reads an entry: "record" (or absent) under the
		// decoding rule alone, here; "request_fields" as the fields of a CALL,
		// in frame's TestRequestFieldVectors.
		Via string `json:"via"`
	} `json:"entries"`
}

func TestDecodingRuleVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/decoding_rule_v1.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors decodingRuleVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if vectors.Version != 1 || len(vectors.Entries) == 0 {
		t.Fatalf("vectors: version %d with %d entries, want version 1 with entries", vectors.Version, len(vectors.Entries))
	}
	for _, e := range vectors.Entries {
		if e.Via != "" && e.Via != "record" {
			continue
		}
		t.Run(e.Name, func(t *testing.T) {
			input, err := hex.DecodeString(e.CBOR)
			if err != nil {
				t.Fatalf("hex %q: %v", e.CBOR, err)
			}
			_, err = Decode(input)
			switch e.Expect {
			case "accept":
				if err != nil {
					t.Errorf("0x%s: %v, want it accepted", e.CBOR, err)
				}
			case "refuse":
				if err == nil {
					t.Errorf("0x%s: accepted, want it refused", e.CBOR)
				}
			default:
				t.Fatalf("unknown expectation %q", e.Expect)
			}
		})
	}
}
