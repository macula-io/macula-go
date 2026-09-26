package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/ownershipproof"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

// The vector's fields as a binding hands them to the ABI: JSON, bytes as
// {"$bytes": base64}.
const vectorFieldsJSON = `{"subject": "entity:alpha", "predicate": "knows", "object": "entity:beta",
 "confidence": 0.75, "weight": 3, "offset": -7, "digest": {"$bytes": "AQID"}, "note": null,
 "tags": ["a", "b"], "metadata": {"source": "field-notes", "page": 12}}`

func ownershipVector(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "ownershipproof", "testdata", "vector", name))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The ABI's JSON mapping of the fields reaches mcl_om's vector.
func TestOwnershipFieldsJSONSignMclOmsVector(t *testing.T) {
	fields, err := payloadFromJSON(vectorFieldsJSON)
	if err != nil {
		t.Fatal(err)
	}
	var id [32]byte
	copy(id[:], ownershipVector(t, "identity.hex"))
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	got := ownershipproof.Message(id, sha256.Sum256([]byte("io.macula")), "mcl-graph/learn_link", 1790000000000, nonce, fields)
	if want := ownershipVector(t, "message.hex"); !bytes.Equal(got, want) {
		t.Fatalf("the ABI's fields do not give mcl_om's vector:\n got %x\nwant %x", got, want)
	}
}

// The message export takes a whole payload and signs its Fields, as Attach
// does: an asserted_by and a text caller in it change nothing.
func TestTheOwnershipMessageSignsThePayloadsFields(t *testing.T) {
	var id [32]byte
	copy(id[:], ownershipVector(t, "identity.hex"))
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	whole := strings.TrimSuffix(vectorFieldsJSON, "}") + `, "caller": "claimed", "asserted_by": {"identity": "x"}}`
	payload, err := payloadFromJSON(whole)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := ownershipproof.Fields(payload)
	if err != nil {
		t.Fatal(err)
	}
	got := ownershipproof.Message(id, sha256.Sum256([]byte("io.macula")), "mcl-graph/learn_link", 1790000000000, nonce, fields)
	if want := ownershipVector(t, "message.hex"); !bytes.Equal(got, want) {
		t.Fatal("a payload's asserted_by or caller changed the signed bytes")
	}
}

func TestAnOwnershipProofPayloadVerifies(t *testing.T) {
	key := teststation.Key(t, profile.PQPure, "owner")
	realm := sha256.Sum256([]byte("io.macula"))
	text, err := ownershipProofPayload(key, realm, "mcl-graph/learn_link",
		`{"subject": "entity:alpha", "weight": 3, "asserted_by": {"identity": "stale"}}`)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := payloadFromJSON(text)
	if err != nil {
		t.Fatalf("the signed payload is not the ABI's JSON: %v\n%s", err, text)
	}
	got, err := ownershipproof.Verify(payload, "mcl-graph/learn_link", realm, profile.PQPure, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v\n%s", err, text)
	}
	if id, _ := key.NodeID(); got.Identity != id {
		t.Fatalf("verified %x, want the key's node", got.Identity)
	}
	if weight, _ := payload.Get("weight"); !bytes.Equal(cbor.Encode(weight), cbor.Encode(cbor.Int(3))) {
		t.Fatalf("the fields changed: %s", text)
	}
}

func TestOwnershipProofRefusals(t *testing.T) {
	key := teststation.Key(t, profile.PQPure, "owner")
	realm := sha256.Sum256([]byte("io.macula"))
	for name, c := range map[string]struct{ procedure, payload string }{
		"a payload that is not an object": {"p", `[1]`},
		"a boolean in the payload":        {"p", `{"a": true}`},
		"an empty procedure":              {"", `{"a": 1}`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ownershipProofPayload(key, realm, c.procedure, c.payload); kindOf(err) != kindInvalidArgument {
				t.Fatalf("%v, want invalid_argument", err)
			}
		})
	}
	var abiErr *abiError
	_, err := ownershipProofPayload(key, realm, "p", `[1]`)
	if !errors.As(err, &abiErr) {
		t.Fatalf("%T, want an abiError", err)
	}
}
