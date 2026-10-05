package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

const objectLabel = "MACULA-PQ-RECORD-V1"

func signedObjectBytes(t *testing.T, p profile.Profile) ([]byte, *identity.NodeKey) {
	t.Helper()
	key, err := identity.GenerateKey(identity.PurposeIdentity, p)
	if err != nil {
		t.Fatal(err)
	}
	object, err := identity.SignObject(objectLabel, []cbor.MapEntry{
		{Key: cbor.Text("title"), Val: cbor.Text("corpus entry")},
		{Key: cbor.Text("digest"), Val: cbor.Bytes([]byte{1, 2, 3})},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return cbor.Encode(object.Value()), key
}

func unverifiedReason(t *testing.T, err error) string {
	t.Helper()
	var ae *abiError
	if !errors.As(err, &ae) || ae.kind != kindUnverified {
		t.Fatalf("not unverified: %v", err)
	}
	return ae.fields["reason"].(string)
}

// A signed object verifies to its signer's node_id and key, its tbs and its
// fields, bytes in the ABI's {"$bytes"} form.
func TestASignedObjectVerifiesToItsSignerAndFields(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQHybrid, profile.PQPure} {
		object, key := signedObjectBytes(t, p)
		text, err := verifySignedObject(objectLabel, object, string(p))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		var got struct {
			NodeID string            `json:"node_id"`
			Key    map[string]string `json:"key"`
			TBS    map[string]string `json:"tbs"`
			Fields map[string]any    `json:"fields"`
		}
		if err := json.Unmarshal([]byte(text), &got); err != nil {
			t.Fatal(err)
		}
		nodeID, _ := key.NodeID()
		if got.NodeID != hex.EncodeToString(nodeID[:]) {
			t.Errorf("%s: node_id %v", p, got.NodeID)
		}
		if got.Key["$bytes"] != base64.StdEncoding.EncodeToString(key.PublicKey()) {
			t.Errorf("%s: not the signer's key", p)
		}
		if got.TBS["$bytes"] == "" {
			t.Errorf("%s: no tbs", p)
		}
		if got.Fields["title"] != "corpus entry" || got.Fields["alg"] == nil {
			t.Errorf("%s: fields %v", p, got.Fields)
		}
		if d, _ := got.Fields["digest"].(map[string]any); d["$bytes"] != "AQID" {
			t.Errorf("%s: digest %v", p, got.Fields["digest"])
		}
	}
}

// Each refusal comes back as unverified with macula's reason, a bad label or
// profile as invalid_argument, and an error that is no verdict on the object
// as failed, never as malformed.
func TestASignedObjectThatDoesNotVerifyIsUnverifiedWithItsReason(t *testing.T) {
	object, _ := signedObjectBytes(t, profile.PQHybrid)

	_, err := verifySignedObject("MACULA-PQ-REPLY-V1", object, "")
	if r := unverifiedReason(t, err); r != "signature_invalid" {
		t.Errorf("another label: %s", r)
	}

	tampered := append([]byte(nil), object...)
	tampered[len(tampered)-1] ^= 1
	_, err = verifySignedObject(objectLabel, tampered, "")
	if r := unverifiedReason(t, err); r != "signature_invalid" {
		t.Errorf("a flipped signature byte: %s", r)
	}

	_, err = verifySignedObject(objectLabel, object, "pq_pure")
	if r := unverifiedReason(t, err); r != "malformed" {
		t.Errorf("another profile's key: %s", r)
	}

	for name, b := range map[string][]byte{
		"not CBOR":     {0xff},
		"not a map":    cbor.Encode(cbor.Text("x")),
		"missing keys": cbor.Encode(cbor.Map([]cbor.MapEntry{{Key: cbor.Text("tbs"), Val: cbor.Bytes(nil)}})),
	} {
		_, err := verifySignedObject(objectLabel, b, "")
		if r := unverifiedReason(t, err); r != "malformed" {
			t.Errorf("%s: %s", name, r)
		}
	}

	for name, call := range map[string]func() error{
		"empty label": func() error { _, err := verifySignedObject("", object, ""); return err },
		"bad profile": func() error { _, err := verifySignedObject(objectLabel, object, "rsa"); return err },
	} {
		var ae *abiError
		if err := call(); !errors.As(err, &ae) || ae.kind != kindInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// macula-rag's signed corpus vectors (macula-rag ef6c536,
// test/vectors/signed_corpus.json): each verifies under its own profile to
// its signer and corpus_hash, and is malformed under the other.
func TestMaculaRagSignedCorpusVectors(t *testing.T) {
	const corpusLabel = "macula-rag corpus v1"
	raw, err := os.ReadFile(filepath.Join("testdata", "signed_corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Profile         string `json:"profile"`
		SignedBy        string `json:"signed_by"`
		CorpusHash      string `json:"corpus_hash"`
		SignatureBase64 string `json:"signature_base64"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 2 {
		t.Fatalf("%d vectors, not one per profile", len(vectors))
	}
	for _, v := range vectors {
		object, err := base64.StdEncoding.DecodeString(v.SignatureBase64)
		if err != nil {
			t.Fatal(err)
		}
		text, err := verifySignedObject(corpusLabel, object, v.Profile)
		if err != nil {
			t.Fatalf("%s: %v", v.Profile, err)
		}
		var got struct {
			NodeID string         `json:"node_id"`
			Fields map[string]any `json:"fields"`
		}
		if err := json.Unmarshal([]byte(text), &got); err != nil {
			t.Fatal(err)
		}
		if got.NodeID != v.SignedBy {
			t.Errorf("%s: node_id %s, not %s", v.Profile, got.NodeID, v.SignedBy)
		}
		if got.Fields["corpus_hash"] != v.CorpusHash {
			t.Errorf("%s: corpus_hash %v", v.Profile, got.Fields["corpus_hash"])
		}
		other := map[string]string{"pq_pure": "pq_hybrid", "pq_hybrid": "pq_pure"}[v.Profile]
		_, err = verifySignedObject(corpusLabel, object, other)
		if r := unverifiedReason(t, err); r != "malformed" {
			t.Errorf("%s under %s: %s", v.Profile, other, r)
		}
	}
}

func TestAnErrorThatIsNoVerdictIsFailedNotUnverified(t *testing.T) {
	var ae *abiError
	if !errors.As(errUnverified(identity.ErrPostQuantumUnavailable), &ae) || ae.kind != kindFailed {
		t.Fatalf("post-quantum unavailable: %v", ae)
	}
}
