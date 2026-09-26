package devicerequest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

// The vector is macula-realm's
// apps/macula_realm/test/macula_realm/identity/device_request_proof_vector.hex,
// the bytes MaculaRealm.Identity.DeviceRequestProof.message/6 builds for these
// inputs, decoded independently with cbor2.
func TestMessageReproducesTheRealmsVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "device_request_proof_vector.hex"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	request, err := JSONRequest([]byte(`{"device_info": {"hostname": "laptop.local", "note": null}, "n": 1e2, "z": -0.0, "f": 1.5}`))
	if err != nil {
		t.Fatal(err)
	}
	got := Message(bytes.Repeat([]byte{0x07}, 2592), sha256.Sum256([]byte("io.macula")), ProcedureJoinSession,
		1790000000000, [16]byte{}, request)
	if !bytes.Equal(got, want) {
		t.Fatalf("the message differs from the realm's vector:\n got %x\nwant %x", got, want)
	}
}

// The HTTP rule, as the realm applies it to a join-session body.
func TestJSONRequestFollowsTheRealmsRule(t *testing.T) {
	request, err := JSONRequest([]byte(`{"proof": {"v": 2}, "a": 1.0, "b": -0.0, "c": 2.5, "d": "x", "e": [1, null], "f": {"g": 9007199254740991}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("a"), Val: cbor.Int(1)},
		{Key: cbor.Text("b"), Val: cbor.Int(0)},
		{Key: cbor.Text("c"), Val: cbor.Float(2.5)},
		{Key: cbor.Text("d"), Val: cbor.Text("x")},
		{Key: cbor.Text("e"), Val: cbor.List([]cbor.Value{cbor.Int(1), cbor.Null()})},
		{Key: cbor.Text("f"), Val: cbor.Map([]cbor.MapEntry{{Key: cbor.Text("g"), Val: cbor.Int(9007199254740991)}})},
	})
	if !bytes.Equal(cbor.Encode(request), cbor.Encode(want)) {
		t.Fatalf("request: %v, want %v (proof dropped, integral numbers as integers)", request, want)
	}

	for body, refusal := range map[string]error{
		`{"a": true}`:              ErrBooleanNotAllowed,
		`{"a": [false]}`:           ErrBooleanNotAllowed,
		`{"a": 9007199254740992}`:  ErrNumberOutOfRange,
		`{"a": -9007199254740992}`: ErrNumberOutOfRange,
		`{"a": 1e20}`:              ErrNumberOutOfRange,
		`[1]`:                      ErrNotAJSONObject,
		`"text"`:                   ErrNotAJSONObject,
		`{"a": 1} {"b": 2}`:        ErrNotAJSONObject,
		`{`:                        ErrNotAJSONObject,
	} {
		if _, err := JSONRequest([]byte(body)); !errors.Is(err, refusal) {
			t.Errorf("%s: %v, want %v", body, err, refusal)
		}
	}
}

// A signed proof is the realm's shape, and its signature verifies over the
// message its own fields rebuild, with the key's own profile.
func TestSignedProofVerifiesOverItsMessage(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		key := teststation.Key(t, p, "device "+string(p))
		realm := sha256.Sum256([]byte("io.macula"))
		request, err := JSONRequest([]byte(`{"public_key": "a2V5", "device_info": {"hostname": "h"}}`))
		if err != nil {
			t.Fatal(err)
		}
		proof, err := Sign(key, realm, ProcedureJoinSession, request)
		if err != nil {
			t.Fatal(err)
		}
		if proof.V != Version || len(proof.Nonce) != 32 || proof.Timestamp == 0 {
			t.Fatalf("%s: proof %+v", p, proof)
		}
		nonce, _ := hex.DecodeString(proof.Nonce)
		signature, _ := hex.DecodeString(proof.Signature)
		message := Message(key.PublicKey(), realm, ProcedureJoinSession, proof.Timestamp, [16]byte(nonce), request)
		if !identity.Verify(message, signature, key.PublicKey(), p) {
			t.Fatalf("%s: the signature does not verify over its message", p)
		}
		other, err := JSONRequest([]byte(`{"public_key": "a2V5", "device_info": {"hostname": "evil"}}`))
		if err != nil {
			t.Fatal(err)
		}
		if identity.Verify(Message(key.PublicKey(), realm, ProcedureJoinSession, proof.Timestamp, [16]byte(nonce), other),
			signature, key.PublicKey(), p) {
			t.Fatalf("%s: the signature also verifies over another device_info", p)
		}
		again, err := Sign(key, realm, ProcedureJoinSession, request)
		if err != nil {
			t.Fatal(err)
		}
		if again.Nonce == proof.Nonce {
			t.Fatalf("%s: two proofs share a nonce", p)
		}
	}
}

// A request's caller is its verified signer, never one of its fields: the
// realm drops a "caller" when it rebuilds the signed request, on either
// transport, so a proof over one would fail there as bad_proof. Sign refuses
// such a request at the source, whichever rule built it.
func TestSignRefusesARequestCarryingACaller(t *testing.T) {
	key := teststation.Key(t, profile.PQPure, "device caller")
	realm := sha256.Sum256([]byte("io.macula"))
	http, err := JSONRequest([]byte(`{"public_key": "a2V5", "caller": "me"}`))
	if err != nil {
		t.Fatal(err)
	}
	mesh := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("caller"), Val: cbor.Bytes(make([]byte, 32))},
		{Key: cbor.Text("public_key"), Val: cbor.Text("a2V5")}})
	for name, request := range map[string]cbor.Value{"an HTTP body": http, "a mesh payload": mesh} {
		if _, err := Sign(key, realm, ProcedureJoinSession, request); !errors.Is(err, ErrCallerInRequest) {
			t.Errorf("%s: %v, want ErrCallerInRequest", name, err)
		}
	}
	nested, err := JSONRequest([]byte(`{"public_key": "a2V5", "device_info": {"caller": "a field of its own"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(key, realm, ProcedureJoinSession, nested); err != nil {
		t.Errorf("a nested caller is a field like any other: %v", err)
	}
}
