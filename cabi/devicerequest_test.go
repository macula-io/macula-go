package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/devicerequest"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

// The HTTP rule reaches the realm's vector through the ABI's request forms.
func TestAnHTTPRequestSignsTheRealmsVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "devicerequest", "testdata", "device_request_proof_vector.hex"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(strings.TrimSpace(string(raw)))
	request, err := signedRequest(`{"device_info": {"hostname": "laptop.local", "note": null}, "n": 1e2, "z": -0.0, "f": 1.5}`, requestHTTP)
	if err != nil {
		t.Fatal(err)
	}
	got := devicerequest.Message(bytes.Repeat([]byte{7}, 2592), sha256.Sum256([]byte("io.macula")),
		devicerequest.ProcedureJoinSession, 1790000000000, [16]byte{}, request)
	if !bytes.Equal(got, want) {
		t.Fatal("the HTTP form does not give the realm's vector")
	}
}

// A mesh request is the payload as it goes on the wire, less its proof: the
// same value a call with that payload carries.
func TestAMeshRequestIsThePayloadLessItsProof(t *testing.T) {
	request, err := signedRequest(`{"public_key": "a2V5", "ttl_seconds": 3600, "proof": {"v": 2}}`, requestMesh)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := payloadFromJSON(`{"public_key": "a2V5", "ttl_seconds": 3600}`)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cbor.Encode(request), cbor.Encode(payload)) {
		t.Fatalf("mesh request %v, want %v", request, payload)
	}
	for text, rule := range map[string]int32{`[1]`: requestMesh, `{"a": true}`: requestHTTP, `{"a": 1}`: 7} {
		if _, err := signedRequest(text, rule); kindOf(err) != kindInvalidArgument {
			t.Errorf("%s under rule %d: %v, want invalid_argument", text, rule, err)
		}
	}
}

func TestADeviceRequestProofVerifies(t *testing.T) {
	key := teststation.Key(t, profile.PQPure, "device")
	realm := sha256.Sum256([]byte("io.macula"))
	text, err := deviceRequestProof(key, realm, devicerequest.ProcedureMembershipUCAN, `{"public_key": "a2V5", "ttl_seconds": 3600}`, requestMesh)
	if err != nil {
		t.Fatal(err)
	}
	var proof devicerequest.Proof
	if err := json.Unmarshal([]byte(text), &proof); err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(proof.Nonce)
	signature, _ := hex.DecodeString(proof.Signature)
	request, _ := signedRequest(`{"public_key": "a2V5", "ttl_seconds": 3600}`, requestMesh)
	message := devicerequest.Message(key.PublicKey(), realm, devicerequest.ProcedureMembershipUCAN, proof.Timestamp,
		[16]byte(nonce), request)
	if proof.V != 2 || !identity.Verify(message, signature, key.PublicKey(), profile.PQPure) {
		t.Fatalf("proof %s does not verify", text)
	}
}
