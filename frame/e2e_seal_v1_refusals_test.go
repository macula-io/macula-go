package frame

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
)

// macula's keyed refusals (test/vectors/e2e_seal_v1_refusals.json, copied by
// scripts/interop/copy_e2e_seal_vectors.sh): per profile, a keyed provider's
// refusal of a clear CALL and of a clear STREAM_OPEN, each beside the request
// it answers. macula generates the file from its own link, and
// testdata/../seal/testdata/E2E_SEAL_V1.md's "A refusal carrying the key"
// states what every reader must find in it: the refusal verifies against the
// request it names, and its signed tbs carries the provider's KEM key under
// the non-critical extension seal.kem_key.

// refusalCodeSealedRequired is the refusal code a keyed provider answers a
// clear call or open with.
const refusalCodeSealedRequired = "sealed_required"

// refusalVector is e2e_seal_v1_refusals.json.
type refusalVector struct {
	Design    string `json:"design"`
	Procedure string `json:"procedure"`
	Realm     string `json:"realm"`
	Profiles  map[string]struct {
		Call          string `json:"call"`
		Refusal       string `json:"refusal"`
		StreamOpen    string `json:"stream_open"`
		StreamRefusal string `json:"stream_refusal"`
		Extension     string `json:"extension"`
		KEMKey        string `json:"kem_key"`
		KEMKeyID      string `json:"kem_key_id"`
		KEMKeySize    int    `json:"kem_key_size"`
		ProviderNode  string `json:"provider_node_id"`
	} `json:"profiles"`
}

// TestTheSealRefusalVectors holds the wire readers to macula's refusals: a
// clear CALL and a clear STREAM_OPEN are refused sealed_required, the refusal
// verifies against the request it names, and the key it carries is the
// provider's own, non-critical, under the name the vector states.
func TestTheSealRefusalVectors(t *testing.T) {
	v := loadRefusalVector(t)
	for name, c := range v.Profiles {
		t.Run(name, func(t *testing.T) {
			assertCallRefusalVector(t, v, profile.Profile(name), c.Call, c.Refusal, c.KEMKey, c.KEMKeyID, c.KEMKeySize)
			assertStreamRefusalVector(t, v, profile.Profile(name), c.StreamOpen, c.StreamRefusal, c.KEMKey, c.KEMKeyID, c.KEMKeySize)
		})
	}
}

// assertCallRefusalVector checks a CALL's refusal: it verifies against the
// call, says sealed_required, and carries the key.
func assertCallRefusalVector(t *testing.T, v refusalVector, p profile.Profile, callHex, refusalHex, keyHex, keyIDHex string, keySize int) {
	t.Helper()
	request, err := VerifyRequest(wireFrame(t, callHex), p)
	if err != nil {
		t.Fatalf("the vector's call: %v", err)
	}
	assertVectorRequest(t, v, request)
	if request.Sealed != nil {
		t.Fatal("the vector's call went out sealed, want the clear call that is refused")
	}
	reply, err := VerifyReply(wireFrame(t, refusalHex), request, p)
	if err != nil {
		t.Fatalf("the refusal: %v", err)
	}
	if reply.FrameType != frameTypeError || reply.Code != refusalCodeSealedRequired {
		t.Fatalf("the refusal is %s %s, want error sealed_required", reply.FrameType, reply.Code)
	}
	if reply.RespondedBy != request.Target {
		t.Errorf("the refusal answers as %x, want the call's target %x", reply.RespondedBy, request.Target)
	}
	assertCarriedKey(t, "the refusal", reply.Ext, keyHex, keyIDHex, keySize)
}

// assertStreamRefusalVector checks a STREAM_OPEN's refusal: the seq-0
// STREAM_ERROR verifies against the open, and carries the key.
func assertStreamRefusalVector(t *testing.T, v refusalVector, p profile.Profile, openHex, refusalHex, keyHex, keyIDHex string, keySize int) {
	t.Helper()
	open, err := VerifyRequest(wireFrame(t, openHex), p)
	if err != nil {
		t.Fatalf("the vector's stream_open: %v", err)
	}
	assertVectorRequest(t, v, open)
	state, err := OpenStream(open)
	if err != nil {
		t.Fatalf("the vector's open: %v", err)
	}
	refusal, _, err := VerifyProviderStream(wireFrame(t, refusalHex), state, p)
	if err != nil {
		t.Fatalf("the stream refusal: %v", err)
	}
	if refusal.FrameType != frameTypeStreamError || refusal.Code != refusalCodeSealedRequired || refusal.Seq != 0 {
		t.Fatalf("the refusal is %s %s at seq %d, want stream_error sealed_required at seq 0",
			refusal.FrameType, refusal.Code, refusal.Seq)
	}
	if refusal.Signer != open.Target {
		t.Errorf("the refusal is signed by %x, want the open's target %x", refusal.Signer, open.Target)
	}
	assertCarriedKey(t, "the stream refusal", refusal.Ext, keyHex, keyIDHex, keySize)
}

// assertVectorRequest checks the request both refusals answer is the vector's:
// the procedure and realm it states, to the provider it names.
func assertVectorRequest(t *testing.T, v refusalVector, request VerifiedRequest) {
	t.Helper()
	if request.Procedure != v.Procedure {
		t.Errorf("the request is for %q, want %q", request.Procedure, v.Procedure)
	}
	if got := hex.EncodeToString(request.Realm[:]); got != v.Realm {
		t.Errorf("the request's realm is %s, want %s", got, v.Realm)
	}
}

// assertCarriedKey checks a refusal's ext holds the vector's key under the name
// the vector states, non-critically, and that the reader finds it there.
func assertCarriedKey(t *testing.T, what string, ext cbor.Value, keyHex, keyIDHex string, keySize int) {
	t.Helper()
	key, ok := KEMKeyFromExt(ext)
	if !ok {
		t.Fatalf("%s carries no %s", what, ExtSealKEMKey)
	}
	if got := hex.EncodeToString(key); got != keyHex {
		t.Errorf("%s carries key %s, want %s", what, got, keyHex)
	}
	if len(key) != keySize {
		t.Errorf("%s carries a %d-byte key, want %d", what, len(key), keySize)
	}
	if id := seal.KeyID(key); hex.EncodeToString(id[:]) != keyIDHex {
		t.Errorf("%s carries a key whose id is %x, want %s", what, id, keyIDHex)
	}
	entries, _ := ext.AsMap()
	if len(entries) != 1 {
		t.Fatalf("%s carries %d extensions, want just %s", what, len(entries), ExtSealKEMKey)
	}
	name, _ := entries[0].Key.AsText()
	if name != ExtSealKEMKey {
		t.Errorf("%s carries %q, want %s", what, name, ExtSealKEMKey)
	}
	if critical, ok := extensionCriticality(entries[0].Val); !ok || critical {
		t.Errorf("%s's %s is critical or unreadable, want non-critical", what, ExtSealKEMKey)
	}
}

// wireFrame is a vector's frame: four bytes of length, then the CBOR frame, as
// a control frame and a dedicated stream carry one on the wire.
func wireFrame(t *testing.T, hexFrame string) cbor.Value {
	t.Helper()
	b, err := hex.DecodeString(hexFrame)
	if err != nil {
		t.Fatalf("the vector's frame: %v", err)
	}
	if len(b) < 4 {
		t.Fatalf("the vector's frame is %d bytes, want a length and a frame", len(b))
	}
	length := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if length != len(b)-4 {
		t.Fatalf("the vector's frame says %d bytes, its frame is %d", length, len(b)-4)
	}
	v, err := cbor.Decode(b[4:])
	if err != nil {
		t.Fatalf("the vector's frame: %v", err)
	}
	return v
}

// loadRefusalVector reads the copied e2e_seal_v1_refusals.json.
func loadRefusalVector(t *testing.T) refusalVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "e2e_seal_v1_refusals.json"))
	if err != nil {
		t.Fatalf("%v (run scripts/interop/copy_e2e_seal_vectors.sh)", err)
	}
	var v refusalVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("e2e_seal_v1_refusals.json: %v", err)
	}
	if len(v.Profiles) == 0 {
		t.Fatal("e2e_seal_v1_refusals.json holds no profile")
	}
	return v
}
