package frame

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
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
	Design    string                    `json:"design"`
	Procedure string                    `json:"procedure"`
	Realm     string                    `json:"realm"`
	Profiles  map[string]refusalProfile `json:"profiles"`
}

// refusalProfile is one profile's refusals and the provider that made them.
type refusalProfile struct {
	Call          string `json:"call"`
	Refusal       string `json:"refusal"`
	StreamOpen    string `json:"stream_open"`
	StreamRefusal string `json:"stream_refusal"`
	Extension     string `json:"extension"`
	KEMKey        string `json:"kem_key"`
	KEMKeyID      string `json:"kem_key_id"`
	KEMKeySize    int    `json:"kem_key_size"`
	ProviderNode  string `json:"provider_node_id"`
}

// TestTheSealRefusalVectors holds the wire readers to macula's refusals: a
// clear CALL and a clear STREAM_OPEN are refused sealed_required, the refusal
// verifies against the request it names, and the key it carries is the
// provider's own, non-critical, under the name the vector states.
func TestTheSealRefusalVectors(t *testing.T) {
	v := loadRefusalVector(t)
	for name, c := range v.Profiles {
		t.Run(name, func(t *testing.T) {
			assertCallRefusalVector(t, v, c, profile.Profile(name))
			assertStreamRefusalVector(t, v, c, profile.Profile(name))
		})
	}
}

// assertCallRefusalVector checks a CALL's refusal: it verifies against the
// call, says sealed_required, and carries the key.
func assertCallRefusalVector(t *testing.T, v refusalVector, c refusalProfile, p profile.Profile) {
	t.Helper()
	request, err := VerifyRequest(wireFrame(t, c.Call), p)
	if err != nil {
		t.Fatalf("the vector's call: %v", err)
	}
	assertVectorRequest(t, v, c, request)
	if request.Sealed != nil {
		t.Fatal("the vector's call went out sealed, want the clear call that is refused")
	}
	reply, err := VerifyReply(wireFrame(t, c.Refusal), request, p)
	if err != nil {
		t.Fatalf("the refusal: %v", err)
	}
	if reply.FrameType != frameTypeError || reply.Code != refusalCodeSealedRequired {
		t.Fatalf("the refusal is %s %s, want error sealed_required", reply.FrameType, reply.Code)
	}
	if got := hex.EncodeToString(reply.RespondedBy[:]); got != c.ProviderNode {
		t.Errorf("the refusal answers as %s, want the provider it names, %s", got, c.ProviderNode)
	}
	assertCarriedKey(t, "the refusal", reply.Ext, c.KEMKey, c.KEMKeyID, c.KEMKeySize)
}

// assertStreamRefusalVector checks a STREAM_OPEN's refusal: the seq-0
// STREAM_ERROR verifies against the open, and carries the key.
func assertStreamRefusalVector(t *testing.T, v refusalVector, c refusalProfile, p profile.Profile) {
	t.Helper()
	open, err := VerifyRequest(wireFrame(t, c.StreamOpen), p)
	if err != nil {
		t.Fatalf("the vector's stream_open: %v", err)
	}
	assertVectorRequest(t, v, c, open)
	state, err := OpenStream(open)
	if err != nil {
		t.Fatalf("the vector's open: %v", err)
	}
	refusal, _, err := VerifyProviderStream(wireFrame(t, c.StreamRefusal), state, p)
	if err != nil {
		t.Fatalf("the stream refusal: %v", err)
	}
	if refusal.FrameType != frameTypeStreamError || refusal.Code != refusalCodeSealedRequired || refusal.Seq != 0 {
		t.Fatalf("the refusal is %s %s at seq %d, want stream_error sealed_required at seq 0",
			refusal.FrameType, refusal.Code, refusal.Seq)
	}
	if got := hex.EncodeToString(refusal.Signer[:]); got != c.ProviderNode {
		t.Errorf("the refusal is signed by %s, want the provider it names, %s", got, c.ProviderNode)
	}
	assertCarriedKey(t, "the stream refusal", refusal.Ext, c.KEMKey, c.KEMKeyID, c.KEMKeySize)
}

// assertVectorRequest checks the request both refusals answer is the vector's:
// the procedure and realm it states, to the provider it names.
func assertVectorRequest(t *testing.T, v refusalVector, c refusalProfile, request VerifiedRequest) {
	t.Helper()
	if request.Procedure != v.Procedure {
		t.Errorf("the request is for %q, want %q", request.Procedure, v.Procedure)
	}
	if got := hex.EncodeToString(request.Realm[:]); got != v.Realm {
		t.Errorf("the request's realm is %s, want %s", got, v.Realm)
	}
	if got := hex.EncodeToString(request.Target[:]); got != c.ProviderNode {
		t.Errorf("the request is addressed to %s, want the provider it names, %s", got, c.ProviderNode)
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

// A refusal carries its key inside the signed tbs, so no hop between the
// provider and the reader can strip it or put a key of its own there: rewrite
// the tbs and keep the vector's signature, and the reader must refuse, handing
// up no key. Without this a reader that took ext from the envelope rather than
// the tbs would pass every case above while a station answered a clear call
// with a key it chose.
func TestASealRefusalWithARewrittenTBSIsRefused(t *testing.T) {
	v := loadRefusalVector(t)
	for name, c := range v.Profiles {
		t.Run(name, func(t *testing.T) {
			p := profile.Profile(name)
			request, err := VerifyRequest(wireFrame(t, c.Call), p)
			if err != nil {
				t.Fatalf("the vector's call: %v", err)
			}
			open, err := VerifyRequest(wireFrame(t, c.StreamOpen), p)
			if err != nil {
				t.Fatalf("the vector's stream_open: %v", err)
			}
			state, err := OpenStream(open)
			if err != nil {
				t.Fatalf("the vector's open: %v", err)
			}
			another := bytes.Repeat([]byte{0x5a}, c.KEMKeySize)
			for _, tc := range []struct {
				what    string
				rewrite func([]cbor.MapEntry) []cbor.MapEntry
				refused bool
			}{
				// The control: an unchanged tbs re-encoded by this package still
				// verifies, so a refusal below is the rewrite and not the encoder.
				{"re-encoded with nothing changed", func(e []cbor.MapEntry) []cbor.MapEntry { return e }, false},
				{"with ext stripped", func(e []cbor.MapEntry) []cbor.MapEntry { return withoutEntry(e, "ext") }, true},
				{"with another key of the same size", func(e []cbor.MapEntry) []cbor.MapEntry {
					return withEntry(e, "ext", cbor.Map([]cbor.MapEntry{extension(ExtSealKEMKey, 0, cbor.Bytes(another))}))
				}, true},
			} {
				reply, err := VerifyReply(rewrittenTBS(t, wireFrame(t, c.Refusal), "reply", tc.rewrite), request, p)
				checkRewrittenRefusal(t, "the call's refusal "+tc.what, err, KEMKeyOf(reply.Ext), tc.refused, c.KEMKey)

				frame, _, err := VerifyProviderStream(rewrittenTBS(t, wireFrame(t, c.StreamRefusal), "stream", tc.rewrite), state, p)
				checkRewrittenRefusal(t, "the stream's refusal "+tc.what, err, KEMKeyOf(frame.Ext), tc.refused, c.KEMKey)
			}
		})
	}
}

// checkRewrittenRefusal holds one rewritten refusal to its verdict: refused,
// with no key, or verified and carrying the vector's own key.
func checkRewrittenRefusal(t *testing.T, what string, err error, key []byte, refused bool, wantKey string) {
	t.Helper()
	if refused {
		if err == nil {
			t.Fatalf("%s: verified, want it refused", what)
		}
		if key != nil {
			t.Errorf("%s: refused, yet handed up a %d-byte key", what, len(key))
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: %v, want it verified: the re-encode must be faithful", what, err)
	}
	if got := hex.EncodeToString(key); got != wantKey {
		t.Errorf("%s: carries key %s, want %s", what, got, wantKey)
	}
}

// KEMKeyOf is the carried key in ext, or nil.
func KEMKeyOf(ext cbor.Value) []byte {
	key, _ := KEMKeyFromExt(ext)
	return key
}

// rewrittenTBS is a refusal frame with its tbs decoded, handed to rewrite,
// re-encoded, and the vector's own signature kept: what a hop that rewrote an
// object it had no key for would send.
func rewrittenTBS(t *testing.T, frame cbor.Value, field string, rewrite func([]cbor.MapEntry) []cbor.MapEntry) cbor.Value {
	t.Helper()
	object := objectOf(t, frame, field)
	tbs, err := cbor.Decode(object.TBS)
	if err != nil {
		t.Fatalf("the refusal's tbs: %v", err)
	}
	entries, isMap := tbs.AsMap()
	if !isMap {
		t.Fatalf("the refusal's tbs is not a map")
	}
	rewritten := identity.Object{Key: object.Key, TBS: cbor.Encode(cbor.Map(rewrite(entries))), Signature: object.Signature}
	return frameWith(frame, field, rewritten.Value())
}

// A critical seal.kem_key is refused by name, as any critical extension is:
// the reader that cannot honour it must not read the object or its key.
func TestACriticalSealKEMKeyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	open := streamOpenOf(t, keys, ServerStream, idOf(7))
	critical := cbor.Map([]cbor.MapEntry{extension(ExtSealKEMKey, 1, cbor.Bytes(bytes.Repeat([]byte{7}, 1568)))})
	for _, tc := range []struct {
		what    string
		verify  func() error
		readKey func() bool
	}{
		{"a reply", func() error {
			fields := withEntry(replyTBS(request, frameTypeError), "ext", critical)
			fields = withEntry(fields, "code", cbor.Text(refusalCodeSealedRequired))
			_, err := VerifyReply(onWire(t, crafted(frameTypeError, "reply",
				signedWith(t, replyLabel, fields, keys.provider))), request, profile.PQPure)
			return err
		}, func() bool { return false }},
		{"a stream frame", func() error {
			fields := withEntry(streamTBSOf(open, frameTypeStreamError, keys.provider.KeyID(), 0,
				textEntry("code", refusalCodeSealedRequired), textEntry("message", "sealed")), "ext", critical)
			_, _, err := verifyProvider(t, crafted(frameTypeStreamError, "stream",
				signedWith(t, streamLabel, fields, keys.provider)), streamStateOf(t, open))
			return err
		}, func() bool { return false }},
	} {
		var unsupported *ExtensionUnsupportedError
		if err := tc.verify(); !errors.As(err, &unsupported) || !slices.Equal(unsupported.Names, []string{ExtSealKEMKey}) {
			t.Errorf("%s carrying a critical %s: %v, want it refused naming it", tc.what, ExtSealKEMKey, err)
		}
	}
}
