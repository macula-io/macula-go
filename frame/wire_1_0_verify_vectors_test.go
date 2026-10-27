package frame

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/internal/wire10vectors"
	"github.com/macula-io/macula-go/profile"
)

// The wire 1.0 frame cases in verify.json (macula priv/vectors/wire_1_0,
// macula#136, docs/design/WIRE_1_0.md section 3.2): a signed frame object that
// carries an extension inside its tbs. A non-critical one this reader does not
// know is ignored and counted by its name; a critical one refuses the object it
// sits in, extension_unsupported. Each case is put to the reader of the frame
// that carries it - a CALL or STREAM_OPEN to VerifyRequest, a RESULT or ERROR to
// VerifyReply against the request the case names, a STREAM_ERROR to
// VerifyProviderStream against that request's open stream - as macula's own
// runner does. The record class of the same file runs in package record.

// verifyExtName is the extension every case carries, and the name the tolerance
// counter counts it under.
const verifyExtName = "example.unknown"

func TestTheWireOneFrameExtVectors(t *testing.T) {
	f, err := wire10vectors.Load("verify")
	if err != nil {
		t.Fatal(err)
	}
	cases := 0
	for _, c := range f.Cases {
		if !strings.HasPrefix(c.ID, "frame.") {
			continue
		}
		cases++
		t.Run(c.ID, func(t *testing.T) {
			checkFrameExtVector(t, c)
		})
	}
	if cases == 0 {
		t.Fatal("verify.json holds no frame case")
	}
}

// checkFrameExtVector holds one frame case to its verdict, and an ignored
// extension to its counter.
func checkFrameExtVector(t *testing.T, c wire10vectors.Case) {
	t.Helper()
	p := profile.Profile(c.Profile)
	before := WireCounters().ExtIgnored[verifyExtName]
	err := verifyFrameExtCase(t, c, p)
	switch c.Outcome() {
	case "accept":
		if err != nil {
			t.Fatalf("%v, want it verified", err)
		}
		if c.ExpectText("count") == "wire_ext_ignored" && WireCounters().ExtIgnored[verifyExtName] <= before {
			t.Errorf("the ignored extension %s was not counted", verifyExtName)
		}
	case "refuse":
		if c.Reason() != "extension_unsupported" || !errors.Is(err, ErrExtensionUnsupported) {
			t.Fatalf("%v, want %s", err, c.Reason())
		}
		if WireCounters().ExtIgnored[verifyExtName] > before {
			t.Errorf("an extension inside a signed object was counted ignored as well as refused")
		}
	default:
		t.Fatalf("outcome %q has no check here", c.Outcome())
	}
}

// verifyFrameExtCase verifies a case's object as the frame that carries it.
func verifyFrameExtCase(t *testing.T, c wire10vectors.Case, p profile.Profile) error {
	t.Helper()
	object := signedVectorObject(t, c.Text("object"))
	switch frameTypeOf(t, object) {
	case frameTypeCall, frameTypeStreamOpen:
		_, err := VerifyRequest(carriedFrame(frameTypeOf(t, object), "request", object), p)
		return err
	case frameTypeResult, frameTypeError:
		request := verifiedVectorRequest(t, c.Text("request"), p)
		_, err := VerifyReply(carriedFrame(frameTypeOf(t, object), "reply", object), request, p)
		return err
	case frameTypeStreamError:
		request := verifiedVectorRequest(t, c.Text("request"), p)
		state, err := OpenStream(request)
		if err != nil {
			return err
		}
		_, _, err = VerifyProviderStream(carriedFrame(frameTypeStreamError, "stream", object), state, p)
		return err
	}
	t.Fatalf("%s: no reader for frame type %q", c.ID, frameTypeOf(t, object))
	return nil
}

// signedVectorObject is a case's bare signed object as a CBOR value.
func signedVectorObject(t *testing.T, hexObject string) cbor.Value {
	t.Helper()
	b, err := hex.DecodeString(hexObject)
	if err != nil {
		t.Fatalf("the case's object: %v", err)
	}
	v, err := cbor.Decode(b)
	if err != nil {
		t.Fatalf("the case's object: %v", err)
	}
	return v
}

// carriedFrame wraps a bare signed object as the frame that carries it, as it
// travels on the wire.
func carriedFrame(frameType, objectName string, object cbor.Value) cbor.Value {
	return envelopeOf(frameType, cbor.MapEntry{Key: cbor.Text(objectName), Val: object})
}

// frameTypeOf is the frame_type a signed object's tbs carries.
func frameTypeOf(t *testing.T, object cbor.Value) string {
	t.Helper()
	tbs, ok := object.Get("tbs")
	if !ok {
		t.Fatalf("the case's object carries no tbs")
	}
	raw, ok := tbs.AsBytes()
	if !ok {
		t.Fatalf("the case's tbs is not bytes")
	}
	fields, err := cbor.Decode(raw)
	if err != nil {
		t.Fatalf("the case's tbs: %v", err)
	}
	name, _ := fields.Get("frame_type")
	text, _ := name.AsText()
	return text
}

// verifiedVectorRequest is the request a case names, verified: what a RESULT,
// an ERROR or a STREAM_ERROR is read against.
func verifiedVectorRequest(t *testing.T, hexRequest string, p profile.Profile) VerifiedRequest {
	t.Helper()
	object := signedVectorObject(t, hexRequest)
	request, err := VerifyRequest(carriedFrame(frameTypeOf(t, object), "request", object), p)
	if err != nil {
		t.Fatalf("the case's request: %v", err)
	}
	return request
}
