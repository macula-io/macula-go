package frame

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// A signed object's own extension map (WIRE_1_0.md section 3.2, macula#42).
// `ext` sits inside the tbs, so its criticality is covered by the signature: a
// receiver that does not know a non-critical entry ignores it and counts
// wire_ext_ignored, and one that carries a critical entry is refused rather
// than read. Before this a signed reply, request or stream frame carrying any
// extension was ErrMalformedFrame, so an Erlang or Rust peer adding one made
// every call in Go run to its deadline.

// unknownExt is an extension no reader of wire 1.0 knows yet, at criticality
// 0: the shape a peer sends when it announces a new extension.
func unknownExt(name string) cbor.MapEntry {
	return extEntry(extension(name, 0, cbor.Text("x")))
}

// criticalExt is an extension at criticality 1, which no receiver has to read.
func criticalExt(name string) cbor.MapEntry {
	return extEntry(extension(name, 1, cbor.Text("x")))
}

// TestASignedReplyIgnoresAndCountsAnUnknownNonCriticalExtension holds a RESULT
// and an ERROR to the same rule: the object verifies, and the extension counts
// under its name.
func TestASignedReplyIgnoresAndCountsAnUnknownNonCriticalExtension(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	name := "replica.hint"
	for _, frameType := range []string{frameTypeResult, frameTypeError} {
		before := WireCounters().ExtIgnored[name]
		fields := withEntry(replyTBS(request, frameType), "ext", unknownExt(name).Val)
		reply, err := VerifyReply(onWire(t, crafted(frameType, "reply", signedWith(t, replyLabel, fields, keys.provider))),
			request, profile.PQPure)
		if err != nil {
			t.Fatalf("%s with an unknown non-critical extension: %v, want it verified", frameType, err)
		}
		if reply.FrameType != frameType {
			t.Errorf("%s verified as %s", frameType, reply.FrameType)
		}
		if got := WireCounters().ExtIgnored[name]; got != before+1 {
			t.Errorf("wire_ext_ignored{%s} = %d, want %d", name, got, before+1)
		}
	}
}

// A critical extension is not read: the signature covers its criticality, so no
// hop can have changed it, and the object is refused by name.
func TestASignedReplyWithACriticalExtensionIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	fields := withEntry(replyTBS(request, frameTypeResult), "ext", criticalExt("no_such.extension").Val)
	_, err := VerifyReply(onWire(t, crafted(frameTypeResult, "reply", signedWith(t, replyLabel, fields, keys.provider))),
		request, profile.PQPure)
	if !errors.Is(err, ErrExtensionUnsupported) {
		t.Fatalf("VerifyReply = %v, want ErrExtensionUnsupported", err)
	}
	var unsupported *ExtensionUnsupportedError
	if !errors.As(err, &unsupported) || len(unsupported.Names) != 1 || unsupported.Names[0] != "no_such.extension" {
		t.Errorf("the refusal names %+v, want [no_such.extension]", unsupported)
	}
}

// A provider's relay error is a signed object of its own and reads the same
// way.
func TestARelayErrorIgnoresAnUnknownNonCriticalExtension(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	station := keys.station
	name := "replica.hint"
	before := WireCounters().ExtIgnored[name]
	fields := withEntry(relayTBS(request, station), "ext", unknownExt(name).Val)
	_, err := VerifyRelayError(onWire(t, crafted(frameTypeError, "relay_error",
		signedWith(t, relayErrorLabel, fields, station))), request, profile.PQPure, station.KeyID())
	if err != nil {
		t.Fatalf("a relay error with an unknown non-critical extension: %v, want it verified", err)
	}
	if got := WireCounters().ExtIgnored[name]; got != before+1 {
		t.Errorf("wire_ext_ignored{%s} = %d, want %d", name, got, before+1)
	}
}

// A request reads it too, so a caller that adds one is not refused by a
// provider or a station.
func TestARequestIgnoresAnUnknownNonCriticalExtension(t *testing.T) {
	keys := requestKeysFor(t)
	name := "replica.hint"
	before := WireCounters().ExtIgnored[name]
	fields := withEntry(requestTBS(keys), "ext", unknownExt(name).Val)
	if err := verifyCraftedRequest(t, frameTypeCall, fields, keys.caller); err != nil {
		t.Fatalf("a CALL with an unknown non-critical extension: %v, want it verified", err)
	}
	if got := WireCounters().ExtIgnored[name]; got != before+1 {
		t.Errorf("wire_ext_ignored{%s} = %d, want %d", name, got, before+1)
	}
}

// And a stream frame: the seq-0 STREAM_DATA a provider sends first is exactly
// where the sealed-by-default work (macula#135) carries its key, in an
// extension of its own.
func TestAStreamFrameCarriesAnUnknownNonCriticalExtension(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, ServerStream, idOf(7))
	signer := keys.provider.KeyID()
	name := "stream.hint"
	before := WireCounters().ExtIgnored[name]
	fields := withEntry(chunkTBS(open, signer, 0), "ext", unknownExt(name).Val)
	stream, _, err := verifyProvider(t, crafted(frameTypeStreamData, "stream",
		signedWith(t, streamLabel, fields, keys.provider)), streamStateOf(t, open))
	if err != nil {
		t.Fatalf("a stream frame with an unknown non-critical extension: %v, want it verified", err)
	}
	if stream.Seq != 0 {
		t.Errorf("the frame verified at seq %d, want 0", stream.Seq)
	}
	if got := WireCounters().ExtIgnored[name]; got != before+1 {
		t.Errorf("wire_ext_ignored{%s} = %d, want %d", name, got, before+1)
	}
}

// An ext map of the wrong shape is malformed, not ignored: an empty map (a
// frame with no extensions omits the key), more than 16 entries, a name
// outside [a-z0-9_.], a criticality that is not 0 or 1, and an entry that is
// not exactly {critical, value}.
func TestAMalformedTBSExtensionIsAMalformedFrame(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	seventeen := make([]cbor.MapEntry, 17)
	for i := range seventeen {
		seventeen[i] = extension("e"+strings.Repeat("x", i), 0, cbor.Int(1))
	}
	for name, ext := range map[string]cbor.Value{
		"an empty ext map":     cbor.Map(nil),
		"seventeen extensions": cbor.Map(seventeen),
		"an upper-case name":   cbor.Map([]cbor.MapEntry{extension("Trace", 0, cbor.Int(1))}),
		"a criticality of 2":   cbor.Map([]cbor.MapEntry{extension("e", 2, cbor.Int(1))}),
		"a name over 64 bytes": cbor.Map([]cbor.MapEntry{extension(strings.Repeat("a", 65), 0, cbor.Int(1))}),
		"an entry with no value": cbor.Map([]cbor.MapEntry{{Key: cbor.Text("e"), Val: cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("critical"), Val: cbor.Int(0)},
		})}}),
	} {
		fields := withEntry(replyTBS(request, frameTypeResult), "ext", ext)
		_, err := VerifyReply(onWire(t, crafted(frameTypeResult, "reply", signedWith(t, replyLabel, fields, keys.provider))),
			request, profile.PQPure)
		wantRefusal(t, name, err, ErrMalformedFrame)
	}
}

// An extension's value may be null: absent is omitted and null is no protocol
// field's value, but an extension's value is the peer's own, so only the
// frame's payload and an extension's value may hold one.
func TestAnExtensionsValueMayHoldNull(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	fields := withEntry(replyTBS(request, frameTypeResult), "ext",
		cbor.Map([]cbor.MapEntry{extension("trace.hint", 0, cbor.Null())}))
	if _, err := VerifyReply(onWire(t, crafted(frameTypeResult, "reply", signedWith(t, replyLabel, fields, keys.provider))),
		request, profile.PQPure); err != nil {
		t.Fatalf("a reply whose extension value is null: %v, want it verified", err)
	}
}

// A keyed provider's sealed_required refusal carries the KEM key it holds in a
// non-critical seal.kem_key entry of its tbs (DESIGN_E2E_SEALED_BY_DEFAULT.md
// section 3, release A0). The reader recognises the name, so the entry is not
// counted as ignored, and hands the key up for the link to check against its
// profile.
func TestASealedRequiredRefusalCarriesTheProvidersKEMKey(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	kemKey := bytes.Repeat([]byte{7}, 1568)
	before := WireCounters().ExtIgnored[ExtSealKEMKey]
	fields := withEntry(replyTBS(request, frameTypeError), "ext",
		cbor.Map([]cbor.MapEntry{extension(ExtSealKEMKey, 0, cbor.Bytes(kemKey))}))
	reply, err := VerifyReply(onWire(t, crafted(frameTypeError, "reply",
		signedWith(t, replyLabel, fields, keys.provider))), request, profile.PQPure)
	if err != nil {
		t.Fatalf("a sealed_required carrying its key: %v, want it verified", err)
	}
	carried, ok := KEMKeyFromExt(reply.Ext)
	if !ok || !bytes.Equal(carried, kemKey) {
		t.Errorf("KEMKeyFromExt = %d bytes, %v; want the %d the refusal carried", len(carried), ok, len(kemKey))
	}
	if after := WireCounters().ExtIgnored[ExtSealKEMKey]; after != before {
		t.Errorf("wire_ext_ignored{%s} = %d, want %d: a known extension is read, not ignored", ExtSealKEMKey, after, before)
	}
}

// A value that is not bytes names no key: the refusal then surfaces as the
// provider's own sealed_required.
func TestAKEMKeyThatIsNotBytesNamesNoKey(t *testing.T) {
	for name, value := range map[string]cbor.Value{
		"a text value": cbor.Text("not a key"),
		"an int value": cbor.Int(1),
		"no entry":     cbor.Map([]cbor.MapEntry{extension("other.ext", 0, cbor.Bytes([]byte{1}))}),
		"an empty map": cbor.Map(nil),
	} {
		if key, ok := KEMKeyFromExt(value); ok {
			t.Errorf("%s: KEMKeyFromExt = %d bytes, true; want none", name, len(key))
		}
	}
}
