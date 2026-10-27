package frame

import (
	"errors"
	"slices"
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
// where the sealed-by-default work (macula#135) carries its key.
func TestAStreamFrameCarriesAnUnknownNonCriticalExtension(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, ServerStream, idOf(7))
	signer := keys.provider.KeyID()
	name := "seal.kem_key"
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
		"a criticality of null": cbor.Map([]cbor.MapEntry{{Key: cbor.Text("e"), Val: cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("critical"), Val: cbor.Null()},
			{Key: cbor.Text("value"), Val: cbor.Int(1)},
		})}}),
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

// A publication reads it too. The origin station verifies one before fan-out
// and every subscriber before delivery, so an Erlang or Rust publisher adding
// an extension reached neither: it was ErrMalformedFrame, and a Go subscriber
// dropped every PUBLISH, EVENT and GOSSIP that carried one.
func TestAPublicationIgnoresAnUnknownNonCriticalExtension(t *testing.T) {
	keys := requestKeysFor(t)
	name := "replica.hint"
	before := WireCounters().ExtIgnored[name]
	fields := withEntry(publicationTBS(keys.caller, testNow), "ext", unknownExt(name).Val)
	publication, err := verifyCraftedPublication(t, fields, keys.caller)
	if err != nil {
		t.Fatalf("a publication with an unknown non-critical extension: %v, want it verified", err)
	}
	if publication.Seq != 7 {
		t.Errorf("the publication read at seq %d, want 7", publication.Seq)
	}
	if got := WireCounters().ExtIgnored[name]; got != before+1 {
		t.Errorf("wire_ext_ignored{%s} = %d, want %d", name, got, before+1)
	}
}

// Every signed object this library verifies refuses a critical extension, not
// only the reply: a receiver that cannot honour one must not read the object.
// Erlang carries ext in five tables (macula_frame.erl: request, reply, relay
// error, publication, stream) and this is each of them.
func TestEverySignedObjectRefusesACriticalExtension(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	open := streamOpenOf(t, keys, ServerStream, idOf(7))
	state := streamStateOf(t, open)
	name := "seal.critical.hint"
	for _, tc := range []struct {
		object string
		verify func() error
	}{
		{"a request", func() error {
			return verifyCraftedRequest(t, frameTypeCall, withEntry(requestTBS(keys), "ext", criticalExt(name).Val), keys.caller)
		}},
		{"a reply", func() error {
			_, err := VerifyReply(onWire(t, crafted(frameTypeResult, "reply",
				signedWith(t, replyLabel, withEntry(replyTBS(request, frameTypeResult), "ext", criticalExt(name).Val), keys.provider))),
				request, profile.PQPure)
			return err
		}},
		{"a relay error", func() error {
			_, err := VerifyRelayError(onWire(t, crafted(frameTypeError, "relay_error",
				signedWith(t, relayErrorLabel, withEntry(relayTBS(request, keys.station), "ext", criticalExt(name).Val), keys.station))),
				request, profile.PQPure, keys.station.KeyID())
			return err
		}},
		{"a stream frame", func() error {
			_, _, err := verifyProvider(t, crafted(frameTypeStreamData, "stream",
				signedWith(t, streamLabel, withEntry(chunkTBS(open, keys.provider.KeyID(), 0), "ext", criticalExt(name).Val), keys.provider)), state)
			return err
		}},
		{"a publication", func() error {
			_, err := verifyCraftedPublication(t, withEntry(publicationTBS(keys.caller, testNow), "ext", criticalExt(name).Val), keys.caller)
			return err
		}},
	} {
		var unsupported *ExtensionUnsupportedError
		err := tc.verify()
		if !errors.As(err, &unsupported) || !slices.Equal(unsupported.Names, []string{name}) {
			t.Errorf("%s carrying a critical extension: %v, want it refused naming %s", tc.object, err, name)
		}
	}
}

// An ext map refused for one critical entry counts nothing: the count is for
// extensions that were read past, and this object is not read at all.
func TestANonCriticalBesideACriticalIsNotCounted(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	name := "replica.hint"
	before := WireCounters().ExtIgnored[name]
	ext := cbor.Map([]cbor.MapEntry{extension(name, 0, cbor.Text("x")), extension("no_such.extension", 1, cbor.Text("x"))})
	_, err := VerifyReply(onWire(t, crafted(frameTypeResult, "reply",
		signedWith(t, replyLabel, withEntry(replyTBS(request, frameTypeResult), "ext", ext), keys.provider))), request, profile.PQPure)
	var unsupported *ExtensionUnsupportedError
	if !errors.As(err, &unsupported) {
		t.Fatalf("a reply with a critical extension beside a non-critical one: %v, want ErrExtensionUnsupported", err)
	}
	if got := WireCounters().ExtIgnored[name]; got != before {
		t.Errorf("wire_ext_ignored{%s} = %d, want %d: a refused object counts nothing", name, got, before)
	}
}
