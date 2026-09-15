package frame

import (
	"crypto/fips140"
	"errors"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// frameWithout is the frame v without its field name.
func frameWithout(v cbor.Value, name string) cbor.Value {
	entries, _ := v.AsMap()
	return cbor.Map(withoutEntry(entries, name))
}

// A frame around a signed object is read as a received frame is decoded before
// its object is verified, as macula_frame's field tables and receive rules read
// it: the routing fields a frame kind carries verify, and a version other than
// the protocol's, a missing version, a routing field that is null or not of its
// kind, a retry budget of 2^53, and the other frame kind's routing field are each
// refused as malformed. A stream frame carries no routing field.
func TestAFrameAroundASignedObjectIsReadAsAReceivedFrameIs(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	call := must[cbor.Value](t)(SignCall(callSpec(keys), keys.caller))
	result := must[cbor.Value](t)(SignResult(request, cbor.Uint64(1), nil, keys.provider))
	relay := must[cbor.Value](t)(SignRelayError(RelayErrorSpec{FrameType: frameTypeError, Request: request, Code: "unknown_next_peer"},
		keys.station))
	providerData := must[cbor.Value](t)(SignProviderStream(streamChunk(0), open, keys.provider))
	callerData := must[cbor.Value](t)(SignCallerStream(streamChunk(0), open, keys.caller))
	verifyRequest := func(v cbor.Value) error {
		_, err := VerifyRequest(onWire(t, v), profile.PQPure)
		return err
	}
	verifyReply := func(v cbor.Value) error {
		_, err := VerifyReply(onWire(t, v), request, profile.PQPure)
		return err
	}
	verifyRelayError := func(v cbor.Value) error {
		_, err := VerifyRelayError(onWire(t, v), request, profile.PQPure, keys.station.KeyID())
		return err
	}
	verifyProviderStream := func(v cbor.Value) error {
		_, _, err := verifyProvider(t, v, streamStateOf(t, open))
		return err
	}
	verifyCallerStream := func(v cbor.Value) error {
		_, _, err := verifyCaller(t, v, streamStateOf(t, open))
		return err
	}
	route, otherVersion := cbor.Bytes([]byte{1, 2}), cbor.Uint64(ProtocolVersion+1)
	type frameCase struct {
		name   string
		frame  cbor.Value
		verify func(cbor.Value) error
	}

	for _, c := range []frameCase{
		{"a CALL with a source route and a retry budget of 2^53 - 1",
			frameWith(frameWith(call, "source_route", route), "retry_budget", cbor.Uint64(maxProtocolInt-1)), verifyRequest},
		{"a RESULT with a reverse source route", frameWith(result, "source_route_reverse", route), verifyReply},
		{"a relay ERROR with a partial source route", frameWith(relay, "source_route_partial", route), verifyRelayError},
		{"a provider's STREAM_DATA", providerData, verifyProviderStream},
		{"a caller's STREAM_DATA", callerData, verifyCallerStream},
	} {
		if err := c.verify(c.frame); err != nil {
			t.Errorf("%s: %v, want it verified", c.name, err)
		}
	}
	for _, c := range []frameCase{
		{"a CALL of another version", frameWith(call, "version", otherVersion), verifyRequest},
		{"a CALL without its version", frameWithout(call, "version"), verifyRequest},
		{"a CALL with a null source route", frameWith(call, "source_route", cbor.Null()), verifyRequest},
		{"a CALL with a source route as text", frameWith(call, "source_route", cbor.Text("a route")), verifyRequest},
		{"a CALL with a null retry budget", frameWith(call, "retry_budget", cbor.Null()), verifyRequest},
		{"a CALL with a retry budget of 2^53", frameWith(call, "retry_budget", cbor.Uint64(maxProtocolInt)), verifyRequest},
		{"a CALL with a reply's reverse source route", frameWith(call, "source_route_reverse", route), verifyRequest},
		{"a RESULT of another version", frameWith(result, "version", otherVersion), verifyReply},
		{"a RESULT without its version", frameWithout(result, "version"), verifyReply},
		{"a RESULT with a null reverse source route", frameWith(result, "source_route_reverse", cbor.Null()), verifyReply},
		{"a RESULT with a relay error's partial source route", frameWith(result, "source_route_partial", route), verifyReply},
		{"a relay ERROR of another version", frameWith(relay, "version", otherVersion), verifyRelayError},
		{"a relay ERROR without its version", frameWithout(relay, "version"), verifyRelayError},
		{"a relay ERROR with a partial source route as text", frameWith(relay, "source_route_partial", cbor.Text("a route")), verifyRelayError},
		{"a relay ERROR with a request's source route", frameWith(relay, "source_route", route), verifyRelayError},
		{"a provider's STREAM_DATA of another version", frameWith(providerData, "version", otherVersion), verifyProviderStream},
		{"a provider's STREAM_DATA without its version", frameWithout(providerData, "version"), verifyProviderStream},
		{"a provider's STREAM_DATA with a partial source route", frameWith(providerData, "source_route_partial", route), verifyProviderStream},
		{"a caller's STREAM_DATA of another version", frameWith(callerData, "version", otherVersion), verifyCallerStream},
		{"a caller's STREAM_DATA without its version", frameWithout(callerData, "version"), verifyCallerStream},
		{"a caller's STREAM_DATA with a source route", frameWith(callerData, "source_route", route), verifyCallerStream},
	} {
		wantRefusal(t, c.name, c.verify(c.frame), ErrMalformedFrame)
	}
}

// A binary built with GOFIPS140=v1.0.0 cannot check a signed frame's signature,
// so VerifyRequest, VerifyReply, VerifyRelayError, VerifyProviderStream and
// VerifyCallerStream say so with identity.ErrPostQuantumUnavailable alone, not
// as a malformed frame or a signature that does not verify. In any other binary
// the same frames reach the signature check and are refused as invalid
// signatures, and nothing else. Which way a run goes is read from
// crypto/fips140, not from the check under test. CI runs this test both ways.
func TestASignedFrameVerifierSaysWhetherTheBinaryHasMLDSA(t *testing.T) {
	carriedKey, tbs := make([]byte, 2592), cbor.Encode(cbor.Map(nil))
	signature := make([]byte, identity.SignatureSize(profile.PQPure))
	object := identity.Object{Key: carriedKey, TBS: tbs, Signature: signature}.Value()
	held := identity.HeldObject{TBS: tbs, Signature: signature}.Value()
	_, requestErr := VerifyRequest(crafted(frameTypeCall, "request", object), profile.PQPure)
	_, replyErr := VerifyReply(crafted(frameTypeResult, "reply", object), VerifiedRequest{}, profile.PQPure)
	_, relayErr := VerifyRelayError(crafted(frameTypeError, "relay_error", object), VerifiedRequest{}, profile.PQPure, [32]byte{})
	_, _, providerErr := VerifyProviderStream(crafted(frameTypeStreamData, "stream", object), StreamState{}, profile.PQPure)
	_, _, callerErr := VerifyCallerStream(crafted(frameTypeStreamData, "caller_stream", held),
		StreamState{open: VerifiedRequest{Key: carriedKey}}, profile.PQPure)
	want, notWant := identity.ErrObjectSignatureInvalid, identity.ErrPostQuantumUnavailable
	if strings.HasPrefix(fips140.Version(), "v1.0.") {
		want, notWant = identity.ErrPostQuantumUnavailable, identity.ErrObjectSignatureInvalid
	}
	for name, err := range map[string]error{"VerifyRequest": requestErr, "VerifyReply": replyErr, "VerifyRelayError": relayErr,
		"VerifyProviderStream": providerErr, "VerifyCallerStream": callerErr} {
		if !errors.Is(err, want) || errors.Is(err, notWant) || errors.Is(err, ErrMalformedFrame) {
			t.Errorf("%s with the module %s: %v, want %v alone, not %v or a malformed frame", name, fips140.Version(), err, want, notWant)
		}
	}
}

// A build with more than one fault is refused for the first in macula's order:
// the key, then the text, then the payload, then a field's range; for a relay
// error the key, then the code's set, then the frame type; and for a stream
// frame the key, then the frame types its side sends, then the text, then the
// body or payload, then a field's range.
func TestABuildIsRefusedForItsFirstFaultInMaculasOrder(t *testing.T) {
	keys := requestKeysFor(t)
	connectKey := must[*identity.NodeKey](t)(identity.GenerateKey(identity.PurposeConnect, profile.PQPure))
	request := verifiedCall(t, keys)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	noMode, longWithMode := callSpec(keys), callSpec(keys)
	longWithMode.Procedure, longWithMode.Mode = strings.Repeat("p", 513), modeOf(Bidi)
	badRelay := RelayErrorSpec{FrameType: frameTypeResult, Request: request, Code: "no_route"}
	unsendable := cbor.Map([]cbor.MapEntry{textEntry("unsendable", "\xff")})

	_, err := SignStreamOpen(noMode, connectKey)
	wantRefusal(t, "a STREAM_OPEN with a CONNECT key and no mode", err, ErrUnsignable)
	_, err = SignCall(longWithMode, keys.caller)
	wantRefusal(t, "a CALL with a 513-byte procedure and a mode", err, ErrTextTooLong)
	_, err = SignRelayError(badRelay, keys.station)
	wantRefusal(t, "a relay error with code no_route and frame type result", err, ErrRelayCodeOutsideItsSet)
	_, err = SignRelayError(badRelay, connectKey)
	wantRefusal(t, "a relay error with a CONNECT key, code no_route and frame type result", err, ErrUnsignable)
	_, err = SignCallerStream(StreamReplyFields{Payload: unsendable}, open, keys.provider)
	wantRefusal(t, "a caller's STREAM_REPLY with the provider's key and a payload the wire cannot carry", err, ErrUnsignable)
	_, err = SignCallerStream(StreamReplyFields{Payload: unsendable}, open, keys.caller)
	wantRefusal(t, "a caller's STREAM_REPLY with a payload the wire cannot carry", err, ErrNotAllowed)
	_, err = SignProviderStream(StreamErrorFields{Seq: maxProtocolInt, Code: strings.Repeat("c", 65)}, open, keys.provider)
	wantRefusal(t, "a STREAM_ERROR with a 65-byte code and a seq of 2^53", err, ErrTextTooLong)
	_, err = SignProviderStream(StreamDataFields{Seq: maxProtocolInt, Encoding: Msgpack, Body: unsendable}, open, keys.provider)
	if want := CheckPayload(unsendable); err == nil || err.Error() != want.Error() {
		t.Errorf("a STREAM_DATA with a body the wire cannot carry and a seq of 2^53: %v, want %v", err, want)
	}
}
