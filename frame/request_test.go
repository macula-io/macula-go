package frame

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_frame_request_tests at merge-11.0.0
// 335b114f (DESIGN_PQ_SIGNED_FRAMES_AND_RECORDS.md: Requests, Replies and Relay
// errors; D25). CALL and STREAM_OPEN carry request, a {key, tbs, signature}
// under MACULA-PQ-REQUEST-V1 signed by the caller; RESULT and ERROR from a
// provider carry reply under MACULA-PQ-REPLY-V1; ERROR and STREAM_ERROR from a
// station carry relay_error under MACULA-PQ-RELAY-ERROR-V1. caller,
// responded_by and reported_by are key ids.

const (
	testProcedure = "acme/get_forecast_v1"
	testDeadline  = uint64(1789000600000)
)

type requestKeys struct {
	caller, provider, station, other *identity.NodeKey
}

var generatedRequestKeys = sync.OnceValues(func() (requestKeys, error) {
	var keys requestKeys
	for _, slot := range []**identity.NodeKey{&keys.caller, &keys.provider, &keys.station, &keys.other} {
		key, err := identity.GenerateKey(identity.PurposeIdentity, profile.PQPure)
		if err != nil {
			return requestKeys{}, err
		}
		*slot = key
	}
	return keys, nil
})

func requestKeysFor(t *testing.T) requestKeys {
	t.Helper()
	keys, err := generatedRequestKeys()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	return keys
}

// must checks a result that must not be an error.
func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return v
	}
}

func wantRefusal(t *testing.T, name string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", name, err, want)
	}
}

func idOf(n byte) (id [16]byte) {
	id[15] = n
	return id
}

func testRealm() (realm [32]byte) {
	realm[31] = 1
	return realm
}

func targetOf(keys requestKeys) [32]byte { return keys.provider.KeyID() }

func callSpec(keys requestKeys) RequestSpec {
	return RequestSpec{
		RequestID: idOf(7),
		Realm:     testRealm(),
		Procedure: testProcedure,
		Target:    targetOf(keys),
		Deadline:  testDeadline,
		Payload:   cbor.Map([]cbor.MapEntry{textEntry("city", "Tienen")}),
	}
}

// onWire is a frame as a peer receives it: encoded and decoded.
func onWire(t *testing.T, v cbor.Value) cbor.Value {
	t.Helper()
	encoded, err := Encode(v)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil || !decoded.Complete || decoded.Consumed != len(encoded) {
		t.Fatalf("Decode: (%+v, %v)", decoded, err)
	}
	return decoded.Frame
}

func verifiedRequestOf(t *testing.T, key *identity.NodeKey, spec RequestSpec) VerifiedRequest {
	t.Helper()
	return must[VerifiedRequest](t)(VerifyRequest(onWire(t, must[cbor.Value](t)(SignCall(spec, key))), profile.PQPure))
}

func verifiedCall(t *testing.T, keys requestKeys) VerifiedRequest {
	t.Helper()
	return verifiedRequestOf(t, keys.caller, callSpec(keys))
}

func verifiedStreamOpen(t *testing.T, keys requestKeys) VerifiedRequest {
	t.Helper()
	spec := callSpec(keys)
	spec.Mode = modeOf(ServerStream)
	return must[VerifiedRequest](t)(VerifyRequest(onWire(t, must[cbor.Value](t)(SignStreamOpen(spec, keys.caller))), profile.PQPure))
}

func modeOf(mode StreamMode) *StreamMode {
	return &mode
}

// requestTBS is the fields of a CALL request as its signer puts them in tbs;
// signing adds alg.
func requestTBS(keys requestKeys) []cbor.MapEntry {
	caller, requestID, realm, target := keys.caller.KeyID(), idOf(7), testRealm(), targetOf(keys)
	return []cbor.MapEntry{
		textEntry("frame_type", frameTypeCall),
		bytesEntry("caller", caller[:]),
		bytesEntry("request_id", requestID[:]),
		bytesEntry("realm", realm[:]),
		textEntry("procedure", testProcedure),
		bytesEntry("target", target[:]),
		uintEntry("deadline", testDeadline),
		uintEntry("payload", 1),
	}
}

func replyTBS(request VerifiedRequest, frameType string) []cbor.MapEntry {
	fields := []cbor.MapEntry{
		textEntry("frame_type", frameType),
		bytesEntry("request_id", request.RequestID[:]),
		bytesEntry("request_hash", request.RequestHash[:]),
		bytesEntry("responded_by", request.Target[:]),
	}
	if frameType == frameTypeResult {
		return append(fields, uintEntry("payload", 1))
	}
	return append(fields, textEntry("code", "closed"))
}

func relayTBS(request VerifiedRequest, station *identity.NodeKey) []cbor.MapEntry {
	reportedBy := station.KeyID()
	return []cbor.MapEntry{
		textEntry("frame_type", frameTypeError),
		bytesEntry("request_id", request.RequestID[:]),
		bytesEntry("request_hash", request.RequestHash[:]),
		bytesEntry("reported_by", reportedBy[:]),
		textEntry("code", "unknown_next_peer"),
	}
}

// withEntry is entries with name set to value, replacing any entry it held.
func withEntry(entries []cbor.MapEntry, name string, value cbor.Value) []cbor.MapEntry {
	return append(withoutEntry(entries, name), cbor.MapEntry{Key: cbor.Text(name), Val: value})
}

func withoutEntry(entries []cbor.MapEntry, name string) []cbor.MapEntry {
	return slices.DeleteFunc(slices.Clone(entries), func(e cbor.MapEntry) bool {
		key, _ := e.Key.AsText()
		return key == name
	})
}

func signedWith(t *testing.T, label string, fields []cbor.MapEntry, key *identity.NodeKey) cbor.Value {
	t.Helper()
	return must[identity.Object](t)(identity.SignObject(label, fields, key)).Value()
}

// crafted is a frame around one signed object, with the version the codec
// writes.
func crafted(frameType, field string, object cbor.Value) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		uintEntry("version", ProtocolVersion),
		textEntry("frame_type", frameType),
		valueEntry(field, object),
	})
}

func verifyCraftedRequest(t *testing.T, frameType string, fields []cbor.MapEntry, key *identity.NodeKey) error {
	t.Helper()
	_, err := VerifyRequest(onWire(t, crafted(frameType, "request", signedWith(t, requestLabel, fields, key))), profile.PQPure)
	return err
}

// frameWith is the frame v with its field name set to value.
func frameWith(v cbor.Value, name string, value cbor.Value) cbor.Value {
	entries, _ := v.AsMap()
	return cbor.Map(withEntry(entries, name, value))
}

// objectOf is the signed object a frame carries under name.
func objectOf(t *testing.T, v cbor.Value, name string) identity.Object {
	t.Helper()
	field, _ := v.Get(name)
	return must[identity.Object](t)(identity.ParseObject(field))
}

// withFlippedTBS is the frame v with one bit changed in the tbs of the object
// under name.
func withFlippedTBS(t *testing.T, v cbor.Value, name string) cbor.Value {
	t.Helper()
	object := objectOf(t, v, name)
	object.TBS = bytes.Clone(object.TBS)
	object.TBS[20] ^= 1
	return frameWith(v, name, object.Value())
}

func sortedKeys(v cbor.Value) []string {
	entries, _ := v.AsMap()
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		key, _ := e.Key.AsText()
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

//------------------------------------------------------------------
// Requests: CALL and STREAM_OPEN
//------------------------------------------------------------------

func TestASignedCallVerifiesWithItsCallerKeyAndRequestHash(t *testing.T) {
	keys := requestKeysFor(t)
	frame := onWire(t, must[cbor.Value](t)(SignCall(callSpec(keys), keys.caller)))
	object := objectOf(t, frame, "request")
	request := must[VerifiedRequest](t)(VerifyRequest(frame, profile.PQPure))
	if request.FrameType != frameTypeCall || request.RequestID != idOf(7) || request.Realm != testRealm() ||
		request.Procedure != testProcedure || request.Deadline != testDeadline {
		t.Errorf("the verified request's fields: %+v", request)
	}
	if !bytes.Equal(object.Key, keys.caller.PublicKey()) || !bytes.Equal(request.Key, object.Key) {
		t.Error("the request does not carry the caller's key, or verifies to another key")
	}
	if request.Caller != keys.caller.KeyID() || request.Target != targetOf(keys) {
		t.Error("the request's caller or target is not the caller's or the provider's key id")
	}
	if request.RequestHash != sha512.Sum384(object.TBS) {
		t.Error("the request hash is not the SHA-384 of the tbs")
	}
	if !bytes.Equal(cbor.Encode(request.Payload), cbor.Encode(callSpec(keys).Payload)) {
		t.Error("the verified payload is not the signed payload")
	}
}

func TestACallFrameCarriesVersionFrameTypeRequestAndItsRoutingFields(t *testing.T) {
	keys := requestKeysFor(t)
	spec := callSpec(keys)
	budget := uint64(3)
	spec.SourceRoute, spec.RetryBudget = []byte{1, 2}, &budget
	routed := onWire(t, must[cbor.Value](t)(SignCall(spec, keys.caller)))
	request, _ := routed.Get("request")
	plain := onWire(t, must[cbor.Value](t)(SignCall(callSpec(keys), keys.caller)))
	if got := sortedKeys(routed); !slices.Equal(got, []string{"frame_type", "request", "retry_budget", "source_route", "version"}) {
		t.Errorf("a routed CALL's fields: %v", got)
	}
	if got := sortedKeys(request); !slices.Equal(got, []string{"key", "signature", "tbs"}) {
		t.Errorf("a request's fields: %v", got)
	}
	if got := sortedKeys(plain); !slices.Equal(got, []string{"frame_type", "request", "version"}) {
		t.Errorf("a CALL's fields: %v", got)
	}
	if _, err := VerifyRequest(routed, profile.PQPure); err != nil {
		t.Errorf("a routed CALL: %v, want it verified", err)
	}
}

func TestAStreamOpenCarriesItsMode(t *testing.T) {
	keys := requestKeysFor(t)
	if open := verifiedStreamOpen(t, keys); open.FrameType != frameTypeStreamOpen || open.Mode == nil || *open.Mode != ServerStream {
		t.Errorf("a STREAM_OPEN verifies as %s with mode %v, want stream_open with server_stream", open.FrameType, open.Mode)
	}
	if call := verifiedCall(t, keys); call.Mode != nil {
		t.Errorf("a CALL verifies with mode %s, want none", call.Mode.Name())
	}
}

// Mode belongs to a STREAM_OPEN only: SignCall refuses a CALL with a mode and
// SignStreamOpen a STREAM_OPEN without one or with an unknown one, and a
// verifier refuses a CALL whose tbs names one and a STREAM_OPEN whose tbs names
// none.
func TestModeBelongsToStreamOpenOnly(t *testing.T) {
	keys := requestKeysFor(t)
	withMode, withoutMode, unknownMode := callSpec(keys), callSpec(keys), callSpec(keys)
	withMode.Mode, unknownMode.Mode = modeOf(Bidi), modeOf(StreamMode(7))
	_, err := SignCall(withMode, keys.caller)
	wantRefusal(t, "a CALL with a mode", err, ErrOutOfRange)
	_, err = SignStreamOpen(withoutMode, keys.caller)
	wantRefusal(t, "a STREAM_OPEN without a mode", err, ErrOutOfRange)
	_, err = SignStreamOpen(unknownMode, keys.caller)
	wantRefusal(t, "a STREAM_OPEN of an unknown mode", err, ErrOutOfRange)
	wantRefusal(t, "a CALL whose tbs names a mode",
		verifyCraftedRequest(t, frameTypeCall, withEntry(requestTBS(keys), "mode", cbor.Text("bidi")), keys.caller), ErrMalformedFrame)
	wantRefusal(t, "a STREAM_OPEN whose tbs names no mode",
		verifyCraftedRequest(t, frameTypeStreamOpen, withEntry(requestTBS(keys), "frame_type", cbor.Text(frameTypeStreamOpen)), keys.caller),
		ErrMalformedFrame)
}

func TestATokenIsOptionalBytes(t *testing.T) {
	keys := requestKeysFor(t)
	spec := callSpec(keys)
	spec.Token = []byte("a token")
	if request := verifiedRequestOf(t, keys.caller, spec); !bytes.Equal(request.Token, []byte("a token")) {
		t.Errorf("a request's token: %q, want %q", request.Token, "a token")
	}
	if request := verifiedCall(t, keys); request.Token != nil {
		t.Errorf("a request without a token verifies with token %q", request.Token)
	}
	wantRefusal(t, "a token as text",
		verifyCraftedRequest(t, frameTypeCall, withEntry(requestTBS(keys), "token", cbor.Text("a token")), keys.caller), ErrMalformedFrame)
}

func TestACallerThatIsNotTheKeyIDOfItsKeyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	other := keys.other.KeyID()
	wantRefusal(t, "another node's key id as caller",
		verifyCraftedRequest(t, frameTypeCall, withEntry(requestTBS(keys), "caller", cbor.Bytes(other[:])), keys.caller), ErrKeyIDMismatch)
}

func TestATamperedRequestIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	frame := must[cbor.Value](t)(SignCall(callSpec(keys), keys.caller))
	_, err := VerifyRequest(onWire(t, withFlippedTBS(t, frame, "request")), profile.PQPure)
	wantRefusal(t, "a tampered request", err, identity.ErrObjectSignatureInvalid)
}

func TestARequestUnderAnotherLabelIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	frame := crafted(frameTypeCall, "request", signedWith(t, replyLabel, requestTBS(keys), keys.caller))
	_, err := VerifyRequest(onWire(t, frame), profile.PQPure)
	wantRefusal(t, "a request under the reply label", err, identity.ErrObjectSignatureInvalid)
}

func TestRequestFieldsTheDesignDoesNotAllowAreMalformed(t *testing.T) {
	keys := requestKeysFor(t)
	base := requestTBS(keys)
	if err := verifyCraftedRequest(t, frameTypeCall, base, keys.caller); err != nil {
		t.Fatalf("the crafted request: %v, want it verified", err)
	}
	requestID, target := idOf(7), targetOf(keys)
	cases := []struct {
		name   string
		fields []cbor.MapEntry
	}{
		{"an extra field", withEntry(base, "extra", cbor.Uint64(1))},
		{"no target", withoutEntry(base, "target")},
		{"a 15-byte request_id", withEntry(base, "request_id", cbor.Bytes(requestID[1:]))},
		{"a 31-byte target", withEntry(base, "target", cbor.Bytes(target[1:]))},
		{"a deadline at 2^53", withEntry(base, "deadline", cbor.Uint64(1<<53))},
		{"a deadline as text", withEntry(base, "deadline", cbor.Text("soon"))},
		{"the procedure as bytes", withEntry(base, "procedure", cbor.Bytes([]byte(testProcedure)))},
		{"a frame_type of result", withEntry(base, "frame_type", cbor.Text(frameTypeResult))},
	}
	for _, c := range cases {
		wantRefusal(t, c.name, verifyCraftedRequest(t, frameTypeCall, c.fields, keys.caller), ErrMalformedFrame)
	}
}

// A procedure name is text of at most 512 bytes: the builder refuses a longer
// one and one that is not UTF-8, and a verifier refuses a request whose
// procedure is longer.
func TestAProcedureIsTextOfAtMost512Bytes(t *testing.T) {
	keys := requestKeysFor(t)
	long := strings.Repeat("p", 512)
	spec := callSpec(keys)
	spec.Procedure = long
	if request := verifiedRequestOf(t, keys.caller, spec); request.Procedure != long {
		t.Errorf("a 512-byte procedure verifies as %d bytes", len(request.Procedure))
	}
	spec.Procedure = long + "p"
	_, err := SignCall(spec, keys.caller)
	wantRefusal(t, "a 513-byte procedure", err, ErrTextTooLong)
	spec.Procedure, spec.Mode = "\xff\xfe", modeOf(Bidi)
	_, err = SignStreamOpen(spec, keys.caller)
	wantRefusal(t, "a procedure that is not UTF-8", err, ErrInvalidText)
	wantRefusal(t, "a request whose procedure is 513 bytes",
		verifyCraftedRequest(t, frameTypeCall, withEntry(requestTBS(keys), "procedure", cbor.Text(long+"p")), keys.caller), ErrMalformedFrame)
}

func TestARequestUnderTheOtherProfileIsMalformed(t *testing.T) {
	keys := requestKeysFor(t)
	_, err := VerifyRequest(onWire(t, must[cbor.Value](t)(SignCall(callSpec(keys), keys.caller))), profile.PQHybrid)
	wantRefusal(t, "a pq_pure request under pq_hybrid", err, ErrMalformedFrame)
}

func TestTwoCallersNeverShareARequestHash(t *testing.T) {
	keys := requestKeysFor(t)
	if verifiedRequestOf(t, keys.caller, callSpec(keys)).RequestHash == verifiedRequestOf(t, keys.other, callSpec(keys)).RequestHash {
		t.Error("two callers' requests with the same fields share a request hash")
	}
}

//------------------------------------------------------------------
// Replies: RESULT and ERROR from a provider
//------------------------------------------------------------------

func TestAResultFromTheTargetVerifiesForItsRequest(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	payload := cbor.Map([]cbor.MapEntry{uintEntry("temp", 21)})
	result := onWire(t, must[cbor.Value](t)(SignResult(request, payload, nil, keys.provider)))
	if got := sortedKeys(result); !slices.Equal(got, []string{"frame_type", "reply", "version"}) {
		t.Errorf("a RESULT's fields: %v", got)
	}
	reply := must[VerifiedReply](t)(VerifyReply(result, request, profile.PQPure))
	if reply.FrameType != frameTypeResult || reply.RespondedBy != targetOf(keys) || reply.Code != "" || reply.Detail != nil ||
		!bytes.Equal(cbor.Encode(reply.Payload), cbor.Encode(payload)) {
		t.Errorf("the verified RESULT: %+v", reply)
	}
}

func TestAProviderErrorCarriesItsCodeAndDetail(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	detail := "after six"
	detailed := onWire(t, must[cbor.Value](t)(SignProviderError(request, "closed", &detail, nil, keys.provider)))
	reply := must[VerifiedReply](t)(VerifyReply(detailed, request, profile.PQPure))
	if reply.FrameType != frameTypeError || reply.RespondedBy != targetOf(keys) || reply.Code != "closed" ||
		reply.Detail == nil || *reply.Detail != detail {
		t.Errorf("the verified ERROR with a detail: %+v", reply)
	}
	bare := onWire(t, must[cbor.Value](t)(SignProviderError(request, "closed", nil, nil, keys.provider)))
	if reply := must[VerifiedReply](t)(VerifyReply(bare, request, profile.PQPure)); reply.Code != "closed" || reply.Detail != nil {
		t.Errorf("the verified ERROR without a detail: %+v", reply)
	}
}

// A provider error's code is text of at most 64 bytes and its detail text of at
// most 256: at the bound it verifies, and one byte over is malformed.
func TestAnErrorCodeAndDetailAreReadWithinTheirBounds(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	verify := func(field string, size int) (VerifiedReply, error) {
		fields := withEntry(withEntry(replyTBS(request, frameTypeError), "detail", cbor.Text("d")), field, cbor.Text(strings.Repeat("a", size)))
		frame := crafted(frameTypeError, "reply", signedWith(t, replyLabel, fields, keys.provider))
		return VerifyReply(onWire(t, frame), request, profile.PQPure)
	}
	if reply, err := verify("code", 64); err != nil || len(reply.Code) != 64 {
		t.Errorf("a 64-byte code: (%d bytes, %v), want it verified", len(reply.Code), err)
	}
	if reply, err := verify("detail", 256); err != nil || reply.Detail == nil || len(*reply.Detail) != 256 {
		t.Errorf("a 256-byte detail: %v, want it verified", err)
	}
	_, err := verify("code", 65)
	wantRefusal(t, "a 65-byte code", err, ErrMalformedFrame)
	_, err = verify("detail", 257)
	wantRefusal(t, "a 257-byte detail", err, ErrMalformedFrame)
}

// A provider error is built with a code of at most 64 bytes and a detail of at
// most 256, both UTF-8.
func TestAProviderErrorBuilderRefusesTextOutsideItsBounds(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	build := func(code string, detail *string) error {
		_, err := SignProviderError(request, code, detail, nil, keys.provider)
		return err
	}
	atBound, overBound, notText := strings.Repeat("d", 256), strings.Repeat("d", 257), "\xff"
	if err := build(strings.Repeat("c", 64), &atBound); err != nil {
		t.Errorf("a 64-byte code and a 256-byte detail: %v, want them built", err)
	}
	wantRefusal(t, "a 65-byte code", build(strings.Repeat("c", 65), nil), ErrTextTooLong)
	wantRefusal(t, "a 257-byte detail", build("c", &overBound), ErrTextTooLong)
	wantRefusal(t, "a code that is not UTF-8", build("\xff", nil), ErrInvalidText)
	wantRefusal(t, "a detail that is not UTF-8", build("c", &notText), ErrInvalidText)
}

// A reply from a node other than the target is refused: the builder will not
// sign one, and a verifier refuses one another node signed.
func TestAReplyFromANodeOtherThanTheTargetIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	_, err := SignResult(request, cbor.Uint64(1), nil, keys.other)
	wantRefusal(t, "SignResult with a key other than the target's", err, ErrUnsignable)
	other := keys.other.KeyID()
	fields := withEntry(replyTBS(request, frameTypeResult), "responded_by", cbor.Bytes(other[:]))
	_, err = VerifyReply(onWire(t, crafted(frameTypeResult, "reply", signedWith(t, replyLabel, fields, keys.other))), request, profile.PQPure)
	wantRefusal(t, "a reply another node signed", err, ErrNotTheTarget)
}

func TestAReplyForAnotherRequestIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	result := onWire(t, must[cbor.Value](t)(SignResult(request, cbor.Uint64(1), nil, keys.provider)))
	anotherSpec := callSpec(keys)
	anotherSpec.RequestID = idOf(8)
	_, err := VerifyReply(result, verifiedRequestOf(t, keys.caller, anotherSpec), profile.PQPure)
	wantRefusal(t, "a reply checked against another request_id", err, ErrRequestMismatch)
	otherHash := request
	otherHash.RequestHash = sha512.Sum384([]byte("another request"))
	_, err = VerifyReply(result, otherHash, profile.PQPure)
	wantRefusal(t, "a reply checked against another request_hash", err, ErrRequestMismatch)
}

func TestARespondedByThatIsNotTheKeyIDOfItsKeyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	other := keys.other.KeyID()
	fields := withEntry(replyTBS(request, frameTypeResult), "responded_by", cbor.Bytes(other[:]))
	_, err := VerifyReply(onWire(t, crafted(frameTypeResult, "reply", signedWith(t, replyLabel, fields, keys.provider))), request, profile.PQPure)
	wantRefusal(t, "another node's key id as responded_by", err, ErrKeyIDMismatch)
}

func TestATamperedReplyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	result := must[cbor.Value](t)(SignResult(request, cbor.Uint64(1), nil, keys.provider))
	_, err := VerifyReply(onWire(t, withFlippedTBS(t, result, "reply")), request, profile.PQPure)
	wantRefusal(t, "a tampered reply", err, identity.ErrObjectSignatureInvalid)
}

func TestReplyFieldsTheDesignDoesNotAllowAreMalformed(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	verify := func(frameType string, fields []cbor.MapEntry) error {
		_, err := VerifyReply(onWire(t, crafted(frameType, "reply", signedWith(t, replyLabel, fields, keys.provider))), request, profile.PQPure)
		return err
	}
	result, providerError := replyTBS(request, frameTypeResult), replyTBS(request, frameTypeError)
	if err := verify(frameTypeResult, result); err != nil {
		t.Fatalf("the crafted RESULT: %v, want it verified", err)
	}
	if err := verify(frameTypeError, providerError); err != nil {
		t.Fatalf("the crafted ERROR: %v, want it verified", err)
	}
	hash := request.RequestHash
	cases := []struct {
		name, frameType string
		fields          []cbor.MapEntry
	}{
		{"a RESULT with a code", frameTypeResult, withEntry(result, "code", cbor.Text("closed"))},
		{"a RESULT without its payload", frameTypeResult, withoutEntry(result, "payload")},
		{"an ERROR with a payload", frameTypeError, withEntry(providerError, "payload", cbor.Uint64(1))},
		{"an ERROR without its code", frameTypeError, withoutEntry(providerError, "code")},
		{"a 47-byte request_hash", frameTypeResult, withEntry(result, "request_hash", cbor.Bytes(hash[1:]))},
		{"an extra field", frameTypeResult, withEntry(result, "extra", cbor.Uint64(1))},
		{"a RESULT's tbs in an ERROR frame", frameTypeError, result},
	}
	for _, c := range cases {
		wantRefusal(t, c.name, verify(c.frameType, c.fields), ErrMalformedFrame)
	}
}

//------------------------------------------------------------------
// Relay errors: ERROR and STREAM_ERROR from a station
//------------------------------------------------------------------

func TestARelayErrorVerifiesForItsRequest(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	hop := [32]byte{31: 9}
	spec := RelayErrorSpec{FrameType: frameTypeError, Request: request, Code: "unknown_next_peer", OffendingHop: &hop}
	relay := onWire(t, must[cbor.Value](t)(SignRelayError(spec, keys.station)))
	if got := sortedKeys(relay); !slices.Equal(got, []string{"frame_type", "relay_error", "version"}) {
		t.Errorf("a relay ERROR's fields: %v", got)
	}
	verified := must[VerifiedRelayError](t)(VerifyRelayError(relay, request, profile.PQPure, keys.station.KeyID()))
	if verified.FrameType != frameTypeError || verified.ReportedBy != keys.station.KeyID() || verified.Code != "unknown_next_peer" ||
		verified.OffendingHop == nil || *verified.OffendingHop != hop {
		t.Errorf("the verified relay error: %+v", verified)
	}
}

// A relay error carries a code from its closed set and no free text: its spec
// has no detail, and a verifier refuses a relay error whose tbs holds one.
func TestARelayErrorCarriesNoDetail(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	fields := withEntry(relayTBS(request, keys.station), "detail", cbor.Text("no route"))
	frame := crafted(frameTypeError, "relay_error", signedWith(t, relayErrorLabel, fields, keys.station))
	_, err := VerifyRelayError(onWire(t, frame), request, profile.PQPure, keys.station.KeyID())
	wantRefusal(t, "a relay error with a detail", err, ErrMalformedFrame)
}

func TestAStreamErrorFromAStationIsARelayError(t *testing.T) {
	keys := requestKeysFor(t)
	open := verifiedStreamOpen(t, keys)
	spec := RelayErrorSpec{FrameType: frameTypeStreamError, Request: open, Code: "unknown_next_peer"}
	relay := onWire(t, must[cbor.Value](t)(SignRelayError(spec, keys.station)))
	verified := must[VerifiedRelayError](t)(VerifyRelayError(relay, open, profile.PQPure, keys.station.KeyID()))
	if verified.FrameType != frameTypeStreamError || verified.ReportedBy != keys.station.KeyID() || verified.Code != "unknown_next_peer" ||
		verified.OffendingHop != nil {
		t.Errorf("the verified relay STREAM_ERROR: %+v", verified)
	}
}

func TestARelayCodeOutsideTheClosedSetIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	_, err := SignRelayError(RelayErrorSpec{FrameType: frameTypeError, Request: request, Code: "no_route"}, keys.station)
	wantRefusal(t, "a relay error built with code no_route", err, ErrRelayCodeOutsideItsSet)
	fields := withEntry(relayTBS(request, keys.station), "code", cbor.Text("no_route"))
	frame := crafted(frameTypeError, "relay_error", signedWith(t, relayErrorLabel, fields, keys.station))
	_, err = VerifyRelayError(onWire(t, frame), request, profile.PQPure, keys.station.KeyID())
	wantRefusal(t, "a relay error with code no_route", err, ErrMalformedFrame)
}

func TestARelayErrorForAnotherRequestIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	spec := RelayErrorSpec{FrameType: frameTypeError, Request: request, Code: "unknown_next_peer"}
	relay := onWire(t, must[cbor.Value](t)(SignRelayError(spec, keys.station)))
	anotherSpec := callSpec(keys)
	anotherSpec.RequestID = idOf(8)
	_, err := VerifyRelayError(relay, verifiedRequestOf(t, keys.caller, anotherSpec), profile.PQPure, keys.station.KeyID())
	wantRefusal(t, "a relay error checked against another request", err, ErrRequestMismatch)
}

func TestAReportedByThatIsNotTheKeyIDOfItsKeyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	other := keys.other.KeyID()
	fields := withEntry(relayTBS(request, keys.station), "reported_by", cbor.Bytes(other[:]))
	frame := crafted(frameTypeError, "relay_error", signedWith(t, relayErrorLabel, fields, keys.station))
	_, err := VerifyRelayError(onWire(t, frame), request, profile.PQPure, keys.station.KeyID())
	wantRefusal(t, "another node's key id as reported_by", err, ErrKeyIDMismatch)
}

// A relay error counts only from the station the connection authenticated: one
// that another station reports is refused as not the connection's, once its
// signature and request checks pass.
func TestARelayErrorFromAStationOtherThanTheConnectionIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	spec := RelayErrorSpec{FrameType: frameTypeError, Request: request, Code: "unknown_next_peer"}
	relay := onWire(t, must[cbor.Value](t)(SignRelayError(spec, keys.other)))
	_, err := VerifyRelayError(relay, request, profile.PQPure, keys.station.KeyID())
	wantRefusal(t, "a relay error another station reported", err, ErrNotTheConnection)
	if verified, err := VerifyRelayError(relay, request, profile.PQPure, keys.other.KeyID()); err != nil ||
		verified.FrameType != frameTypeError || verified.Code != "unknown_next_peer" {
		t.Errorf("the same relay error from its own connection: (%+v, %v), want it verified", verified, err)
	}
}

// An ERROR frame carries a provider's reply or a station's relay error, never
// both, and each verifier refuses the other's.
func TestAnErrorFrameIsEitherAReplyOrARelayError(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	providerError := must[cbor.Value](t)(SignProviderError(request, "closed", nil, nil, keys.provider))
	relay := must[cbor.Value](t)(SignRelayError(RelayErrorSpec{FrameType: frameTypeError, Request: request, Code: "unknown_next_peer"}, keys.station))
	_, err := VerifyReply(onWire(t, relay), request, profile.PQPure)
	wantRefusal(t, "a relay error read as a reply", err, ErrMalformedFrame)
	_, err = VerifyRelayError(onWire(t, providerError), request, profile.PQPure, keys.station.KeyID())
	wantRefusal(t, "a provider error read as a relay error", err, ErrMalformedFrame)
	reply, _ := providerError.Get("reply")
	relayError, _ := relay.Get("relay_error")
	_, err = VerifyReply(onWire(t, frameWith(providerError, "relay_error", relayError)), request, profile.PQPure)
	wantRefusal(t, "an ERROR holding both objects, read as a reply", err, ErrMalformedFrame)
	_, err = VerifyRelayError(onWire(t, frameWith(relay, "reply", reply)), request, profile.PQPure, keys.station.KeyID())
	wantRefusal(t, "an ERROR holding both objects, read as a relay error", err, ErrMalformedFrame)
}

//------------------------------------------------------------------
// The ids a reply names, before it is verified
//------------------------------------------------------------------

func TestClaimedIDsComeFromAResultAnErrorAndARelayError(t *testing.T) {
	keys := requestKeysFor(t)
	request, open := verifiedCall(t, keys), verifiedStreamOpen(t, keys)
	if request.RequestID != idOf(7) || open.RequestID != idOf(7) || request.RequestHash == ([48]byte{}) ||
		open.RequestHash == request.RequestHash {
		t.Fatalf("the CALL and STREAM_OPEN verified without their own ids: (%x, %x), (%x, %x)",
			request.RequestID, request.RequestHash, open.RequestID, open.RequestHash)
	}
	replies := map[string]cbor.Value{
		"a RESULT":         must[cbor.Value](t)(SignResult(request, cbor.Uint64(1), nil, keys.provider)),
		"a provider ERROR": must[cbor.Value](t)(SignProviderError(request, "closed", nil, nil, keys.provider)),
		"a relay ERROR": must[cbor.Value](t)(SignRelayError(RelayErrorSpec{FrameType: frameTypeError, Request: request, Code: "unknown_next_peer"},
			keys.station)),
	}
	for name, frame := range replies {
		requestID, requestHash, err := ClaimedReplyIDs(onWire(t, frame))
		if err != nil || requestID != request.RequestID || requestHash != request.RequestHash {
			t.Errorf("%s: (%x, %v), want the request's ids", name, requestID, err)
		}
	}
	streamRelay := must[cbor.Value](t)(SignRelayError(RelayErrorSpec{FrameType: frameTypeStreamError, Request: open, Code: "unknown_next_peer"},
		keys.station))
	if requestID, requestHash, err := ClaimedReplyIDs(onWire(t, streamRelay)); err != nil ||
		requestID != open.RequestID || requestHash != open.RequestHash {
		t.Errorf("a relay STREAM_ERROR: (%x, %v), want the STREAM_OPEN's ids", requestID, err)
	}
}

// A frame of another type or with a field a reply does not have, a signed
// object without its key, a tbs that is not CBOR, and a tbs whose ids are
// missing or of another length name no request.
func TestClaimedIDsAreMalformedForAnythingElse(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	result := must[cbor.Value](t)(SignResult(request, cbor.Uint64(1), nil, keys.provider))
	signed := objectOf(t, result, "reply")
	notCBOR := signed
	notCBOR.TBS = []byte("not cbor")
	tbs := replyTBS(request, frameTypeResult)
	craftedResult := func(fields []cbor.MapEntry) cbor.Value {
		return crafted(frameTypeResult, "reply", signedWith(t, replyLabel, fields, keys.provider))
	}
	hash := request.RequestHash
	refused := map[string]cbor.Value{
		"a CALL":                       must[cbor.Value](t)(SignCall(callSpec(keys), keys.caller)),
		"a RESULT with a source_route": frameWith(result, "source_route", cbor.Bytes([]byte("a route"))),
		"a reply without its key": frameWith(result, "reply",
			cbor.Map([]cbor.MapEntry{bytesEntry("tbs", signed.TBS), bytesEntry("signature", signed.Signature)})),
		"a tbs that is not CBOR":       frameWith(result, "reply", notCBOR.Value()),
		"a tbs without its request_id": craftedResult(withoutEntry(tbs, "request_id")),
		"a 47-byte request_hash":       craftedResult(withEntry(tbs, "request_hash", cbor.Bytes(hash[1:]))),
	}
	for name, frame := range refused {
		_, _, err := ClaimedReplyIDs(frame)
		wantRefusal(t, name, err, ErrMalformedFrame)
	}
}

// Ids that name a pending request decide nothing: a reply from a node other
// than the target, and one whose signature does not verify, both name that
// request and still fail VerifyReply.
func TestClaimedIDsAreOnlyALookupKey(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	other := keys.other.KeyID()
	fromOther := onWire(t, crafted(frameTypeResult, "reply", signedWith(t, replyLabel,
		withEntry(replyTBS(request, frameTypeResult), "responded_by", cbor.Bytes(other[:])), keys.other)))
	result := must[cbor.Value](t)(SignResult(request, cbor.Uint64(1), nil, keys.provider))
	zeroed := objectOf(t, result, "reply")
	zeroed.Signature = make([]byte, len(zeroed.Signature))
	unsigned := onWire(t, frameWith(result, "reply", zeroed.Value()))
	for name, frame := range map[string]cbor.Value{"a reply from another node": fromOther, "a reply with a zeroed signature": unsigned} {
		if requestID, requestHash, err := ClaimedReplyIDs(frame); err != nil ||
			requestID != request.RequestID || requestHash != request.RequestHash {
			t.Errorf("%s: (%x, %v), want the request's ids", name, requestID, err)
		}
	}
	_, err := VerifyReply(fromOther, request, profile.PQPure)
	wantRefusal(t, "a reply from another node", err, ErrNotTheTarget)
	_, err = VerifyReply(unsigned, request, profile.PQPure)
	wantRefusal(t, "a reply with a zeroed signature", err, identity.ErrObjectSignatureInvalid)
}

// A request_id of another length is refused as a request_hash of another length
// is, and the relay_error branch refuses a signed object without its key and a
// tbs that is not CBOR, as the reply branch does.
func TestClaimedIDsRefuseAShortIDAndAMalformedRelayError(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	requestID := request.RequestID
	shortID := crafted(frameTypeResult, "reply", signedWith(t, replyLabel,
		withEntry(replyTBS(request, frameTypeResult), "request_id", cbor.Bytes(requestID[1:])), keys.provider))
	streamRelay := must[cbor.Value](t)(SignRelayError(RelayErrorSpec{FrameType: frameTypeStreamError, Request: verifiedStreamOpen(t, keys),
		Code: "unknown_next_peer"}, keys.station))
	streamObject := objectOf(t, streamRelay, "relay_error")
	errorRelay := must[cbor.Value](t)(SignRelayError(RelayErrorSpec{FrameType: frameTypeError, Request: request, Code: "unknown_next_peer"},
		keys.station))
	errorObject := objectOf(t, errorRelay, "relay_error")
	errorObject.TBS = []byte("not cbor")
	refused := map[string]cbor.Value{
		"a 15-byte request_id": shortID,
		"a relay error without its key": frameWith(streamRelay, "relay_error",
			cbor.Map([]cbor.MapEntry{bytesEntry("tbs", streamObject.TBS), bytesEntry("signature", streamObject.Signature)})),
		"a relay error whose tbs is not CBOR": frameWith(errorRelay, "relay_error", errorObject.Value()),
	}
	for name, frame := range refused {
		_, _, err := ClaimedReplyIDs(frame)
		wantRefusal(t, name, err, ErrMalformedFrame)
	}
}

//------------------------------------------------------------------
// Builds a receiver would refuse
//------------------------------------------------------------------

// A build its receiver would refuse returns an error and no frame, as
// macula_frame's stream_bytes/2 refuses one: a key that is not an identity key,
// or not the sender the receiver verifies; a deadline or retry budget of 2^53 or
// more; a payload the wire cannot carry; and a relay error of another frame
// type.
func TestABuildItsReceiverWouldRefuseReturnsAnError(t *testing.T) {
	keys := requestKeysFor(t)
	connectKey := must[*identity.NodeKey](t)(identity.GenerateKey(identity.PurposeConnect, profile.PQPure))
	request := verifiedCall(t, keys)
	limit := uint64(maxProtocolInt)
	deadline, budget, notCarried := callSpec(keys), callSpec(keys), callSpec(keys)
	deadline.Deadline, budget.RetryBudget, notCarried.Payload = limit, &limit, cbor.Float(math.NaN())
	relay := RelayErrorSpec{FrameType: frameTypeError, Request: request, Code: "unknown_next_peer"}
	resultRelay := relay
	resultRelay.FrameType = frameTypeResult

	_, err := SignCall(callSpec(keys), connectKey)
	wantRefusal(t, "a CALL signed with a CONNECT key", err, ErrUnsignable)
	_, err = SignCall(callSpec(keys), nil)
	wantRefusal(t, "a CALL with no key", err, ErrUnsignable)
	_, err = SignCall(callSpec(keys), &identity.NodeKey{})
	wantRefusal(t, "a CALL with an empty key", err, ErrUnsignable)
	_, err = SignCall(deadline, keys.caller)
	wantRefusal(t, "a deadline of 2^53", err, ErrOutOfRange)
	_, err = SignCall(budget, keys.caller)
	wantRefusal(t, "a retry budget of 2^53", err, ErrOutOfRange)
	if _, err = SignCall(notCarried, keys.caller); err == nil {
		t.Error("a CALL with a NaN payload was built")
	}
	_, err = SignResult(request, cbor.Uint64(1), nil, keys.caller)
	wantRefusal(t, "a RESULT signed by the caller", err, ErrUnsignable)
	_, err = SignProviderError(request, "closed", nil, nil, keys.station)
	wantRefusal(t, "a provider ERROR signed by a station", err, ErrUnsignable)
	_, err = SignRelayError(relay, connectKey)
	wantRefusal(t, "a relay error signed with a CONNECT key", err, ErrUnsignable)
	_, err = SignRelayError(resultRelay, keys.station)
	wantRefusal(t, "a relay error of frame type result", err, ErrOutOfRange)
}
