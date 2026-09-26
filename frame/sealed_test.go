package frame

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// A payload sealed end to end (macula 13, E2E seal scheme 1) travels in a
// frame's `sealed` field in place of its clear one, never beside it. A
// verifier opens nothing: it holds the sealed map's shape to the frame it
// rides in, as macula_frame's sealed_table/0 and sealed_shape/3 do.

func sealedOf(kemCt, nonce []byte) Sealed {
	return Sealed{KeyID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, KemCt: kemCt, Nonce: nonce, Ct: []byte("ciphertext and tag")}
}

func sealedMap(entries ...cbor.MapEntry) cbor.Value {
	return cbor.Map(entries)
}

func TestASealedMapIsShapedForItsFrame(t *testing.T) {
	kemPure, kemHybrid, nonce := make([]byte, 1568), make([]byte, 1665), make([]byte, 12)
	base := []cbor.MapEntry{uintEntry("scheme", 1), bytesEntry("key_id", make([]byte, 8)), bytesEntry("ct", []byte("c"))}
	with := func(extra ...cbor.MapEntry) cbor.Value {
		return sealedMap(append(append([]cbor.MapEntry{}, base...), extra...)...)
	}
	for _, c := range []struct {
		name    string
		v       cbor.Value
		context sealedContext
		ok      bool
	}{
		{"a request's, pq_pure", with(bytesEntry("kem_ct", kemPure)), sealedRequest, true},
		{"a request's, pq_hybrid", with(bytesEntry("kem_ct", kemHybrid)), sealedRequest, true},
		{"a request's without kem_ct", with(), sealedRequest, false},
		{"a request's with a nonce", with(bytesEntry("kem_ct", kemPure), bytesEntry("nonce", nonce)), sealedRequest, false},
		{"a request's kem_ct of another size", with(bytesEntry("kem_ct", make([]byte, 1000))), sealedRequest, false},
		{"a reply's", with(bytesEntry("nonce", nonce)), sealedReply, true},
		{"a reply's without a nonce", with(), sealedReply, false},
		{"a reply's with kem_ct", with(bytesEntry("nonce", nonce), bytesEntry("kem_ct", kemPure)), sealedReply, false},
		{"a reply's nonce of 11 bytes", with(bytesEntry("nonce", make([]byte, 11))), sealedReply, false},
		{"a provider stream frame's", with(bytesEntry("nonce", nonce)), sealedProviderStream, true},
		{"a provider stream frame's without a nonce", with(), sealedProviderStream, false},
		{"a caller stream frame's", with(), sealedCallerStream, true},
		{"a caller stream frame's with a nonce", with(bytesEntry("nonce", nonce)), sealedCallerStream, false},
		{"scheme 2", sealedMap(uintEntry("scheme", 2), bytesEntry("key_id", make([]byte, 8)), bytesEntry("ct", []byte("c")),
			bytesEntry("nonce", nonce)), sealedReply, false},
		{"a key id of 7 bytes", sealedMap(uintEntry("scheme", 1), bytesEntry("key_id", make([]byte, 7)), bytesEntry("ct", []byte("c")),
			bytesEntry("nonce", nonce)), sealedReply, false},
		{"no ct", sealedMap(uintEntry("scheme", 1), bytesEntry("key_id", make([]byte, 8)), bytesEntry("nonce", nonce)), sealedReply, false},
		{"a key the table cannot name", with(bytesEntry("nonce", nonce), textEntry("hint", "h")), sealedReply, false},
		{"not a map", cbor.Bytes([]byte("c")), sealedReply, false},
	} {
		if _, ok := readSealed(c.v, c.context); ok != c.ok {
			t.Errorf("%s: read %v, want %v", c.name, ok, c.ok)
		}
	}
}

// A sealed CALL carries `sealed` in place of `payload` in its signed request,
// and verifies with it; a request with both, or with neither, is malformed.
func TestASealedRequestCarriesSealedInPlaceOfItsPayload(t *testing.T) {
	keys := requestKeysFor(t)
	sealed := sealedOf(make([]byte, 1568), nil)
	spec := callSpec(keys)
	spec.Sealed = &sealed
	request := verifiedRequestOf(t, keys.caller, spec)
	if request.Sealed == nil || request.Sealed.KeyID != sealed.KeyID || string(request.Sealed.Ct) != string(sealed.Ct) ||
		len(request.Sealed.KemCt) != 1568 || request.Sealed.Nonce != nil {
		t.Fatalf("the sealed request verified as %+v", request.Sealed)
	}
	if _, has := objectFields(t, must[cbor.Value](t)(SignCall(spec, keys.caller)), "request")["payload"]; has {
		t.Error("a sealed request signed a payload beside its sealed field")
	}
	clear := verifiedCall(t, keys)
	if clear.Sealed != nil {
		t.Error("a clear request verified as sealed")
	}

	both := withEntry(requestTBS(keys), "sealed", sealed.value())
	wantRefusal(t, "a request with payload and sealed", verifyCraftedRequest(t, frameTypeCall, both, keys.caller), ErrMalformedFrame)
	neither := withoutEntry(requestTBS(keys), "payload")
	wantRefusal(t, "a request with neither", verifyCraftedRequest(t, frameTypeCall, neither, keys.caller), ErrMalformedFrame)
	reply := withEntry(withoutEntry(requestTBS(keys), "payload"), "sealed", sealedOf(nil, make([]byte, 12)).value())
	wantRefusal(t, "a request sealed as a reply is", verifyCraftedRequest(t, frameTypeCall, reply, keys.caller), ErrMalformedFrame)

	wrong := sealedOf(nil, make([]byte, 12))
	spec.Sealed = &wrong
	if _, err := SignCall(spec, keys.caller); err == nil {
		t.Error("a request sealed as a reply is was signed")
	}
}

// A sealed RESULT and a sealed ERROR carry `sealed` alone: a sealed ERROR has
// no code or detail of its own, both travel sealed.
func TestASealedReplyCarriesSealedAlone(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	sealed := sealedOf(nil, make([]byte, 12))
	for _, frameType := range []string{frameTypeResult, frameTypeError} {
		var signed cbor.Value
		if frameType == frameTypeResult {
			signed = must[cbor.Value](t)(SignSealedResult(request, sealed, nil, keys.provider))
		} else {
			signed = must[cbor.Value](t)(SignSealedProviderError(request, sealed, nil, keys.provider))
		}
		reply := must[VerifiedReply](t)(VerifyReply(onWire(t, signed), request, profile.PQPure))
		if reply.FrameType != frameType || reply.Sealed == nil || reply.Sealed.KeyID != sealed.KeyID || reply.Code != "" {
			t.Errorf("a sealed %s verified as %+v", frameType, reply)
		}
		fields := objectFields(t, signed, "reply")
		for _, clearField := range []string{"payload", "code", "detail"} {
			if _, has := fields[clearField]; has {
				t.Errorf("a sealed %s signed %s beside its sealed field", frameType, clearField)
			}
		}
	}
	if clear := must[VerifiedReply](t)(VerifyReply(onWire(t, must[cbor.Value](t)(SignResult(request, cbor.Text("ok"), nil,
		keys.provider))), request, profile.PQPure)); clear.Sealed != nil {
		t.Error("a clear RESULT verified as sealed")
	}

	for name, fields := range map[string][]cbor.MapEntry{
		"a sealed ERROR with a code":       withEntry(replyTBS(request, frameTypeError), "sealed", sealed.value()),
		"a sealed RESULT with its payload": withEntry(replyTBS(request, frameTypeResult), "sealed", sealed.value()),
		"a reply sealed as a request is": withEntry(withoutEntry(replyTBS(request, frameTypeResult), "payload"), "sealed",
			sealedOf(make([]byte, 1568), nil).value()),
	} {
		frameType := frameTypeResult
		if name == "a sealed ERROR with a code" {
			frameType = frameTypeError
		}
		_, err := VerifyReply(onWire(t, crafted(frameType, "reply", signedWith(t, replyLabel, fields, keys.provider))), request, profile.PQPure)
		wantRefusal(t, name, err, ErrMalformedFrame)
	}
	if _, err := SignSealedResult(request, sealedOf(nil, nil), nil, keys.provider); err == nil {
		t.Error("a reply sealed without its nonce was signed")
	}
}

// objectFields is the fields of the signed object a frame carries under name,
// read from its tbs.
func objectFields(t *testing.T, v cbor.Value, name string) map[string]cbor.Value {
	t.Helper()
	tbs := must[cbor.Value](t)(cbor.Decode(objectOf(t, onWire(t, v), name).TBS))
	entries, _ := tbs.AsMap()
	out := map[string]cbor.Value{}
	for _, e := range entries {
		key, _ := e.Key.AsText()
		out[key] = e.Val
	}
	return out
}

// A sealed stream frame carries `sealed` in place of a STREAM_DATA's body (its
// encoding stays), a STREAM_REPLY's payload, or a STREAM_ERROR's code and
// message. A provider's carries its random nonce, a caller's none: its nonce is
// its seq. A STREAM_END has nothing to seal.
func TestASealedStreamFrameCarriesSealedInPlaceOfItsField(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(21))
	providerSealed, callerSealed := sealedOf(nil, make([]byte, 12)), sealedOf(nil, nil)
	state := streamStateOf(t, open)
	for seq, fields := range []StreamFields{
		StreamDataFields{Seq: 0, Encoding: Msgpack, Sealed: &providerSealed},
		StreamErrorFields{Seq: 1, Sealed: &providerSealed},
		StreamReplyFields{Seq: 2, Sealed: &providerSealed},
	} {
		built := must[cbor.Value](t)(SignProviderStream(fields, open, keys.provider))
		frame, next, err := verifyProvider(t, built, state)
		if err != nil || frame.Sealed == nil || frame.Sealed.KeyID != providerSealed.KeyID || frame.Code != "" {
			t.Fatalf("the provider's sealed frame %d: %+v, %v", seq, frame, err)
		}
		if seq == 0 && frame.Encoding != Msgpack {
			t.Errorf("a sealed STREAM_DATA lost its encoding: %v", frame.Encoding)
		}
		state = next
	}
	built := must[cbor.Value](t)(SignCallerStream(StreamDataFields{Seq: 0, Encoding: Raw, Sealed: &callerSealed}, open, keys.caller))
	if frame, _, err := verifyCaller(t, built, state); err != nil || frame.Sealed == nil || frame.Sealed.Nonce != nil {
		t.Fatalf("the caller's sealed frame: %+v, %v", frame, err)
	}
	clear := must[cbor.Value](t)(SignCallerStream(StreamDataFields{Seq: 0, Encoding: Raw, Body: cbor.Bytes([]byte("c"))}, open, keys.caller))
	if frame, _, err := verifyCaller(t, clear, state); err != nil || frame.Sealed != nil {
		t.Fatalf("a clear caller frame: %+v, %v", frame, err)
	}

	for name, err := range map[string]error{
		"a provider's without its nonce": signErr(SignProviderStream(StreamReplyFields{Seq: 3, Sealed: &callerSealed}, open, keys.provider)),
		"a caller's with a nonce": signErr(SignCallerStream(StreamDataFields{Seq: 0, Encoding: Raw, Sealed: &providerSealed},
			open, keys.caller)),
	} {
		wantRefusal(t, name, err, ErrSealedShape)
	}

	signer := keys.caller.KeyID()
	data := func(extra ...cbor.MapEntry) []cbor.MapEntry {
		return streamTBSOf(open, frameTypeStreamData, signer, 0, append([]cbor.MapEntry{textEntry("encoding", "raw")}, extra...)...)
	}
	for name, fields := range map[string][]cbor.MapEntry{
		"a body beside sealed":    data(bytesEntry("body", []byte("c")), valueEntry("sealed", callerSealed.value())),
		"a caller's with a nonce": data(valueEntry("sealed", providerSealed.value())),
		"a code beside sealed": streamTBSOf(open, frameTypeStreamError, signer, 0, textEntry("code", "c"), textEntry("message", "m"),
			valueEntry("sealed", callerSealed.value())),
		"a sealed STREAM_END": streamTBSOf(open, frameTypeStreamEnd, signer, 0, textEntry("role", "send"),
			valueEntry("sealed", callerSealed.value())),
	} {
		frameType := textOf(func() cbor.Value { v, _ := cbor.Map(fields).Get("frame_type"); return v }())
		v := streamFrame(frameType, "caller_stream", heldSignedWith(t, callerStreamLabel, fields, keys.caller))
		_, _, err := verifyCaller(t, v, state)
		wantStreamRefusal(t, name, err, ErrMalformedFrame)
	}
}

func signErr(_ cbor.Value, err error) error { return err }
