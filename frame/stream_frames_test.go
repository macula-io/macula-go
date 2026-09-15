package frame

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_frame_stream_tests, and the stream frame
// cases of macula_frame_stream_bytes_tests, at merge-11.0.0 335b114f
// (DESIGN_PQ_SIGNED_FRAMES_AND_RECORDS.md: Provider stream frames and Caller
// stream frames; D25 item 5, D17 as revised). A provider's STREAM_DATA,
// STREAM_END, STREAM_ERROR and STREAM_REPLY carry stream under
// MACULA-PQ-STREAM-V1: {key, tbs, signature} on its first frame of a stream,
// {tbs, signature} after. A caller's STREAM_DATA, STREAM_END and STREAM_ERROR
// carry caller_stream, {tbs, signature} under MACULA-PQ-CALLER-STREAM-V1,
// verified with the caller key of the STREAM_OPEN. Each side numbers its own
// frames from 0, and STREAM_END is its last.

// streamChunk is a raw STREAM_DATA of seq holding "chunk".
func streamChunk(seq uint64) StreamDataFields {
	return StreamDataFields{Seq: seq, Encoding: Raw, Body: cbor.Bytes([]byte("chunk"))}
}

// streamOpenOf is a verified STREAM_OPEN in mode from the caller to the
// provider, with requestID.
func streamOpenOf(t *testing.T, keys requestKeys, mode StreamMode, requestID [16]byte) VerifiedRequest {
	t.Helper()
	spec := callSpec(keys)
	spec.Mode, spec.RequestID = modeOf(mode), requestID
	return must[VerifiedRequest](t)(VerifyRequest(onWire(t, must[cbor.Value](t)(SignStreamOpen(spec, keys.caller))), profile.PQPure))
}

func streamStateOf(t *testing.T, open VerifiedRequest) StreamState {
	t.Helper()
	return must[StreamState](t)(OpenStream(open))
}

// providerVerified is the stream's state after the provider frames given, each
// built by the provider and verified in turn.
func providerVerified(t *testing.T, keys requestKeys, open VerifiedRequest, frames ...StreamFields) StreamState {
	t.Helper()
	state := streamStateOf(t, open)
	for _, fields := range frames {
		built := must[cbor.Value](t)(SignProviderStream(fields, open, keys.provider))
		var err error
		if _, state, err = VerifyProviderStream(onWire(t, built), state, profile.PQPure); err != nil {
			t.Fatalf("verify the provider's %+v: %v", fields, err)
		}
	}
	return state
}

func verifyProvider(t *testing.T, v cbor.Value, state StreamState) (VerifiedStreamFrame, StreamState, error) {
	t.Helper()
	return VerifyProviderStream(onWire(t, v), state, profile.PQPure)
}

func verifyCaller(t *testing.T, v cbor.Value, state StreamState) (VerifiedStreamFrame, StreamState, error) {
	t.Helper()
	return VerifyCallerStream(onWire(t, v), state, profile.PQPure)
}

// streamTBSOf is the fields a stream frame of frameType signs, with the fields
// of its type; signing adds alg.
func streamTBSOf(open VerifiedRequest, frameType string, signer [32]byte, seq uint64, typeFields ...cbor.MapEntry) []cbor.MapEntry {
	return append([]cbor.MapEntry{
		textEntry("frame_type", frameType),
		bytesEntry("request_id", open.RequestID[:]),
		bytesEntry("request_hash", open.RequestHash[:]),
		bytesEntry("signer", signer[:]),
		uintEntry("seq", seq),
	}, typeFields...)
}

func chunkTBS(open VerifiedRequest, signer [32]byte, seq uint64) []cbor.MapEntry {
	return streamTBSOf(open, frameTypeStreamData, signer, seq, textEntry("encoding", "raw"), bytesEntry("body", []byte("chunk")))
}

func heldSignedWith(t *testing.T, label string, fields []cbor.MapEntry, key *identity.NodeKey) cbor.Value {
	t.Helper()
	return must[identity.HeldObject](t)(identity.SignHeldObject(label, fields, key)).Value()
}

// wantStreamRefusal checks that err is want and no other refusal of a stream
// frame.
func wantStreamRefusal(t *testing.T, name string, err, want error) {
	t.Helper()
	refusals := []error{ErrMalformedFrame, ErrStreamEnded, ErrSeqMismatch, ErrKeyIDMismatch, ErrRequestMismatch, ErrNotTheTarget,
		identity.ErrObjectSignatureInvalid}
	for _, other := range refusals {
		if other != want && errors.Is(err, other) {
			t.Errorf("%s: %v, want %v alone", name, err, want)
			return
		}
	}
	wantRefusal(t, name, err, want)
}

// sameValue reports whether two values encode alike, or are both absent.
func sameValue(a, b cbor.Value) bool {
	absent := cbor.Value{}.Kind()
	if a.Kind() == absent || b.Kind() == absent {
		return a.Kind() == b.Kind()
	}
	return slices.Equal(cbor.Encode(a), cbor.Encode(b))
}

func sameStreamFrame(a, b VerifiedStreamFrame) bool {
	return a.FrameType == b.FrameType && a.Signer == b.Signer && a.Seq == b.Seq && a.Encoding == b.Encoding &&
		a.Role == b.Role && a.Code == b.Code && a.Message == b.Message && sameValue(a.Body, b.Body) && sameValue(a.Payload, b.Payload)
}

//------------------------------------------------------------------
// Provider stream frames
//------------------------------------------------------------------

func TestAProviderFirstFrameCarriesItsKeyAndVerifiesAgainstTheOpen(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	first := onWire(t, must[cbor.Value](t)(SignProviderStream(streamChunk(0), open, keys.provider)))
	stream, _ := first.Get("stream")
	if got, want := sortedKeys(first), []string{"frame_type", "stream", "version"}; !slices.Equal(got, want) {
		t.Errorf("a provider's first frame's fields: %v, want %v", got, want)
	}
	if got, want := sortedKeys(stream), []string{"key", "signature", "tbs"}; !slices.Equal(got, want) {
		t.Errorf("its stream object's fields: %v, want %v", got, want)
	}
	frame, _, err := VerifyProviderStream(first, streamStateOf(t, open), profile.PQPure)
	want := VerifiedStreamFrame{FrameType: frameTypeStreamData, Signer: keys.provider.KeyID(), Encoding: Raw, Body: cbor.Bytes([]byte("chunk"))}
	if err != nil || !sameStreamFrame(frame, want) {
		t.Errorf("verify the first frame: (%+v, %v), want %+v", frame, err, want)
	}
}

func TestLaterProviderFramesVerifyWithTheHeldKey(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	state := providerVerified(t, keys, open, streamChunk(0))
	later := onWire(t, must[cbor.Value](t)(SignProviderStream(streamChunk(1), open, keys.provider)))
	stream, _ := later.Get("stream")
	if got, want := sortedKeys(stream), []string{"signature", "tbs"}; !slices.Equal(got, want) {
		t.Errorf("a later frame's stream object's fields: %v, want %v", got, want)
	}
	frame, _, err := VerifyProviderStream(later, state, profile.PQPure)
	if err != nil || frame.Seq != 1 || frame.Signer != keys.provider.KeyID() {
		t.Errorf("verify the later frame: (%+v, %v), want seq 1 from the provider", frame, err)
	}
}

func TestAProviderFrameOutOfOrderIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	fresh, state := streamStateOf(t, open), providerVerified(t, keys, open, streamChunk(0))
	frame := func(seq uint64) cbor.Value {
		return must[cbor.Value](t)(SignProviderStream(streamChunk(seq), open, keys.provider))
	}
	_, _, err := verifyProvider(t, frame(1), fresh)
	wantStreamRefusal(t, "seq 1 before the first frame", err, ErrSeqMismatch)
	_, _, err = verifyProvider(t, frame(0), state)
	wantStreamRefusal(t, "seq 0 again", err, ErrSeqMismatch)
	_, _, err = verifyProvider(t, frame(2), state)
	wantStreamRefusal(t, "seq 2 after seq 0", err, ErrSeqMismatch)
}

func TestAProviderFirstFrameFromANodeOtherThanTheTargetIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	first := crafted(frameTypeStreamData, "stream", signedWith(t, streamLabel, chunkTBS(open, keys.other.KeyID(), 0), keys.other))
	_, _, err := verifyProvider(t, first, streamStateOf(t, open))
	wantStreamRefusal(t, "a first frame from a node other than the target", err, ErrNotTheTarget)
}

func TestAProviderFirstFrameWhoseSignerIsNotItsKeyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	first := crafted(frameTypeStreamData, "stream", signedWith(t, streamLabel, chunkTBS(open, keys.other.KeyID(), 0), keys.provider))
	_, _, err := verifyProvider(t, first, streamStateOf(t, open))
	wantStreamRefusal(t, "a first frame whose signer is not its key", err, ErrKeyIDMismatch)
}

func TestAProviderFrameForAnotherStreamIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open, another := streamOpenOf(t, keys, Bidi, idOf(7)), streamOpenOf(t, keys, Bidi, idOf(8))
	first := must[cbor.Value](t)(SignProviderStream(streamChunk(0), open, keys.provider))
	_, _, err := verifyProvider(t, first, streamStateOf(t, another))
	wantStreamRefusal(t, "a first frame for another STREAM_OPEN", err, ErrRequestMismatch)
}

func TestNothingFollowsAProviderStreamEnd(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	state := providerVerified(t, keys, open, streamChunk(0), StreamEndFields{Seq: 1, Role: Both})
	after := must[cbor.Value](t)(SignProviderStream(streamChunk(2), open, keys.provider))
	_, _, err := verifyProvider(t, after, state)
	wantStreamRefusal(t, "a frame after the provider's STREAM_END", err, ErrStreamEnded)
}

func TestATamperedProviderFrameIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	first := must[cbor.Value](t)(SignProviderStream(streamChunk(0), open, keys.provider))
	_, _, err := verifyProvider(t, withFlippedTBS(t, first, "stream"), streamStateOf(t, open))
	wantStreamRefusal(t, "a first frame with a changed tbs", err, identity.ErrObjectSignatureInvalid)
}

func TestProviderFrameFieldsTheDesignDoesNotAllowAreMalformed(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	signer := keys.provider.KeyID()
	verify := func(frameType string, tbs []cbor.MapEntry) error {
		_, _, err := verifyProvider(t, crafted(frameType, "stream", signedWith(t, streamLabel, tbs, keys.provider)), streamStateOf(t, open))
		return err
	}
	chunk := chunkTBS(open, signer, 0)
	if err := verify(frameTypeStreamData, chunk); err != nil {
		t.Fatalf("the crafted chunk: %v, want it verified", err)
	}
	for _, c := range []struct {
		name      string
		frameType string
		tbs       []cbor.MapEntry
	}{
		{"a STREAM_DATA without its body", frameTypeStreamData, withoutEntry(chunk, "body")},
		{"an encoding outside its set", frameTypeStreamData, withEntry(chunk, "encoding", cbor.Text("json"))},
		{"a raw body as text", frameTypeStreamData, withEntry(chunk, "body", cbor.Text("chunk"))},
		{"a seq of 2^53", frameTypeStreamData, withEntry(chunk, "seq", cbor.Uint64(maxProtocolInt))},
		{"a STREAM_DATA with a role", frameTypeStreamData, withEntry(chunk, "role", cbor.Text("both"))},
		{"a field no stream frame has", frameTypeStreamData, withEntry(chunk, "extra", cbor.Uint64(1))},
		{"a role outside its set", frameTypeStreamEnd, streamTBSOf(open, frameTypeStreamEnd, signer, 0, textEntry("role", "recv"))},
		{"a STREAM_END around a STREAM_DATA's fields", frameTypeStreamEnd, chunk},
		{"a tbs of another frame type", frameTypeStreamData, withEntry(chunk, "frame_type", cbor.Text(frameTypeCall))},
	} {
		wantStreamRefusal(t, c.name, verify(c.frameType, c.tbs), ErrMalformedFrame)
	}
}

// Before the provider's first frame the verifier holds no key, so a frame
// without one can only be a later frame, out of order. After it, a later frame
// that carries a key has the wrong shape.
func TestAFirstFrameCarriesTheProviderKeyAndALaterOneDoesNot(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	signer := keys.provider.KeyID()
	held := crafted(frameTypeStreamData, "stream", heldSignedWith(t, streamLabel, chunkTBS(open, signer, 0), keys.provider))
	_, _, err := verifyProvider(t, held, streamStateOf(t, open))
	wantStreamRefusal(t, "a first frame without its key", err, ErrSeqMismatch)
	carried := crafted(frameTypeStreamData, "stream", signedWith(t, streamLabel, chunkTBS(open, signer, 1), keys.provider))
	_, _, err = verifyProvider(t, carried, providerVerified(t, keys, open, streamChunk(0)))
	wantStreamRefusal(t, "a later frame with its key", err, ErrMalformedFrame)
}

// A later provider frame is from its first frame's signer: one without a key
// that names another signer, and one that carries another node's key, are each
// refused as not the key they verified with, as macula_frame's later_checked
// and carried_later refuse them.
func TestALaterProviderFrameFromAnotherSignerIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	state := providerVerified(t, keys, open, streamChunk(0))
	held := crafted(frameTypeStreamData, "stream", heldSignedWith(t, streamLabel, chunkTBS(open, keys.other.KeyID(), 1), keys.provider))
	_, _, err := verifyProvider(t, held, state)
	wantStreamRefusal(t, "a later frame naming another signer", err, ErrKeyIDMismatch)
	carried := crafted(frameTypeStreamData, "stream", signedWith(t, streamLabel, chunkTBS(open, keys.provider.KeyID(), 1), keys.other))
	_, _, err = verifyProvider(t, carried, state)
	wantStreamRefusal(t, "a later frame carrying another node's key", err, ErrKeyIDMismatch)
}

func TestAProviderStreamErrorAndStreamReplyCarryTheirFields(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, ClientStream, idOf(7))
	state := providerVerified(t, keys, open, streamChunk(0))
	total := cbor.Map([]cbor.MapEntry{uintEntry("total", 3)})
	reply := must[cbor.Value](t)(SignProviderStream(StreamReplyFields{Seq: 1, Payload: total}, open, keys.provider))
	replied, replyState, err := verifyProvider(t, reply, state)
	want := VerifiedStreamFrame{FrameType: frameTypeStreamReply, Signer: keys.provider.KeyID(), Seq: 1, Payload: total}
	if err != nil || !sameStreamFrame(replied, want) {
		t.Errorf("verify the STREAM_REPLY: (%+v, %v), want %+v", replied, err, want)
	}
	streamError := must[cbor.Value](t)(SignProviderStream(StreamErrorFields{Seq: 2, Code: "overflow", Message: "too many rows"}, open, keys.provider))
	errored, _, err := verifyProvider(t, streamError, replyState)
	want = VerifiedStreamFrame{FrameType: frameTypeStreamError, Signer: keys.provider.KeyID(), Seq: 2, Code: "overflow", Message: "too many rows"}
	if err != nil || !sameStreamFrame(errored, want) {
		t.Errorf("verify the STREAM_ERROR: (%+v, %v), want %+v", errored, err, want)
	}
}

// A STREAM_ERROR's code is text of at most 64 bytes and its message text of at
// most 256: at the bound it verifies, and one byte over is malformed.
func TestAStreamErrorCodeAndMessageAreReadWithinTheirBounds(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	errorTBS := streamTBSOf(open, frameTypeStreamError, keys.provider.KeyID(), 0, textEntry("code", "c"), textEntry("message", "m"))
	verify := func(field string, size int) (VerifiedStreamFrame, error) {
		tbs := withEntry(errorTBS, field, cbor.Text(strings.Repeat("a", size)))
		frame, _, err := verifyProvider(t, crafted(frameTypeStreamError, "stream", signedWith(t, streamLabel, tbs, keys.provider)), streamStateOf(t, open))
		return frame, err
	}
	if frame, err := verify("code", 64); err != nil || len(frame.Code) != 64 {
		t.Errorf("a 64-byte code: (%+v, %v), want it verified", frame, err)
	}
	if frame, err := verify("message", 256); err != nil || len(frame.Message) != 256 {
		t.Errorf("a 256-byte message: (%+v, %v), want it verified", frame, err)
	}
	_, err := verify("code", 65)
	wantStreamRefusal(t, "a 65-byte code", err, ErrMalformedFrame)
	_, err = verify("message", 257)
	wantStreamRefusal(t, "a 257-byte message", err, ErrMalformedFrame)
}

// A STREAM_ERROR is built on either side with a code of at most 64 bytes and a
// message of at most 256, both UTF-8.
func TestAStreamErrorBuilderRefusesTextOutsideItsBounds(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	if _, err := SignProviderStream(StreamErrorFields{Code: strings.Repeat("c", 64), Message: strings.Repeat("m", 256)}, open, keys.provider); err != nil {
		t.Errorf("a STREAM_ERROR at its bounds: %v, want it built", err)
	}
	sides := map[string]func(StreamFields) error{
		"a provider's": func(fields StreamFields) error {
			_, err := SignProviderStream(fields, open, keys.provider)
			return err
		},
		"a caller's": func(fields StreamFields) error {
			_, err := SignCallerStream(fields, open, keys.caller)
			return err
		},
	}
	for side, build := range sides {
		for _, c := range []struct {
			name   string
			fields StreamErrorFields
			want   error
		}{
			{"65-byte code", StreamErrorFields{Code: strings.Repeat("c", 65)}, ErrTextTooLong},
			{"257-byte message", StreamErrorFields{Code: "c", Message: strings.Repeat("m", 257)}, ErrTextTooLong},
			{"code that is not UTF-8", StreamErrorFields{Code: "\xff"}, ErrInvalidText},
			{"message that is not UTF-8", StreamErrorFields{Code: "c", Message: "\xff"}, ErrInvalidText},
		} {
			wantRefusal(t, side+" STREAM_ERROR with a "+c.name, build(c.fields), c.want)
		}
	}
}

//------------------------------------------------------------------
// Caller stream frames
//------------------------------------------------------------------

func TestACallerFrameVerifiesWithTheCallerKeyFromTheOpen(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	body := cbor.Map([]cbor.MapEntry{uintEntry("n", 1)})
	built := onWire(t, must[cbor.Value](t)(SignCallerStream(StreamDataFields{Encoding: Msgpack, Body: body}, open, keys.caller)))
	object, _ := built.Get("caller_stream")
	if got, want := sortedKeys(built), []string{"caller_stream", "frame_type", "version"}; !slices.Equal(got, want) {
		t.Errorf("a caller's frame's fields: %v, want %v", got, want)
	}
	if got, want := sortedKeys(object), []string{"signature", "tbs"}; !slices.Equal(got, want) {
		t.Errorf("its caller_stream object's fields: %v, want %v", got, want)
	}
	frame, _, err := VerifyCallerStream(built, streamStateOf(t, open), profile.PQPure)
	want := VerifiedStreamFrame{FrameType: frameTypeStreamData, Signer: keys.caller.KeyID(), Encoding: Msgpack, Body: body}
	if err != nil || !sameStreamFrame(frame, want) {
		t.Errorf("verify the caller's frame: (%+v, %v), want %+v", frame, err, want)
	}
}

func TestCallerAndProviderCountTheirFramesApart(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	provided := providerVerified(t, keys, open, streamChunk(0))
	frame, _, err := verifyCaller(t, must[cbor.Value](t)(SignCallerStream(streamChunk(0), open, keys.caller)), provided)
	if err != nil || frame.Seq != 0 || frame.Signer != keys.caller.KeyID() {
		t.Errorf("the caller's seq 0 after the provider's: (%+v, %v), want it verified", frame, err)
	}
}

func TestACallerFrameSignedByAnotherKeyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	data := crafted(frameTypeStreamData, "caller_stream", heldSignedWith(t, callerStreamLabel, chunkTBS(open, keys.other.KeyID(), 0), keys.other))
	_, _, err := verifyCaller(t, data, streamStateOf(t, open))
	wantStreamRefusal(t, "a caller's frame signed by another key", err, identity.ErrObjectSignatureInvalid)
}

func TestACallerFrameWhoseSignerIsNotTheCallerIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	data := crafted(frameTypeStreamData, "caller_stream", heldSignedWith(t, callerStreamLabel, chunkTBS(open, keys.other.KeyID(), 0), keys.caller))
	_, _, err := verifyCaller(t, data, streamStateOf(t, open))
	wantStreamRefusal(t, "a caller's frame whose signer is not the caller", err, ErrKeyIDMismatch)
}

func TestCallerStreamDataInAServerStreamIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, ServerStream, idOf(7))
	_, err := SignCallerStream(streamChunk(0), open, keys.caller)
	wantRefusal(t, "build a caller's STREAM_DATA in a server_stream", err, ErrNotAllowed)
	data := crafted(frameTypeStreamData, "caller_stream", heldSignedWith(t, callerStreamLabel, chunkTBS(open, keys.caller.KeyID(), 0), keys.caller))
	_, _, err = verifyCaller(t, data, streamStateOf(t, open))
	wantStreamRefusal(t, "a caller's STREAM_DATA in a server_stream", err, ErrMalformedFrame)
	end := must[cbor.Value](t)(SignCallerStream(StreamEndFields{Role: Both}, open, keys.caller))
	if frame, _, err := verifyCaller(t, end, streamStateOf(t, open)); err != nil || frame.FrameType != frameTypeStreamEnd || frame.Role != Both {
		t.Errorf("a caller's STREAM_END in a server_stream: (%+v, %v), want it verified", frame, err)
	}
}

func TestACallerFrameOutOfOrderIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	skipped := must[cbor.Value](t)(SignCallerStream(streamChunk(1), open, keys.caller))
	_, _, err := verifyCaller(t, skipped, streamStateOf(t, open))
	wantStreamRefusal(t, "the caller's seq 1 first", err, ErrSeqMismatch)
}

func TestNothingFollowsACallerStreamEnd(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	end := must[cbor.Value](t)(SignCallerStream(StreamEndFields{Role: Send}, open, keys.caller))
	_, ended, err := verifyCaller(t, end, streamStateOf(t, open))
	if err != nil {
		t.Fatalf("verify the caller's STREAM_END: %v", err)
	}
	after := must[cbor.Value](t)(SignCallerStream(streamChunk(1), open, keys.caller))
	_, _, err = verifyCaller(t, after, ended)
	wantStreamRefusal(t, "a frame after the caller's STREAM_END", err, ErrStreamEnded)
}

// A caller sends no STREAM_REPLY: its builder refuses one, and a caller's
// verifier refuses a frame that carries one.
func TestACallerHasNoStreamReply(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	_, err := SignCallerStream(StreamReplyFields{Payload: cbor.Uint64(1)}, open, keys.caller)
	wantRefusal(t, "build a caller's STREAM_REPLY", err, ErrNotAllowed)
	tbs := withEntry(chunkTBS(open, keys.caller.KeyID(), 0), "frame_type", cbor.Text(frameTypeStreamReply))
	reply := crafted(frameTypeStreamReply, "caller_stream", heldSignedWith(t, callerStreamLabel, tbs, keys.caller))
	_, _, err = verifyCaller(t, reply, streamStateOf(t, open))
	wantStreamRefusal(t, "a caller's STREAM_REPLY", err, ErrMalformedFrame)
}

func TestAStreamErrorFrameCarriesExactlyOneSignedObject(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	fresh := streamStateOf(t, open)
	fields := StreamErrorFields{Code: "gone", Message: "gone"}
	providerError := must[cbor.Value](t)(SignProviderStream(fields, open, keys.provider))
	callerError := must[cbor.Value](t)(SignCallerStream(fields, open, keys.caller))
	stream, _ := providerError.Get("stream")
	callerStream, _ := callerError.Get("caller_stream")
	_, _, err := verifyProvider(t, callerError, fresh)
	wantStreamRefusal(t, "a caller's STREAM_ERROR at the provider's verifier", err, ErrMalformedFrame)
	_, _, err = verifyCaller(t, providerError, fresh)
	wantStreamRefusal(t, "a provider's STREAM_ERROR at the caller's verifier", err, ErrMalformedFrame)
	_, _, err = verifyProvider(t, frameWith(providerError, "caller_stream", callerStream), fresh)
	wantStreamRefusal(t, "a STREAM_ERROR with both objects at the provider's verifier", err, ErrMalformedFrame)
	_, _, err = verifyCaller(t, frameWith(callerError, "stream", stream), fresh)
	wantStreamRefusal(t, "a STREAM_ERROR with both objects at the caller's verifier", err, ErrMalformedFrame)
}

//------------------------------------------------------------------
// Stream frame builds
//------------------------------------------------------------------

// A body or payload the wire cannot carry is its sender's error: nothing is
// built or signed.
func TestAnUnsendableStreamBodyOrReplyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	unsendable := cbor.Map([]cbor.MapEntry{textEntry("unsendable", "\xff")})
	want := CheckPayload(unsendable)
	if want == nil {
		t.Fatal("CheckPayload accepts the unsendable value")
	}
	_, providerData := SignProviderStream(StreamDataFields{Encoding: Msgpack, Body: unsendable}, open, keys.provider)
	_, callerData := SignCallerStream(StreamDataFields{Encoding: Msgpack, Body: unsendable}, open, keys.caller)
	_, providerReply := SignProviderStream(StreamReplyFields{Payload: unsendable}, open, keys.provider)
	for name, err := range map[string]error{"a provider's body": providerData, "a caller's body": callerData, "a provider's reply": providerReply} {
		if err == nil || err.Error() != want.Error() {
			t.Errorf("%s the wire cannot carry: %v, want %v", name, err, want)
		}
	}
}

// A stream frame needs an identity key to sign it and the verified STREAM_OPEN
// it belongs to, and a stream opens on a STREAM_OPEN only.
func TestAStreamFrameWithoutAnIdentityKeyOrItsOpenIsUnsignable(t *testing.T) {
	keys := requestKeysFor(t)
	open, call := streamOpenOf(t, keys, Bidi, idOf(7)), verifiedCall(t, keys)
	connectKey := must[*identity.NodeKey](t)(identity.GenerateKey(identity.PurposeConnect, profile.PQPure))
	for _, c := range []struct {
		name string
		open VerifiedRequest
		key  *identity.NodeKey
	}{
		{"no key", open, nil},
		{"a CONNECT key", open, connectKey},
		{"a CALL for its open", call, keys.provider},
		{"no open", VerifiedRequest{}, keys.provider},
	} {
		_, err := SignProviderStream(streamChunk(0), c.open, c.key)
		wantRefusal(t, "a provider's frame with "+c.name, err, ErrUnsignable)
	}
	_, err := OpenStream(call)
	wantRefusal(t, "a stream opened on a CALL", err, ErrOutOfRange)
}

// Bytes are built only for the sender its receiver verifies: the STREAM_OPEN's
// target for a provider's frame, its caller for a caller's. A key id holds its
// profile, so a key of the other profile is not the sender either.
func TestAKeyThatIsNotTheVerifiedSenderIsUnsignable(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	hybrid := must[*identity.NodeKey](t)(identity.GenerateKey(identity.PurposeIdentity, profile.PQHybrid))
	_, err := SignProviderStream(streamChunk(0), open, keys.caller)
	wantRefusal(t, "a provider's frame with the caller's key", err, ErrUnsignable)
	_, err = SignCallerStream(streamChunk(0), open, keys.provider)
	wantRefusal(t, "a caller's frame with the provider's key", err, ErrUnsignable)
	_, err = SignProviderStream(streamChunk(0), open, hybrid)
	wantRefusal(t, "a provider's frame with a pq_hybrid key", err, ErrUnsignable)
}

// STREAM_END, STREAM_ERROR and STREAM_REPLY each verify as a provider's first
// frame.
func TestAStreamEndErrorAndReplyVerify(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	for _, c := range []struct {
		fields    StreamFields
		frameType string
	}{
		{StreamEndFields{Role: Both}, frameTypeStreamEnd},
		{StreamErrorFields{Code: "c", Message: "m"}, frameTypeStreamError},
		{StreamReplyFields{Payload: cbor.Map([]cbor.MapEntry{uintEntry("n", 1)})}, frameTypeStreamReply},
	} {
		built := must[cbor.Value](t)(SignProviderStream(c.fields, open, keys.provider))
		if frame, _, err := verifyProvider(t, built, streamStateOf(t, open)); err != nil || frame.FrameType != c.frameType {
			t.Errorf("verify the provider's %+v: (%+v, %v), want a %s", c.fields, frame, err, c.frameType)
		}
	}
}

// A stream build outside its ranges and sets is refused with ErrOutOfRange, and
// nothing is signed.
func TestAStreamBuildOutsideItsRangesIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	if _, err := SignProviderStream(StreamDataFields{Seq: maxProtocolInt - 1, Encoding: Raw, Body: cbor.Bytes(nil)}, open, keys.provider); err != nil {
		t.Errorf("a seq of 2^53 - 1: %v, want it built", err)
	}
	for _, c := range []struct {
		name   string
		fields StreamFields
	}{
		{"a seq of 2^53", StreamDataFields{Seq: maxProtocolInt, Encoding: Raw, Body: cbor.Bytes(nil)}},
		{"an encoding outside its set", StreamDataFields{Encoding: StreamEncoding(2), Body: cbor.Bytes(nil)}},
		{"a raw body as text", StreamDataFields{Encoding: Raw, Body: cbor.Text("chunk")}},
		{"a role outside its set", StreamEndFields{Role: StreamRole(2)}},
		{"a pointer to stream fields", &StreamEndFields{Role: Both}},
		{"no stream fields", nil},
	} {
		_, err := SignProviderStream(c.fields, open, keys.provider)
		wantRefusal(t, c.name, err, ErrOutOfRange)
	}
}

//------------------------------------------------------------------
// Branches beyond macula's cases: authentication after the first frame, the
// request a frame names, and a state's own copies
//------------------------------------------------------------------

// A later provider frame without a key verifies with the key the first frame
// carried, so one signed by another key is refused as a signature that does not
// verify. That check is what authenticates a provider's frames after its first.
func TestALaterProviderFrameWithoutAKeySignedByAnotherKeyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	state := providerVerified(t, keys, open, streamChunk(0))
	later := crafted(frameTypeStreamData, "stream", heldSignedWith(t, streamLabel, chunkTBS(open, keys.provider.KeyID(), 1), keys.other))
	_, _, err := verifyProvider(t, later, state)
	wantStreamRefusal(t, "a keyless later frame signed by another key", err, identity.ErrObjectSignatureInvalid)
}

// A later provider frame names its stream's request: one built for another
// STREAM_OPEN is refused.
func TestALaterProviderFrameForAnotherStreamIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open, another := streamOpenOf(t, keys, Bidi, idOf(7)), streamOpenOf(t, keys, Bidi, idOf(8))
	state := providerVerified(t, keys, open, streamChunk(0))
	later := must[cbor.Value](t)(SignProviderStream(streamChunk(1), another, keys.provider))
	_, _, err := verifyProvider(t, later, state)
	wantStreamRefusal(t, "a later frame for another STREAM_OPEN", err, ErrRequestMismatch)
}

// A provider's first frame, the one that carries its key, has seq 0: one that
// carries its key at seq 1 is refused as out of order.
func TestAFirstProviderFrameCarryingItsKeyAtAnotherSeqIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	first := crafted(frameTypeStreamData, "stream", signedWith(t, streamLabel, chunkTBS(open, keys.provider.KeyID(), 1), keys.provider))
	_, _, err := verifyProvider(t, first, streamStateOf(t, open))
	wantStreamRefusal(t, "a first frame carrying its key at seq 1", err, ErrSeqMismatch)
}

// A caller's frame names its stream's request: one the same caller built for
// another STREAM_OPEN is refused.
func TestACallerFrameForAnotherStreamIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	open, another := streamOpenOf(t, keys, Bidi, idOf(7)), streamOpenOf(t, keys, Bidi, idOf(8))
	data := must[cbor.Value](t)(SignCallerStream(streamChunk(0), another, keys.caller))
	_, _, err := verifyCaller(t, data, streamStateOf(t, open))
	wantStreamRefusal(t, "a caller's frame for another STREAM_OPEN", err, ErrRequestMismatch)
}

// A stream's state keeps its own copies of its STREAM_OPEN's key and mode:
// writing through the caller's VerifiedRequest after OpenStream changes neither
// the server_stream rule nor the key a caller's frames verify with.
func TestAStreamStateKeepsItsOwnKeyAndMode(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, ServerStream, idOf(7))
	state := streamStateOf(t, open)
	data := crafted(frameTypeStreamData, "caller_stream", heldSignedWith(t, callerStreamLabel, chunkTBS(open, keys.caller.KeyID(), 0), keys.caller))
	end := must[cbor.Value](t)(SignCallerStream(StreamEndFields{Role: Both}, open, keys.caller))
	*open.Mode = Bidi
	clear(open.Key)
	_, _, err := verifyCaller(t, data, state)
	wantStreamRefusal(t, "a caller's STREAM_DATA after the open's mode was written", err, ErrMalformedFrame)
	if frame, _, err := verifyCaller(t, end, state); err != nil || frame.FrameType != frameTypeStreamEnd {
		t.Errorf("a caller's STREAM_END after the open's key was cleared: (%+v, %v), want it verified", frame, err)
	}
}
