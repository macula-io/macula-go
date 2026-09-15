package connection

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/ucan"
)

// serveOne serves one CALL for "caller.probe" on s, signed by caller and
// carrying payload. It returns the channel its handler sends the payload it
// received on, and what ServeOneCallGated returned.
func serveOne(t *testing.T, s *Session, fc *fakeControl, id, caller identity.KeyPair, payload cbor.Value) (<-chan cbor.Value, error) {
	t.Helper()
	got := make(chan cbor.Value, 1)
	lookup := func(_ []byte, procedure string) (CallHandler, bool) {
		return func(p cbor.Value) (cbor.Value, error) {
			got <- p
			return cbor.Null(), nil
		}, procedure == "caller.probe"
	}
	served := make(chan error, 1)
	go func() {
		served <- s.ServeOneCallGated(lookup, func([]byte, string) ucan.Policy { return ucan.Open }, id, 2*time.Second)
	}()
	callID := make([]byte, 16)
	if _, err := rand.Read(callID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	spec := frame.NewCallSpec(callID, "caller.probe", testRealm(), payload, time.Now().Add(time.Second).UnixMilli(), caller.NodeID())
	fc.send(t, frame.Sign(frame.Call(spec), caller))
	return got, awaitErr(t, served)
}

// servedPayload serves one CALL as serveOne does, and returns the payload its
// handler received.
func servedPayload(t *testing.T, s *Session, fc *fakeControl, id, caller identity.KeyPair, payload cbor.Value) cbor.Value {
	t.Helper()
	got, err := serveOne(t, s, fc, id, caller, payload)
	if err != nil {
		t.Fatalf("ServeOneCallGated: %v", err)
	}
	select {
	case p := <-got:
		return p
	default:
		t.Fatal("the handler never ran")
		return cbor.Value{}
	}
}

func TestAnInboundCallThreadsItsCallerIntoThePayload(t *testing.T) {
	s, fc, id := readingSession(t)
	caller := registryIdentity(t)
	payload := servedPayload(t, s, fc, id, caller, cbor.Map([]cbor.MapEntry{{Key: cbor.Text("token"), Val: cbor.Text("abc")}}))

	got, ok := payload.Get("caller")
	if b, isBytes := got.AsBytes(); !ok || !isBytes || !bytes.Equal(b, caller.NodeID()) {
		t.Fatalf("payload caller = %v, want the verified caller's node id as bytes", got)
	}
	if token, _ := payload.Get("token"); func() string { v, _ := token.AsText(); return v }() != "abc" {
		t.Fatalf("payload token = %v, want the sender's own field kept", token)
	}
}

// A "caller" the sender put in the payload is replaced: the handler sees
// exactly one caller, the verified one.
func TestACallerTheSenderPutInThePayloadIsReplacedByTheVerifiedCaller(t *testing.T) {
	s, fc, id := readingSession(t)
	caller := registryIdentity(t)
	spoofed := registryIdentity(t)
	payload := servedPayload(t, s, fc, id, caller, cbor.Map([]cbor.MapEntry{{Key: cbor.Text("caller"), Val: cbor.Bytes(spoofed.NodeID())}}))

	got, ok := payload.Get("caller")
	if b, isBytes := got.AsBytes(); !ok || !isBytes || !bytes.Equal(b, caller.NodeID()) {
		t.Errorf("payload caller = %v, want the verified caller, not the one the sender wrote", got)
	}
	if n := callerEntries(payload); n != 1 {
		t.Errorf("payload has %d caller entries, want only the verified one", n)
	}
}

// A CALL whose payload the decoding rule refuses, here one with a "caller"
// under a byte-string key, never reaches a handler.
func TestACallWhosePayloadTheDecodingRuleRefusesNeverReachesAHandler(t *testing.T) {
	s, fc, id := readingSession(t)
	caller := registryIdentity(t)
	spoofed := registryIdentity(t)
	got, _ := serveOne(t, s, fc, id, caller, cbor.Map([]cbor.MapEntry{{Key: cbor.Bytes([]byte("caller")), Val: cbor.Bytes(spoofed.NodeID())}}))

	select {
	case p := <-got:
		t.Fatalf("the handler ran with %v, want the call refused before any handler", p)
	default:
	}
}

// callerEntries counts payload's entries keyed "caller".
func callerEntries(payload cbor.Value) int {
	entries, _ := payload.AsMap()
	n := 0
	for _, e := range entries {
		if text, isText := e.Key.AsText(); isText && text == "caller" {
			n++
		}
	}
	return n
}

func TestANonMapPayloadCarriesNoCaller(t *testing.T) {
	s, fc, id := readingSession(t)
	caller := registryIdentity(t)
	payload := servedPayload(t, s, fc, id, caller, cbor.Text("hello"))

	if text, ok := payload.AsText(); !ok || text != "hello" {
		t.Fatalf("payload = %v, want the sender's text unchanged", payload)
	}
}
