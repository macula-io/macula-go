package stationlink

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
)

func linkWithStation(t *testing.T, p profile.Profile) (*Link, *testStation) {
	t.Helper()
	s := startTestStation(t, p, "")
	link, err := dial(t, s, newClient(t, p))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return link, s
}

func callWithin(t *testing.T, link *Link, c Call) (cbor.Value, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return link.Call(ctx, c)
}

func stationCall(procedure string, payload cbor.Value) Call {
	return Call{Procedure: procedure, Payload: payload, Timeout: 2 * time.Second}
}

// A call to a station procedure goes to the station itself, and its signed
// RESULT, verified against the request, comes back as the payload.
func TestACallReturnsTheVerifiedResult(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			link, s := linkWithStation(t, p)
			s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
				if r.Target != s.nodeID || r.Procedure != "_dht.find_record" {
					t.Errorf("the station got target %x procedure %q", r.Target, r.Procedure)
				}
				reply, err := frame.SignResult(r, r.Payload, nil, s.key)
				return reply, err == nil
			})
			got, err := callWithin(t, link, stationCall("_dht.find_record", cbor.Text("echo me")))
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			if text, _ := got.AsText(); text != "echo me" {
				t.Errorf("result %v", got)
			}
		})
	}
}

// A provider's ERROR comes back as a ProviderError with its code and detail.
func TestAProviderErrorComesBackWithItsCode(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	detail := "no such key"
	s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
		reply, err := frame.SignProviderError(r, "not_found", &detail, nil, s.key)
		return reply, err == nil
	})
	_, err := callWithin(t, link, stationCall("_dht.find_record", cbor.Map(nil)))
	var provider *ProviderError
	if !errors.As(err, &provider) || provider.Code != "not_found" || provider.Detail == nil || *provider.Detail != detail {
		t.Errorf("Call: %v, want a ProviderError not_found with its detail", err)
	}
}

// A relay error the connected station reports comes back as a RelayError.
func TestARelayErrorComesBackFromTheStation(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
		reply, err := frame.SignRelayError(frame.RelayErrorSpec{FrameType: "error", Request: r, Code: "unknown_next_peer"}, s.key)
		return reply, err == nil
	})
	provider := [32]byte{7}
	c := Call{Realm: [32]byte{3}, Procedure: "mcl-echo/echo", Target: provider, Payload: cbor.Map(nil), Timeout: 2 * time.Second}
	_, err := callWithin(t, link, c)
	var relay *RelayError
	if !errors.As(err, &relay) || relay.Code != "unknown_next_peer" || relay.ReportedBy != s.nodeID {
		t.Errorf("Call: %v, want the station's unknown_next_peer", err)
	}
}

// A reply that does not verify for the request, here a RESULT signed by a
// key that is not the target, is ignored: the call stays pending and times
// out, and the link counts it.
func TestAReplyFromAnotherKeyIsIgnored(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	impostor := sharedIdentityKey(t, profile.PQPure, "impostor")
	s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
		forged := r
		forged.Target, _ = impostor.NodeID()
		reply, err := frame.SignResult(forged, cbor.Text("forged"), nil, impostor)
		return reply, err == nil
	})
	c := stationCall("_dht.find_record", cbor.Map(nil))
	c.Timeout = 300 * time.Millisecond
	if _, err := callWithin(t, link, c); !errors.Is(err, ErrCallTimeout) {
		t.Errorf("Call: %v, want ErrCallTimeout", err)
	}
	if link.Unrouted()["unverified_reply"] != 1 {
		t.Errorf("unrouted %v, want one unverified_reply", link.Unrouted())
	}
}

// With a station that answers its _macula.ping probes the link stays up; when
// the station stops answering, two missed probes end it.
func TestLivenessProbesKeepOrEndTheLink(t *testing.T) {
	restoreEvery, restoreWait := livenessEvery, livenessTimeout
	livenessEvery, livenessTimeout = 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { livenessEvery, livenessTimeout = restoreEvery, restoreWait })
	link, s := linkWithStation(t, profile.PQPure)
	answering := make(chan bool, 1)
	answering <- true
	s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
		on := <-answering
		answering <- on
		if !on || r.Procedure != "_macula.ping" || r.Realm != ([32]byte{}) {
			return cbor.Value{}, false
		}
		reply, err := frame.SignResult(r, cbor.Text("pong"), nil, s.key)
		return reply, err == nil
	})
	select {
	case <-link.Done():
		t.Fatalf("the link ended while the station answered: %v", link.Err())
	case <-time.After(600 * time.Millisecond):
	}
	<-answering
	answering <- false
	if err := waitDone(t, link); !errors.Is(err, ErrLivenessLost) {
		t.Errorf("the link ended with %v, want ErrLivenessLost", err)
	}
}
