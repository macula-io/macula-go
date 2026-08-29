//go:build live

// Integration tests against a real, live macula-station. NOT run by
// default `go test ./...` — gated behind the `live` build tag, since
// this depends on external infrastructure this module doesn't own or
// control (network reachability, the fleet's own uptime). Run
// explicitly:
//
//	go test -tags=live ./connection/... -run TestLive -v
//
// DNS gotcha, confirmed directly against the live box (carried over
// from macula-rust-sdk's own tests/live_station.rs, still true here):
// the bare macula.io hostname has an A (IPv4) record but no AAAA
// record, while station-de-frankfurt's actual QUIC listener is bound to
// a specific IPv6 address unrelated to that A record. Dialing
// "macula.io" resolves to a real, reachable IPv4 address with nothing
// listening on port 4433 — every packet vanishes silently.
// "station-de-frankfurt.macula.io" is the name that actually resolves
// to the listener.
package connection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/macula-io/macula-go-sdk/bolt4"
	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/transport"
)

func nowMs() int64 { return time.Now().UnixMilli() }

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

const (
	liveStationHost = "station-de-frankfurt.macula.io"
	liveStationPort = 4433
)

// TestLiveHandshakeAgainstRealStation dials the real production fleet
// and completes a full CONNECT/HELLO handshake, WebPKI trust (the mode
// the live fleet actually presents — see transport.WebPKI's doc and
// plans/PLAN_WIRE_PROTOCOL.md §2's empirical note). Proves the whole
// stack this module built end to end: canonical CBOR, Ed25519 signing,
// the frame envelope, and the QUIC/TLS transport all interoperate with
// a real, unmodified macula-station — not just with themselves.
func TestLiveHandshakeAgainstRealStation(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := Connect(ctx, liveStationHost, liveStationPort, transport.WebPKI{}, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close("normal", nil, id)

	t.Logf("connected: remote=%s station_id=%x accepted=%v capabilities=%d negotiated=%d",
		session.RemoteAddr(), session.Station.StationID, session.Station.Accepted,
		session.Station.Capabilities, session.Station.NegotiatedCapabilities)

	if !session.Station.Accepted {
		t.Fatalf("station did not accept the connection (refusal_code=%v)", session.Station.RefusalCode)
	}
	if len(session.Station.NodeID) != 32 {
		t.Errorf("station NodeID length = %d, want 32", len(session.Station.NodeID))
	}
	if len(session.Station.StationID) != 32 {
		t.Errorf("station StationID length = %d, want 32", len(session.Station.StationID))
	}
}

// TestLiveCallRoundTrip is a real end-to-end CALL/RESULT-or-ERROR round
// trip. Calls a procedure name that certainly doesn't exist
// (macula_go_sdk.test_probe) — the point isn't to exercise any
// particular procedure, only to prove the wire round trip itself: a
// signed CALL sent, and a signed RESULT or ERROR received back,
// correlated by call_id, with a real BOLT#4 code if it's an error.
func TestLiveCallRoundTrip(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := Connect(ctx, liveStationHost, liveStationPort, transport.WebPKI{}, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close("normal", nil, id)

	realm := make([]byte, 32) // the content-sentinel realm, reused here as a harmless default
	response, err := session.Call("macula_go_sdk.test_probe", realm, cbor.Null(),
		nowMs()+10_000, id, 10*time.Second)
	if err != nil {
		t.Fatalf("Call: expected SOME response (result or a well-formed error), not: %v", err)
	}

	if response.IsError {
		t.Logf("OBSERVED: got an ERROR (expected for a nonexistent procedure): code=%d name=%s reported_by=%s detail=%v",
			response.Code, response.Name, hex.EncodeToString(response.ReportedBy), response.Detail)
	} else {
		t.Logf("OBSERVED: got a RESULT (unexpected for a made-up procedure, but valid): payload=%s responded_by=%s",
			response.Payload, hex.EncodeToString(response.RespondedBy))
	}
}

// TestLivePubSubRoundTrip is a real end-to-end SUBSCRIBE -> PUBLISH ->
// (maybe) EVENT round trip. Whether a subscriber receives its own
// publish is genuinely unknown going in — this test observes and
// reports rather than assuming an answer, same discipline as the
// unhardened-identity check in TestLiveHandshakeAgainstRealStation's
// sibling would use if this module built pubkey-pinned trust yet.
func TestLivePubSubRoundTrip(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := Connect(ctx, liveStationHost, liveStationPort, transport.WebPKI{}, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close("normal", nil, id)

	// A realm+topic scratch value nobody else would collide with.
	realm := randomBytes(t, 32)
	topic := fmt.Sprintf("macula-go-sdk.test.%s", hex.EncodeToString(randomBytes(t, 8)))

	if err := session.Subscribe(frame.NewSubscribeSpec(topic, realm, id.NodeID()), id); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if err := session.Publish(frame.NewPublishSpec(topic, realm, id.NodeID(), 1,
		cbor.Text("hello from macula-go-sdk"), nowMs()), id); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	event, err := session.RecvEvent(5 * time.Second)
	if err != nil {
		t.Logf("OBSERVED: no EVENT arrived within 5s (%v) — a subscriber may not receive its "+
			"own publish, or delivery may simply be slower than this test waits. Not asserted "+
			"as a failure either way.", err)
		return
	}
	t.Logf("OBSERVED: received our own EVENT back — topic=%s seq=%d delivered_via=%s payload=%s",
		event.Topic, event.Seq, event.DeliveredVia, event.Payload)
	if event.Topic != topic {
		t.Errorf("event.Topic = %q, want %q", event.Topic, topic)
	}
}

// TestLivePublishSurvivesImmediateClose is the regression test for a
// real bug found live 2026-08-29, NOT caught by TestLivePubSubRoundTrip
// above: that test keeps reading on the SAME session that published,
// so session.Close (deferred) never runs until well after the PUBLISH
// was already flushed by the blocking RecvEvent call in between --
// structurally unable to race. Every one-shot CLI command (macula-cli
// pubsub publish, and by the same shape every other fire-and-forget
// command) instead does exactly: connect, send one frame, close
// immediately, exit -- no intervening read of any kind. quic-go's
// Stream.Write/Close both just queue data for a background sender and
// return before it's actually on the wire; Session.Close's own
// CloseWithError is abrupt and does not wait for outstanding data to
// be delivered. Confirmed live: a PUBLISH sent this way intermittently
// never reached the peer at all (a station-side trace showed zero
// activity despite session.Publish returning nil), and a manually
// inserted delay before Close fixed it every time -- root-caused to
// this race, not to anything about the frame's content. Fixed in
// Session.Close itself (closeDrainMs). This test uses two INDEPENDENT
// sessions specifically so the publishing side's Close is not
// incidentally delayed by anything the subscribing side does.
func TestLivePublishSurvivesImmediateClose(t *testing.T) {
	subID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (subscriber): %v", err)
	}
	pubID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (publisher): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	subSession, err := Connect(ctx, liveStationHost, liveStationPort, transport.WebPKI{}, subID)
	if err != nil {
		t.Fatalf("Connect (subscriber): %v", err)
	}
	defer subSession.Close("normal", nil, subID)

	realm := randomBytes(t, 32)
	topic := fmt.Sprintf("macula-go-sdk.test.immediate-close.%s", hex.EncodeToString(randomBytes(t, 8)))

	if err := subSession.Subscribe(frame.NewSubscribeSpec(topic, realm, subID.NodeID()), subID); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// Give the SUBSCRIBE a moment to register before the publish races
	// it -- this test is about the PUBLISH-then-Close race, not about
	// subscribe-propagation timing (a separate concern).
	time.Sleep(500 * time.Millisecond)

	// Separate connection, separate identity: publish then close
	// immediately, matching macula-cli pubsub publish's exact shape
	// (see cmd/macula-cli/pubsub.go's runPubsubPublish in the sibling
	// repo) -- connect, one frame, Close, done. No read in between.
	func() {
		pubCtx, pubCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer pubCancel()
		pubSession, err := Connect(pubCtx, liveStationHost, liveStationPort, transport.WebPKI{}, pubID)
		if err != nil {
			t.Fatalf("Connect (publisher): %v", err)
		}
		defer pubSession.Close("normal", nil, pubID)

		if err := pubSession.Publish(frame.NewPublishSpec(topic, realm, pubID.NodeID(), 1,
			cbor.Text("hello from the immediate-close regression test"), nowMs()), pubID); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		// Deliberately nothing else here -- Close fires via defer the
		// instant this function returns, exactly like the CLI.
	}()

	// Loop, not a single RecvEvent call: this is a real, shared,
	// busy station (frankfurt), and RecvFrame returns whatever
	// arrives next on the control stream -- unrelated live traffic
	// (including a frame that isn't even an EVENT at all) is expected
	// to interleave, not a sign the race this test guards against has
	// resurfaced. Only a genuine deadline expiry with nothing matching
	// received counts as this test failing.
	deadline := time.Now().Add(5 * time.Second)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("EVENT for our topic never arrived after a publish immediately followed by " +
				"Close (this is the exact race this test exists to catch)")
		}
		event, err := subSession.RecvEvent(remaining)
		if err != nil {
			if isTimeout(err) {
				t.Fatalf("EVENT for our topic never arrived after a publish immediately followed "+
					"by Close: %v (this is the exact race this test exists to catch)", err)
			}
			t.Logf("skipping a non-EVENT frame on this shared, busy station: %v", err)
			continue
		}
		if event.Topic == topic {
			return // found it -- the race did not reproduce
		}
		t.Logf("skipping unrelated live EVENT on this shared station: topic=%s", event.Topic)
	}
}

func isTimeout(err error) bool {
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// TestLiveUnaryCallProviderRoundTrip is the real point of §6.9's
// ADVERTISE existing for unary RPC, not just streaming: two independent
// connections to the SAME live station — one advertises a procedure and
// serves inbound CALLs for it via ServeOneCall (the provider role this
// package's own README used to list as "not yet built"), the other
// dials in and calls it (the caller role, already live-verified in
// TestLiveCallRoundTrip). Same station on purpose, same reasoning as
// the sibling streaming-provider test in package stream: cross-station
// routing depends on gossip propagation this test isn't here to wait
// out.
func TestLiveUnaryCallProviderRoundTrip(t *testing.T) {
	providerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (provider): %v", err)
	}
	callerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (caller): %v", err)
	}

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer connectCancel()
	providerSession, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, providerID)
	if err != nil {
		t.Fatalf("provider handshake should succeed: %v", err)
	}
	defer providerSession.Close("normal", nil, providerID)
	callerSession, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, callerID)
	if err != nil {
		t.Fatalf("caller handshake should succeed: %v", err)
	}
	defer callerSession.Close("normal", nil, callerID)

	realm := randomBytes(t, 32)
	procedure := fmt.Sprintf("macula_go_sdk.test_add.%s", hex.EncodeToString(randomBytes(t, 8)))

	advertiseSpec := frame.NewAdvertiseSpec(realm, procedure, providerID.NodeID())
	if err := providerSession.Advertise(advertiseSpec, providerID); err != nil {
		t.Fatalf("advertise should send: %v", err)
	}

	// Give the station a moment to register the advertisement before the
	// caller dials in against it.
	time.Sleep(500 * time.Millisecond)

	lookup := func(gotRealm []byte, gotProcedure string) (CallHandler, bool) {
		if gotProcedure != procedure {
			return nil, false
		}
		return func(payload cbor.Value) (cbor.Value, error) {
			a, _ := payload.Get("a")
			b, _ := payload.Get("b")
			aVal, _ := a.AsInt64()
			bVal, _ := b.AsInt64()
			return cbor.Int(aVal + bVal), nil
		}, true
	}

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- providerSession.ServeOneCall(lookup, providerID, 15*time.Second)
	}()

	payload := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("a"), Val: cbor.Int(3)},
		{Key: cbor.Text("b"), Val: cbor.Int(4)},
	})
	response, err := callerSession.Call(procedure, realm, payload, nowMs()+10_000, callerID, 10*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}

	if err := <-serveErrCh; err != nil {
		t.Fatalf("ServeOneCall: %v", err)
	}

	if response.IsError {
		t.Fatalf("expected a RESULT, got ERROR code=%d name=%s detail=%v", response.Code, response.Name, response.Detail)
	}
	sum, ok := response.Payload.AsInt64()
	if !ok || sum != 7 {
		t.Fatalf("response.Payload = %v, want Int(7)", response.Payload)
	}
	t.Logf("OBSERVED: provider served the inbound CALL for procedure=%s, caller got RESULT payload=%d", procedure, sum)
}

// TestLiveUnaryCallProviderReportsUnknownNextPeerOnLookupMiss confirms
// the BOLT#4 error path: a provider that's advertised but whose lookup
// (deliberately, here) can't find a handler replies with the exact
// same unknown_next_peer code the reference sends for this race
// (macula_station_link.erl's handle_inbound_call/2, "unknown (realm,
// procedure)" branch).
func TestLiveUnaryCallProviderReportsUnknownNextPeerOnLookupMiss(t *testing.T) {
	providerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (provider): %v", err)
	}
	callerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (caller): %v", err)
	}

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer connectCancel()
	providerSession, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, providerID)
	if err != nil {
		t.Fatalf("provider handshake should succeed: %v", err)
	}
	defer providerSession.Close("normal", nil, providerID)
	callerSession, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, callerID)
	if err != nil {
		t.Fatalf("caller handshake should succeed: %v", err)
	}
	defer callerSession.Close("normal", nil, callerID)

	realm := randomBytes(t, 32)
	procedure := fmt.Sprintf("macula_go_sdk.test_miss.%s", hex.EncodeToString(randomBytes(t, 8)))

	if err := providerSession.Advertise(frame.NewAdvertiseSpec(realm, procedure, providerID.NodeID()), providerID); err != nil {
		t.Fatalf("advertise should send: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	noHandlers := func([]byte, string) (CallHandler, bool) { return nil, false }
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- providerSession.ServeOneCall(noHandlers, providerID, 15*time.Second)
	}()

	response, err := callerSession.Call(procedure, realm, cbor.Null(), nowMs()+10_000, callerID, 10*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if err := <-serveErrCh; err != nil {
		t.Fatalf("ServeOneCall: %v", err)
	}

	if !response.IsError {
		t.Fatalf("expected an ERROR, got a RESULT: %s", response.Payload)
	}
	if response.Code != uint8(bolt4.UnknownNextPeer) {
		t.Errorf("response.Code = %d (%s), want %d (unknown_next_peer)", response.Code, response.Name, bolt4.UnknownNextPeer)
	}
	t.Logf("OBSERVED: lookup miss correctly reported as ERROR code=%d name=%s", response.Code, response.Name)
}
