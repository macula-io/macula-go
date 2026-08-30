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
// from macula-rust's own tests/live_station.rs, still true here):
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

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
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
	topic := fmt.Sprintf("macula-go.test.%s", hex.EncodeToString(randomBytes(t, 8)))

	if err := session.Subscribe(frame.NewSubscribeSpec(topic, realm, id.NodeID()), id); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if err := session.Publish(frame.NewPublishSpec(topic, realm, id.NodeID(), 1,
		cbor.Text("hello from macula-go"), nowMs()), id); err != nil {
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
	topic := fmt.Sprintf("macula-go.test.immediate-close.%s", hex.EncodeToString(randomBytes(t, 8)))

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

// TestLiveKeepAdvertisedStaysCallableAcrossTicks proves KeepAdvertised
// actually keeps a procedure reachable past its first tick (not just
// sent-once), and stops promptly on cancellation. Unlike
// directdial.KeepAdvertisedDirect (independently verifiable via
// dht.FindRecord's created_at), a plain ADVERTISE has no external state
// to query — so the only honest way to prove the registration is still
// alive after two ticks is to actually call the procedure at that point
// and get a real reply, the same round trip TestLiveUnaryCallProviderRoundTrip
// already proves works for a single Advertise.
func TestLiveKeepAdvertisedStaysCallableAcrossTicks(t *testing.T) {
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
	procedure := fmt.Sprintf("macula_go_sdk.test_keepalive.%s", hex.EncodeToString(randomBytes(t, 8)))
	spec := frame.NewAdvertiseSpec(realm, procedure, providerID.NodeID())

	loopCtx, cancelLoop := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	tickErrs := make(chan error, 8)
	go func() {
		providerSession.KeepAdvertised(loopCtx, spec, providerID, 1*time.Second, func(err error) {
			tickErrs <- err
		})
		close(loopDone)
	}()

	// Past the immediate tick AND the ~1s-later second tick, so a
	// successful call here specifically proves the SECOND advertise
	// (not just the first) kept the registration alive.
	time.Sleep(2200 * time.Millisecond)
	select {
	case err := <-tickErrs:
		t.Fatalf("KeepAdvertised tick failed: %v", err)
	default:
	}

	lookup := func(gotRealm []byte, gotProcedure string) (CallHandler, bool) {
		if gotProcedure != procedure {
			return nil, false
		}
		return func(payload cbor.Value) (cbor.Value, error) {
			return cbor.Text("still-alive"), nil
		}, true
	}
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- providerSession.ServeOneCall(lookup, providerID, 10*time.Second)
	}()

	response, err := callerSession.Call(procedure, realm, cbor.Null(), nowMs()+10_000, callerID, 10*time.Second)
	if err != nil {
		t.Fatalf("Call after two ticks: %v (registration did not survive the keep-alive loop)", err)
	}
	if err := <-serveErrCh; err != nil {
		t.Fatalf("ServeOneCall: %v", err)
	}
	if response.IsError {
		t.Fatalf("expected a RESULT, got ERROR code=%d name=%s", response.Code, response.Name)
	}
	txt, ok := response.Payload.AsText()
	if !ok || txt != "still-alive" {
		t.Fatalf("payload = %v, want Text(still-alive)", response.Payload)
	}
	t.Logf("OBSERVED: procedure answered a real call after two KeepAdvertised ticks")

	cancelLoop()
	select {
	case <-loopDone:
		t.Logf("OBSERVED: KeepAdvertised returned promptly after cancel()")
	case <-time.After(3 * time.Second):
		t.Fatalf("KeepAdvertised did not return within 3s of cancel() -- loop is not respecting ctx.Done()")
	}
}

// TestLiveRunSubscriberAndRunPublisher proves the supervised pubsub pair
// (macula_publisher.erl/macula_subscriber.erl's Go counterparts) actually
// works end to end against the real fleet, not just compiles: a
// RunSubscriber goroutine's callback receives a real EVENT delivered by a
// SEPARATE session's RunPublisher (two sessions, matching
// TestLivePublishSurvivesImmediateClose's reasoning for why a self-publish
// on one session is a weaker test), RunPublisher's own onDone callback
// fires with the real outcome, the auto-published
// pubsub.publish_started_v1/publish_completed_v1 facts genuinely land
// (checked via a second, independent bare Subscribe/RecvEvent on that
// well-known topic, not by trusting RunPublisher's own bookkeeping), and
// RunSubscriber returns promptly once its ctx is cancelled (no goroutine
// leak, mirroring TestLiveKeepAdvertisedStaysCallableAcrossTicks's check).
func TestLiveRunSubscriberAndRunPublisher(t *testing.T) {
	subID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (subscriber): %v", err)
	}
	pubID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (publisher): %v", err)
	}

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer connectCancel()
	subSession, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, subID)
	if err != nil {
		t.Fatalf("subscriber handshake should succeed: %v", err)
	}
	defer subSession.Close("normal", nil, subID)
	pubSession, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, pubID)
	if err != nil {
		t.Fatalf("publisher handshake should succeed: %v", err)
	}
	defer pubSession.Close("normal", nil, pubID)

	realm := randomBytes(t, 32)
	topic := fmt.Sprintf("macula-go.test.runsub.%s", hex.EncodeToString(randomBytes(t, 8)))

	// Independent watch on the well-known meta-fact topic, on its OWN
	// session, so it cannot be satisfied by anything RunSubscriber itself
	// does -- this is checking RunPublisher's side effect, not its return
	// value.
	factWatcherID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (fact watcher): %v", err)
	}
	factSession, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, factWatcherID)
	if err != nil {
		t.Fatalf("fact watcher handshake should succeed: %v", err)
	}
	defer factSession.Close("normal", nil, factWatcherID)
	if err := factSession.Subscribe(frame.NewSubscribeSpec(publishCompletedTopic, realm, factWatcherID.NodeID()), factWatcherID); err != nil {
		t.Fatalf("Subscribe (fact watcher): %v", err)
	}

	received := make(chan frame.EventInfo, 1)
	subCtx, cancelSub := context.WithCancel(context.Background())
	subDone := make(chan error, 1)
	go func() {
		subDone <- subSession.RunSubscriber(subCtx, frame.NewSubscribeSpec(topic, realm, subID.NodeID()), subID,
			func(evt frame.EventInfo) error {
				select {
				case received <- evt:
				default:
				}
				return nil
			})
	}()
	// Give the SUBSCRIBE frame a moment to land before publishing --
	// otherwise this is racing the station's own subscribe-then-route
	// wiring, the same class of race TestLivePubSubRoundTrip's own comment
	// already accepts as non-deterministic for a same-session self-publish;
	// a short sleep here keeps THIS test's real assertions deterministic
	// rather than papering over a flake with "not asserted either way".
	time.Sleep(500 * time.Millisecond)

	outcomeCh := make(chan PublishOutcome, 1)
	pubSession.RunPublisher(
		frame.NewPublishSpec(topic, realm, pubID.NodeID(), 1, cbor.Text("hello from RunPublisher"), nowMs()),
		pubID, true,
		func(o PublishOutcome) { outcomeCh <- o },
	)

	select {
	case o := <-outcomeCh:
		if o.Err != nil || o.Cancelled {
			t.Fatalf("RunPublisher outcome = %+v, want a clean completion", o)
		}
		t.Logf("OBSERVED: RunPublisher onDone fired with a clean outcome")
	case <-time.After(5 * time.Second):
		t.Fatalf("RunPublisher onDone never fired within 5s")
	}

	select {
	case evt := <-received:
		if evt.Topic != topic {
			t.Fatalf("received event.Topic = %q, want %q", evt.Topic, topic)
		}
		if txt, ok := evt.Payload.AsText(); !ok || txt != "hello from RunPublisher" {
			t.Fatalf("received event.Payload = %v, want Text(hello from RunPublisher)", evt.Payload)
		}
		t.Logf("OBSERVED: RunSubscriber's handler received the real EVENT")
	case err := <-subDone:
		t.Fatalf("RunSubscriber exited early (err=%v) before delivering any EVENT", err)
	case <-time.After(5 * time.Second):
		t.Fatalf("RunSubscriber's handler never received the published EVENT within 5s")
	}

	// A shared control stream can carry other frame types between one
	// EVENT and the next (confirmed live: the first attempt here hit
	// exactly this), so retry past a non-EVENT parse failure instead of
	// treating RecvEvent's single-call contract as "one shot, no retry" --
	// same reasoning as RunSubscriber's own frame loop, just inlined here
	// since this is a bare-primitive test helper, not that wrapper.
	factDeadline := time.Now().Add(8 * time.Second)
	var factEvt frame.EventInfo
	for {
		var ferr error
		factEvt, ferr = factSession.RecvEvent(time.Until(factDeadline))
		if ferr == nil {
			break
		}
		if errors.Is(ferr, frame.ErrNotAnEventFrame) && time.Now().Before(factDeadline) {
			continue
		}
		t.Fatalf("expected a real pubsub.publish_completed_v1 fact, got: %v", ferr)
	}
	if factEvt.Topic != publishCompletedTopic {
		t.Fatalf("fact event.Topic = %q, want %q", factEvt.Topic, publishCompletedTopic)
	}
	outcomeField, ok := factEvt.Payload.Get("outcome")
	if !ok {
		t.Fatalf("publish_completed_v1 fact missing outcome field: %+v", factEvt.Payload)
	}
	if txt, _ := outcomeField.AsText(); txt != "completed" {
		t.Fatalf("publish_completed_v1 outcome = %v, want Text(completed)", outcomeField)
	}
	t.Logf("OBSERVED: a real pubsub.publish_completed_v1 fact landed with outcome=completed")

	cancelSub()
	select {
	case err := <-subDone:
		if err != context.Canceled {
			t.Fatalf("RunSubscriber returned %v after cancel, want context.Canceled", err)
		}
		t.Logf("OBSERVED: RunSubscriber returned promptly after cancel()")
	case <-time.After(3 * time.Second):
		t.Fatalf("RunSubscriber did not return within 3s of cancel() -- not respecting ctx.Done()")
	}
}

// TestLiveRPCTelemetryFacts proves Call and ServeOneCall auto-publish the
// rpc.sent_v1/rpc.completed_v1 (caller side) and rpc.received_v1/
// rpc.replied_v1 (provider side) mesh facts around a real round trip,
// matching macula_request.erl/macula_response.erl exactly. Verified via
// an INDEPENDENT watcher session subscribed to all four topics, not the
// caller/provider's own bookkeeping -- same verification standard
// TestLiveRunSubscriberAndRunPublisher already established for its own
// auto-published fact.
func TestLiveRPCTelemetryFacts(t *testing.T) {
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

	// FOUR separate watcher sessions/identities, one per topic -- NOT one
	// session shared across 4 concurrent RunSubscriber goroutines. A
	// session's control stream is single-reader; ServeOneCall's own doc
	// already warns about exactly this ("a session that needs to serve
	// CALLs and also act as a caller/subscriber concurrently should use a
	// second Session"), and the same limitation applies to running
	// multiple concurrent RunSubscriber calls on one session -- confirmed
	// the hard way here: sharing one session across all 4 subscriptions
	// panicked RecvFrame with a corrupted length prefix from interleaved
	// concurrent reads on the same stream.
	watcherSessionFor := func(topic string) (*Session, identity.KeyPair) {
		t.Helper()
		id, err := identity.Generate()
		if err != nil {
			t.Fatalf("identity.Generate (watcher for %s): %v", topic, err)
		}
		sess, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, id)
		if err != nil {
			t.Fatalf("watcher handshake for %s should succeed: %v", topic, err)
		}
		t.Cleanup(func() { _ = sess.Close("normal", nil, id) })
		return sess, id
	}

	realm := randomBytes(t, 32)
	procedure := fmt.Sprintf("macula_go_sdk.test_rpc_facts.%s", hex.EncodeToString(randomBytes(t, 8)))

	// Buffered generously, not size 1: this is a real shared public demo
	// fleet ("other people and other agents are also using it, not a
	// sandbox" -- mesh://etiquette), and rpc.sent_v1/rpc.completed_v1/
	// rpc.received_v1/rpc.replied_v1 are FIXED, well-known topic names by
	// design (matching the Erlang reference, which doesn't randomize them
	// either) -- unlike this file's OTHER pubsub tests, which dodge
	// exactly this by randomizing the topic string itself. Concurrent,
	// unrelated third-party traffic on these same topics is expected, so
	// correlation below is proven by matching request_id across a
	// SPECIFIC pair, not by assuming the first event to arrive is ours.
	seen := struct {
		sent, completed, received, replied chan frame.EventInfo
	}{
		sent:      make(chan frame.EventInfo, 32),
		completed: make(chan frame.EventInfo, 32),
		received:  make(chan frame.EventInfo, 32),
		replied:   make(chan frame.EventInfo, 32),
	}
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()
	for topic, ch := range map[string]chan frame.EventInfo{
		rpcSentTopic: seen.sent, rpcCompletedTopic: seen.completed,
		rpcReceivedTopic: seen.received, rpcRepliedTopic: seen.replied,
	} {
		topic, ch := topic, ch
		watcherSession, watcherID := watcherSessionFor(topic)
		go func() {
			_ = watcherSession.RunSubscriber(watchCtx, frame.NewSubscribeSpec(topic, realm, watcherID.NodeID()), watcherID,
				func(evt frame.EventInfo) error {
					select {
					case ch <- evt:
					default:
					}
					return nil
				})
		}()
	}
	// Let all four SUBSCRIBEs land before anything gets published --
	// same race already accepted and handled this way in
	// TestLiveRunSubscriberAndRunPublisher.
	time.Sleep(500 * time.Millisecond)

	advertiseSpec := frame.NewAdvertiseSpec(realm, procedure, providerID.NodeID())
	if err := providerSession.Advertise(advertiseSpec, providerID); err != nil {
		t.Fatalf("advertise should send: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	lookup := func(_ []byte, gotProcedure string) (CallHandler, bool) {
		if gotProcedure != procedure {
			return nil, false
		}
		return func(payload cbor.Value) (cbor.Value, error) { return payload, nil }, true
	}
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- providerSession.ServeOneCall(lookup, providerID, 15*time.Second) }()

	resp, err := callerSession.Call(procedure, realm, cbor.Text("telemetry probe"), nowMs()+10_000, callerID, 10*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.IsError {
		t.Fatalf("expected a RESULT, got ERROR code=%d name=%s", resp.Code, resp.Name)
	}
	if err := <-serveErrCh; err != nil {
		t.Fatalf("ServeOneCall: %v", err)
	}

	requestID := func(t *testing.T, label string, evt frame.EventInfo) []byte {
		t.Helper()
		v, ok := evt.Payload.Get("request_id")
		if !ok {
			t.Fatalf("%s fact missing request_id field: %+v", label, evt.Payload)
		}
		id, ok := v.AsBytes()
		if !ok || len(id) != 16 {
			t.Fatalf("%s fact request_id = %+v, want 16 bytes", label, v)
		}
		return id
	}
	outcomeField := func(t *testing.T, label string, evt frame.EventInfo, want string) {
		t.Helper()
		v, ok := evt.Payload.Get("outcome")
		if txt, _ := v.AsText(); !ok || txt != want {
			t.Fatalf("%s outcome = %+v, want Text(%q)", label, v, want)
		}
	}
	// drain collects every event already buffered or arriving within
	// window on ch -- used instead of "read one and trust it's ours"
	// because unrelated concurrent traffic on this shared fleet publishes
	// to these same fixed topic names too.
	drain := func(ch chan frame.EventInfo, window time.Duration) []frame.EventInfo {
		deadline := time.After(window)
		var out []frame.EventInfo
		for {
			select {
			case evt := <-ch:
				out = append(out, evt)
			case <-deadline:
				return out
			}
		}
	}
	// findPair returns the first (a, b) from as/bs whose request_id
	// fields match -- proving THIS SDK's own correlation is correct
	// (a real call's sent+completed, or received+replied, share one
	// minted request_id) even when other parties' unrelated facts are
	// mixed into the same buffers.
	findPair := func(t *testing.T, labelA string, as []frame.EventInfo, labelB string, bs []frame.EventInfo) (frame.EventInfo, frame.EventInfo, []byte) {
		t.Helper()
		for _, a := range as {
			aID := requestID(t, labelA, a)
			for _, b := range bs {
				bID := requestID(t, labelB, b)
				if string(aID) == string(bID) {
					return a, b, aID
				}
			}
		}
		t.Fatalf("no %s/%s pair shared a request_id -- %d %s event(s), %d %s event(s) observed, none correlated",
			labelA, labelB, len(as), labelA, len(bs), labelB)
		return frame.EventInfo{}, frame.EventInfo{}, nil
	}

	sentEvts := drain(seen.sent, 5*time.Second)
	completedEvts := drain(seen.completed, 100*time.Millisecond)
	receivedEvts := drain(seen.received, 100*time.Millisecond)
	repliedEvts := drain(seen.replied, 100*time.Millisecond)
	if len(sentEvts) == 0 {
		t.Fatalf("%s: no event arrived at the independent watcher at all", rpcSentTopic)
	}
	if len(receivedEvts) == 0 {
		t.Fatalf("%s: no event arrived at the independent watcher at all", rpcReceivedTopic)
	}

	_, completedEvt, callerReqID := findPair(t, rpcSentTopic, sentEvts, rpcCompletedTopic, completedEvts)
	outcomeField(t, rpcCompletedTopic, completedEvt, "completed")

	_, repliedEvt, providerReqID := findPair(t, rpcReceivedTopic, receivedEvts, rpcRepliedTopic, repliedEvts)
	outcomeField(t, rpcRepliedTopic, repliedEvt, "replied")

	// The caller's own request_id lifecycle (sent/completed) and the
	// provider's own (received/replied) are DELIBERATELY independent --
	// matching macula_request.erl/macula_response.erl exactly, each side
	// mints its own via crypto:strong_rand_bytes(16), uncorrelated with
	// the other side or with the wire CALL's own CallID. (Not asserted as
	// inequality here: on a shared fleet, coincidence aside, a DIFFERENT
	// concurrent party's ids could theoretically land in either bucket --
	// the real, meaningful assertion is the two correlations just proven.)

	t.Logf("OBSERVED: RPC telemetry facts correlate correctly through an independent watcher -- caller request_id=%x (sent+completed, outcome=completed), provider request_id=%x (received+replied, outcome=replied)",
		callerReqID, providerReqID)
}
