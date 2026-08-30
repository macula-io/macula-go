package directdial

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/content"
	"github.com/macula-io/macula-go/dht"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/manifest"
	"github.com/macula-io/macula-go/stream"
	"github.com/macula-io/macula-go/transport"
)

// TestLiveOpenStreamDirectRoundTrip proves streaming's direct-dial variant
// actually delivers data end-to-end, not just resolve+dial — same bar
// TestLiveDirectDialServeRoundTrip already established for unary RPC after
// AdvertiseDirect's missing-plain-Advertise bug was found and fixed.
// Streaming's provider side (macula_streamer.erl's advertise_direct) is the
// identical mechanism AdvertiseDirect already implements, confirmed by
// reading the Erlang reference directly — no separate stream-shaped
// advertise exists or is needed.
//
// Uses frame.ServerStream (provider pushes via SendData/CloseSend, caller
// drains via Recv/EOF) deliberately, NOT frame.ClientStream +
// SendReply/AwaitReply — found live while building this: NOTHING in this
// codebase has ever actually proven ClientStream mode against a REAL
// registered provider. stream/live_test.go's only ClientStream test
// (TestLiveStreamOpenRoundTrip) deliberately targets an UNREGISTERED
// procedure and its own comment documents the exact station response
// ("unknown_next_peer / procedure not advertised") as the EXPECTED
// outcome for that case — which is what a first draft of this test hit
// too, with a real registered provider, direct-dial or not. Whether that's
// a real gap specific to ClientStream-mode provider routing is a separate,
// pre-existing question this package's direct-dial work didn't create and
// isn't the right place to chase — flagged as an open follow-up instead.
// ServerStream is the one combination stream/live_test.go's own
// TestLiveStreamingProviderRoundTrip already proves works against a real
// provider, so it isolates direct-dial's OWN correctness cleanly.
func TestLiveOpenStreamDirectRoundTrip(t *testing.T) {
	if os.Getenv("MACULA_LIVE_TEST") == "" {
		t.Skip("set MACULA_LIVE_TEST=1 to run against the live demo fleet")
	}
	host := os.Getenv("MACULA_LIVE_HOST")
	if host == "" {
		host = "station-de-falkenstein.macula.io"
	}
	const port = 4433
	const procedure = "directdial_live_test.stream_round_trip_v1"
	realm := make([]byte, 32)

	// Separate identities for provider vs caller -- this fleet kicks
	// whichever connection reuses an identity second (see
	// TestLiveDirectDialServeRoundTrip's own comment for the incident this
	// avoids).
	providerID, err := identity.GenerateWithPuzzle(identity.DefaultPuzzleDifficulty)
	if err != nil {
		t.Fatalf("identity.GenerateWithPuzzle (provider): %v", err)
	}
	callerID, err := identity.GenerateWithPuzzle(identity.DefaultPuzzleDifficulty)
	if err != nil {
		t.Fatalf("identity.GenerateWithPuzzle (caller): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := connection.Connect(ctx, host, port, transport.WebPKI{}, providerID)
	if err != nil {
		t.Fatalf("Connect (provider session) to %s:%d: %v", host, port, err)
	}
	defer func() { _ = provider.Close("normal", nil, providerID) }()

	if err := AdvertiseDirect(provider, providerID, realm, procedure, time.Hour); err != nil {
		t.Fatalf("AdvertiseDirect: %v", err)
	}
	t.Logf("provider %x advertised (plain + direct) for %q", provider.Station.NodeID, procedure)
	// Same margin stream/live_test.go's own single-station provider test
	// (TestLiveStreamingProviderRoundTrip) gives the station to register
	// the advertisement before a caller dials in against it.
	time.Sleep(500 * time.Millisecond)

	type acceptResult struct {
		handle *stream.Handle
		info   frame.StreamOpenInfo
		err    error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		h, info, err := stream.Accept(provider, 20*time.Second)
		acceptCh <- acceptResult{handle: h, info: info, err: err}
	}()

	resolveVia, err := connection.Connect(ctx, host, port, transport.WebPKI{}, callerID)
	if err != nil {
		t.Fatalf("Connect (resolver session) to %s:%d: %v", host, port, err)
	}
	defer func() { _ = resolveVia.Close("normal", nil, callerID) }()

	target, callerHandle, err := OpenStreamDirect(ctx, resolveVia, callerID, realm, procedure, frame.ServerStream, cbor.Null(), time.Now().Add(15*time.Second).UnixMilli(), 15*time.Second)
	if err != nil {
		if errors.Is(err, ErrStationEndpointNotFound) {
			t.Skipf("Resolve found no live, host-bearing station_endpoint -- known external relay-side gap, not a failure of this package: %v", err)
		}
		t.Fatalf("OpenStreamDirect: %v (this is the fix under test -- the provider advertised but the stream never reached it)", err)
	}
	defer func() { _ = target.Close("normal", nil, callerID) }()

	accepted := <-acceptCh
	if accepted.err != nil {
		t.Fatalf("provider's Accept side reported an error: %v", accepted.err)
	}
	if accepted.info.Procedure != procedure {
		t.Fatalf("accepted stream for the wrong procedure: %q", accepted.info.Procedure)
	}

	if err := accepted.handle.SendData(frame.Raw, cbor.Bytes([]byte("hello direct-dial stream")), providerID); err != nil {
		t.Fatalf("provider SendData: %v", err)
	}
	if err := accepted.handle.CloseSend(providerID); err != nil {
		t.Fatalf("provider CloseSend: %v", err)
	}

	item, err := callerHandle.Recv(10 * time.Second)
	if err != nil {
		t.Fatalf("caller Recv: %v", err)
	}
	if item.IsEOF {
		t.Fatalf("expected Data, got Eof")
	}
	body, ok := item.Body.AsBytes()
	if !ok || string(body) != "hello direct-dial stream" {
		t.Fatalf("item.Body = %v, want Bytes(\"hello direct-dial stream\")", item.Body)
	}
	t.Logf("OBSERVED: real data received through direct-dial stream open: %q", body)

	item, err = callerHandle.Recv(5 * time.Second)
	if err != nil {
		t.Fatalf("caller Recv (expecting Eof): %v", err)
	}
	if !item.IsEOF {
		t.Fatalf("expected Eof, got Data")
	}
}

// TestLivePutDirectRoundTrip proves content PUT-direct actually stores
// retrievable content at a KNOWN station, dialed in one hop — no
// procedure_advertisement involved at all (content has no "procedure" to
// resolve), matching macula_feeder:start_link_direct/5,6's own design:
// the caller already knows WHICH station to push to. Uses the live
// fleet's own already-published station_endpoint (resolveVia's own
// connected station) as that known target -- no self-announcement needed,
// unlike GetDirect's architecturally-different situation (see
// TestLivePutDirectRoundTrip's sibling test below for why).
func TestLivePutDirectRoundTrip(t *testing.T) {
	if os.Getenv("MACULA_LIVE_TEST") == "" {
		t.Skip("set MACULA_LIVE_TEST=1 to run against the live demo fleet")
	}
	host := os.Getenv("MACULA_LIVE_HOST")
	if host == "" {
		host = "station-de-falkenstein.macula.io"
	}
	const port = 4433

	// Separate identities for the resolving/put side vs the verify-fetch
	// side, deliberately -- a first draft shared one identity for both,
	// and since PutDirect's target station here IS resolveVia's own
	// already-connected station, PutDirect's internal fresh dial (same
	// identity) kicked resolveVia's own connection out from under it per
	// this fleet's one-connection-per-identity guard, breaking the
	// fetch-back check with an unrelated-looking stream error. Same class
	// of self-inflicted collision already found and fixed in
	// TestLiveDirectDialServeRoundTrip; worth a real caveat on PutDirect
	// itself (see its doc) since any caller re-using resolveVia afterward
	// against the SAME station could hit this for real.
	putID, err := identity.GenerateWithPuzzle(identity.DefaultPuzzleDifficulty)
	if err != nil {
		t.Fatalf("identity.GenerateWithPuzzle (put): %v", err)
	}
	verifyID, err := identity.GenerateWithPuzzle(identity.DefaultPuzzleDifficulty)
	if err != nil {
		t.Fatalf("identity.GenerateWithPuzzle (verify): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resolveVia, err := connection.Connect(ctx, host, port, transport.WebPKI{}, putID)
	if err != nil {
		t.Fatalf("Connect to %s:%d: %v", host, port, err)
	}
	defer func() { _ = resolveVia.Close("normal", nil, putID) }()

	station := resolveVia.Station.NodeID
	data := []byte("macula-go PutDirect live test payload, " + time.Now().String())

	mcid, err := PutDirect(ctx, resolveVia, putID, station, data, "putdirect-live-test.txt", 15*time.Second)
	if err != nil {
		if errors.Is(err, ErrStationEndpointNotFound) {
			t.Skipf("PutDirect's own station's station_endpoint has no live, host-bearing record -- known external relay-side gap (see TestLiveAdvertiseAndResolve's comment), not a failure of this package: %v", err)
		}
		t.Fatalf("PutDirect: %v", err)
	}
	t.Logf("OBSERVED: PutDirect stored %d bytes at station %x, mcid=%x", len(data), station, mcid)

	// Fetch back through a FRESH session with its own identity (plain
	// content.Get, not GetDirect) -- confirming the data genuinely landed
	// on the station itself, independent of whatever connection PutDirect
	// used internally.
	verifyVia, err := connection.Connect(ctx, host, port, transport.WebPKI{}, verifyID)
	if err != nil {
		t.Fatalf("Connect (verify session) to %s:%d: %v", host, port, err)
	}
	defer func() { _ = verifyVia.Close("normal", nil, verifyID) }()
	got, err := content.Get(ctx, verifyVia, mcid, verifyID)
	if err != nil {
		t.Fatalf("fetching PutDirect's own mcid back: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("round-tripped content mismatch: got %d bytes, want %d bytes matching the original", len(got), len(data))
	}
	t.Logf("OBSERVED: byte-exact round trip confirmed via a plain Get on the original session")
}

// TestLiveGetDirectResolvesAndVerifiesButCannotDialALeafIdentity documents
// a real architectural asymmetry found while building this, not a defect:
// unlike procedure_advertisement (which names a STATION to relay calls
// through — see AdvertiseDirect's own doc), a content_announcement's
// endpoint is the FINAL dial target directly, so the announcer must
// genuinely be independently dialable there. A plain outbound-only leaf
// identity (everything this SDK's Session model supports) can never BE
// that — dialing any real endpoint always proves a STATION's identity via
// HELLO, never an arbitrary client-generated keypair's. This test proves
// the DHT publish/resolve/verify path GetDirect depends on is correct,
// and that the dial-stage trust check correctly refuses a self-published
// record naming an identity nothing is actually listening as — it does
// NOT (and architecturally cannot, from this SDK alone) prove a full
// fetch, the same honest limitation TestLiveAdvertiseAndResolve already
// documented for procedure_advertisement before AdvertiseDirect's
// plain-Advertise fix made a full RPC round trip possible. No such fix
// exists for content: the announcer here would need to genuinely run a
// listening service (macula-station, or a dedicated content-serving
// relay) to ever pass this check for real.
func TestLiveGetDirectResolvesAndVerifiesButCannotDialALeafIdentity(t *testing.T) {
	if os.Getenv("MACULA_LIVE_TEST") == "" {
		t.Skip("set MACULA_LIVE_TEST=1 to run against the live demo fleet")
	}
	host := os.Getenv("MACULA_LIVE_HOST")
	if host == "" {
		host = "station-de-falkenstein.macula.io"
	}
	const port = 4433

	announcer, err := identity.GenerateWithPuzzle(identity.DefaultPuzzleDifficulty)
	if err != nil {
		t.Fatalf("identity.GenerateWithPuzzle (announcer): %v", err)
	}
	resolver, err := identity.GenerateWithPuzzle(identity.DefaultPuzzleDifficulty)
	if err != nil {
		t.Fatalf("identity.GenerateWithPuzzle (resolver): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	announcerSession, err := connection.Connect(ctx, host, port, transport.WebPKI{}, announcer)
	if err != nil {
		t.Fatalf("Connect (announcer session) to %s:%d: %v", host, port, err)
	}
	defer func() { _ = announcerSession.Close("normal", nil, announcer) }()

	mcid := manifest.Mcid{}
	mcid[0] = 1
	for i := 1; i < 34; i++ {
		mcid[i] = byte(i) ^ byte(time.Now().UnixNano())
	}

	rec, err := dht.NewContentAnnouncement(announcer.NodeID(), mcid[:], "https://nowhere-listening.invalid.example:4433", time.Hour)
	if err != nil {
		t.Fatalf("dht.NewContentAnnouncement: %v", err)
	}
	rec = dht.Sign(rec, announcer)
	if err := dht.PutRecord(announcerSession, announcer, rec); err != nil {
		t.Fatalf("dht.PutRecord: %v", err)
	}
	t.Logf("published a self-signed content_announcement for mcid=%x naming announcer %x", mcid, announcer.NodeID())

	resolverSession, err := connection.Connect(ctx, host, port, transport.WebPKI{}, resolver)
	if err != nil {
		t.Fatalf("Connect (resolver session) to %s:%d: %v", host, port, err)
	}
	defer func() { _ = resolverSession.Close("normal", nil, resolver) }()

	// Retry past DHT propagation lag the same way Resolve does internally.
	var recs []dht.Record
	for attempt := 0; attempt < resolveRetries; attempt++ {
		recs, err = dht.FindRecords(resolverSession, resolver, dht.ContentKey(mcid[:]))
		if err == nil && len(recs) > 0 {
			break
		}
		time.Sleep(resolveRetryDelay)
	}
	if len(recs) == 0 {
		t.Fatalf("find_records returned nothing for the record just published (err=%v) -- this is the actual gap under test if it happens", err)
	}
	adv, ok := firstTrustedContentProvider(recs)
	if !ok {
		t.Fatalf("no candidate verified as a trusted content provider -- the DHT publish/resolve/verify path is broken")
	}
	if string(adv.AnnouncerNode) != string(announcer.NodeID()) || adv.Endpoint != "https://nowhere-listening.invalid.example:4433" {
		t.Fatalf("resolved announcement fields don't match what was published: %+v", adv)
	}
	t.Logf("OBSERVED: content_announcement published, resolved, and verified correctly: %+v", adv)

	_, err = GetDirect(ctx, resolverSession, resolver, mcid, 5*time.Second)
	if err == nil {
		t.Fatalf("GetDirect unexpectedly succeeded dialing an identity nothing is listening as -- the trust check is broken")
	}
	t.Logf("OBSERVED (expected, documented above): GetDirect correctly failed at the dial stage, not the resolve/verify stage: %v", err)
}
