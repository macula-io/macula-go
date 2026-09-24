package stationlink

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
)

const (
	servedProcedure = "mcl-echo/echo"
	recordLabel     = "MACULA-PQ-RECORD-V1"
)

var servedRealm = [32]byte{0x11}

// realmFixture is a test realm: its key, an org "mcl-echo" whose key the
// realm names in an org directory, and that org's delegation of its
// procedures to one advertiser, both as record wire bytes.
type realmFixture struct {
	realm, org *identity.NodeKey
	directory  []byte
	delegation []byte
	trust      record.Trust
}

// signedRecord is a record of type t with payload, signed as its issuer signs
// it; the test holds the realm's and the org's keys as identity keys.
func signedRecord(t *testing.T, recordType record.Type, payload cbor.Value, key *identity.NodeKey) []byte {
	t.Helper()
	version, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	now := time.Now().UnixMilli()
	fields := []cbor.MapEntry{
		{Key: cbor.Text("type"), Val: cbor.Uint64(uint64(recordType))},
		{Key: cbor.Text("version"), Val: cbor.Bytes(version[:])},
		{Key: cbor.Text("created_at"), Val: cbor.Uint64(uint64(now))},
		{Key: cbor.Text("expires_at"), Val: cbor.Uint64(uint64(now + 6*3_600_000))},
		{Key: cbor.Text("payload"), Val: payload},
	}
	object, err := identity.SignObject(recordLabel, fields, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cbor.Encode(object.Value())
}

func newRealmFixture(t *testing.T, p profile.Profile, advertiser [32]byte) realmFixture {
	t.Helper()
	realmKey := sharedIdentityKey(t, p, "realm")
	orgKey := sharedIdentityKey(t, p, "org")
	orgKeyID := identity.KeyIDOf(orgKey.PublicKey(), p)
	directory := signedRecord(t, record.TypeOrgDirectory, cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("realm_id"), Val: cbor.Bytes(servedRealm[:])},
		{Key: cbor.Text("org_name"), Val: cbor.Text("mcl-echo")},
		{Key: cbor.Text("org_key"), Val: cbor.Bytes(orgKeyID[:])},
	}), realmKey)
	delegation := signedRecord(t, record.TypeProcedureDelegation, cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("org_key"), Val: cbor.Bytes(orgKeyID[:])},
		{Key: cbor.Text("advertiser"), Val: cbor.Bytes(advertiser[:])},
	}), orgKey)
	return realmFixture{realm: realmKey, org: orgKey, directory: directory, delegation: delegation,
		trust: record.Trust{Profile: p, RealmKey: realmKey.PublicKey()}}
}

// servingStation is a station whose DHT holds the fixture's chain, whose
// client's frames other than CALLs arrive on others, and which can send the
// client CALLs as another node.
type servingStation struct {
	*testStation
	others <-chan []byte
	dht    *dhtStation
	caller *identity.NodeKey
	seq    uint64
}

func startServing(t *testing.T, p profile.Profile) (*Link, *servingStation, realmFixture) {
	t.Helper()
	link, s := linkWithStation(t, p)
	fixture := newRealmFixture(t, p, link.NodeID())
	d := &dhtStation{byKey: map[[32]byte][][]byte{}, byType: map[record.Type][][]byte{}}
	orgKeyID := identity.KeyIDOf(fixture.org.PublicKey(), p)
	d.byKey[record.OrgDirectoryKey(servedRealm, "mcl-echo")] = [][]byte{fixture.directory}
	d.byKey[record.ProcedureDelegationKey(orgKeyID, link.NodeID())] = [][]byte{fixture.delegation}
	others := s.answerCalls(d.answer(t, s))
	return link, &servingStation{testStation: s, others: others, dht: d, caller: sharedIdentityKey(t, p, "caller")}, fixture
}

// nextOther is the next frame from the client that is not a CALL.
func (s *servingStation) nextOther(t *testing.T) cbor.Value {
	t.Helper()
	select {
	case raw := <-s.others:
		return decodeFrame(t, raw)
	case <-time.After(10 * time.Second):
		t.Fatal("no frame from the client")
		return cbor.Value{}
	}
}

// nextControl opens the next control frame from the client at its seq.
func (s *servingStation) nextControl(t *testing.T) cbor.Value {
	t.Helper()
	v := s.nextOther(t)
	opened, err := frame.VerifyNeighbour(v, frame.NeighbourPeer{Profile: s.profile, PeerKey: s.client.IdentityKey, Connection: s.connection, Seq: s.seq})
	if err != nil {
		t.Fatalf("a control frame that does not open: %v", err)
	}
	name, _ := fieldOfTest(v, "frame_type").AsText()
	if frame.NeighbourSigned(s.profile, name) {
		s.seq++
	}
	return opened
}

// call sends the client a CALL to procedure from the caller, with deadline,
// and returns it, verified, as the client will read it.
func (s *servingStation) call(t *testing.T, target [32]byte, procedure string, payload cbor.Value, deadline time.Time) (cbor.Value, frame.VerifiedRequest) {
	t.Helper()
	var id [16]byte
	_, _ = rand.Read(id[:])
	signed, err := frame.SignCall(frame.RequestSpec{RequestID: id, Realm: servedRealm, Procedure: procedure, Target: target,
		Deadline: uint64(deadline.UnixMilli()), Payload: payload}, s.caller)
	if err != nil {
		t.Fatalf("SignCall: %v", err)
	}
	request, err := frame.VerifyRequest(signed, s.profile)
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	s.send(cbor.Encode(signed))
	return signed, request
}

func serveEcho(t *testing.T, link *Link, fixture realmFixture, handler Handler) *Served {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	served, err := link.Serve(ctx, Offer{Realm: servedRealm, Procedure: servedProcedure, Handler: handler, RealmKey: fixture.realm.PublicKey()})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	return served
}

func echo(_ context.Context, r Request) (cbor.Value, error) { return r.Payload, nil }

// Serve resolves the org directory and the delegation from the DHT and
// advertises a signed procedure_advertisement whose authorization the realm's
// key verifies, naming this node as advertiser and the connected station as
// serving station.
func TestServeAdvertisesWithTheDelegationChain(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			link, s, fixture := startServing(t, p)
			serveEcho(t, link, fixture, echo)
			advertise := s.nextControl(t)
			wire, _ := fieldOfTest(advertise, "advertisement").AsBytes()
			verified, err := record.Verify(wire, p, time.Now().UnixMilli())
			if err != nil {
				t.Fatalf("the advertisement: %v", err)
			}
			if err := record.VerifyAuthorization(verified, fixture.trust, time.Now().UnixMilli()); err != nil {
				t.Errorf("its authorization: %v", err)
			}
			ad, err := record.ReadProcedureAdvertisement(verified.Record())
			if err != nil || ad.Procedure != servedProcedure || ad.AdvertiserNode != link.NodeID() || ad.ServingStation != s.nodeID {
				t.Errorf("advertisement %+v, %v", ad, err)
			}
		})
	}
}

// A served procedure answers a CALL with a RESULT its caller verifies, the
// handler seeing the verified caller; a handler's error goes out as
// handler_error with its text.
func TestAServedProcedureAnswersCalls(t *testing.T) {
	link, s, fixture := startServing(t, profile.PQPure)
	callerID, _ := s.caller.NodeID()
	serveEcho(t, link, fixture, func(_ context.Context, r Request) (cbor.Value, error) {
		if r.Caller != callerID {
			t.Errorf("the handler saw caller %x", r.Caller)
		}
		if text, _ := r.Payload.AsText(); text == "fail" {
			return cbor.Value{}, errors.New("refused by the handler")
		}
		return r.Payload, nil
	})
	s.nextControl(t)
	_, request := s.call(t, link.NodeID(), servedProcedure, cbor.Text("hello"), time.Now().Add(5*time.Second))
	reply, err := frame.VerifyReply(s.nextOther(t), request, profile.PQPure)
	if text, _ := reply.Payload.AsText(); err != nil || reply.FrameType != "result" || text != "hello" {
		t.Errorf("the RESULT: %+v, %v", reply, err)
	}
	_, failing := s.call(t, link.NodeID(), servedProcedure, cbor.Text("fail"), time.Now().Add(5*time.Second))
	reply, err = frame.VerifyReply(s.nextOther(t), failing, profile.PQPure)
	if err != nil || reply.Code != "handler_error" || reply.Detail == nil || *reply.Detail != "refused by the handler" {
		t.Errorf("the ERROR: %+v, %v", reply, err)
	}
}

// A copy of an answered CALL gets the stored reply again, byte for byte; a
// CALL past its deadline window is refused expired; a procedure not served
// here is unknown_next_peer.
func TestAdmissionAnswersCopiesAndRefusesTheRest(t *testing.T) {
	link, s, fixture := startServing(t, profile.PQPure)
	serveEcho(t, link, fixture, echo)
	s.nextControl(t)
	signed, request := s.call(t, link.NodeID(), servedProcedure, cbor.Text("once"), time.Now().Add(5*time.Second))
	first := cbor.Encode(s.nextOther(t))
	s.send(cbor.Encode(signed))
	if second := cbor.Encode(s.nextOther(t)); !bytes.Equal(first, second) {
		t.Error("the copy's reply differs from the stored reply")
	}
	if _, err := frame.VerifyReply(decodeFrame(t, first), request, profile.PQPure); err != nil {
		t.Errorf("the stored reply: %v", err)
	}
	_, old := s.call(t, link.NodeID(), servedProcedure, cbor.Text("late"), time.Now().Add(-6*time.Minute))
	reply, err := frame.VerifyReply(s.nextOther(t), old, profile.PQPure)
	if err != nil || reply.Code != "expired" {
		t.Errorf("an expired CALL: %+v, %v", reply, err)
	}
	_, unknown := s.call(t, link.NodeID(), "mcl-echo/nothing_here", cbor.Map(nil), time.Now().Add(5*time.Second))
	reply, err = frame.VerifyReply(s.nextOther(t), unknown, profile.PQPure)
	if err != nil || reply.Code != "unknown_next_peer" {
		t.Errorf("an unknown procedure: %+v, %v", reply, err)
	}
}

// Serving refuses what it cannot serve: a procedure outside any org, a gated
// policy (no post-quantum UCAN yet), and an org whose delegation the DHT does
// not hold.
func TestServeRefusesWhatItCannotServe(t *testing.T) {
	link, s, fixture := startServing(t, profile.PQPure)
	_ = s
	ctx := t.Context()
	if _, err := link.Serve(ctx, Offer{Realm: servedRealm, Procedure: "echo", Handler: echo, RealmKey: fixture.realm.PublicKey()}); !errors.Is(err, ErrNoOrg) {
		t.Errorf("a procedure outside any org: %v, want ErrNoOrg", err)
	}
	if _, err := link.Serve(ctx, Offer{Realm: servedRealm, Procedure: servedProcedure, Handler: echo, RealmKey: fixture.realm.PublicKey(), Gated: true}); !errors.Is(err, ErrGatedUnsupported) {
		t.Errorf("a gated procedure: %v, want ErrGatedUnsupported", err)
	}
	if _, err := link.Serve(ctx, Offer{Realm: [32]byte{0x99}, Procedure: servedProcedure, Handler: echo, RealmKey: fixture.realm.PublicKey()}); !errors.Is(err, ErrRecordNotFound) {
		t.Errorf("a realm with no directory for the org: %v, want ErrRecordNotFound", err)
	}
}

// Stop withdraws the advertisement: UNADVERTISE carries a tombstone the
// advertiser signed, and the procedure is no longer served.
func TestStopWithdrawsTheAdvertisement(t *testing.T) {
	link, s, fixture := startServing(t, profile.PQHybrid)
	served := serveEcho(t, link, fixture, echo)
	s.nextControl(t)
	if err := served.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	unadvertise := s.nextControl(t)
	wire, _ := fieldOfTest(unadvertise, "withdrawal").AsBytes()
	verified, err := record.Verify(wire, profile.PQHybrid, time.Now().UnixMilli())
	if err != nil || verified.Record().Type != record.TypeTombstone {
		t.Errorf("the withdrawal: %v, %v", verified.Record().Type, err)
	}
	_, request := s.call(t, link.NodeID(), servedProcedure, cbor.Map(nil), time.Now().Add(5*time.Second))
	reply, err := frame.VerifyReply(s.nextOther(t), request, profile.PQHybrid)
	if err != nil || reply.Code != "unknown_next_peer" {
		t.Errorf("after Stop: %+v, %v", reply, err)
	}
}

// quiet asserts the client sends nothing for a while.
func (s *servingStation) quiet(t *testing.T) {
	t.Helper()
	select {
	case raw := <-s.others:
		t.Errorf("an unexpected frame: %s", frameTypeOf(decodeFrame(t, raw)))
	case <-time.After(300 * time.Millisecond):
	}
}

func shortAdvertisements(t *testing.T, ttl, retry time.Duration) {
	t.Helper()
	restoreTTL, restoreRetry := maxAdvertisementTTL, refreshRetry
	maxAdvertisementTTL, refreshRetry = ttl, retry
	t.Cleanup(func() { maxAdvertisementTTL, refreshRetry = restoreTTL, restoreRetry })
}

// A chain the pinned realm key did not sign never reaches the station.
func TestServeRefusesAChainTheRealmKeyDoesNotSign(t *testing.T) {
	link, s, _ := startServing(t, profile.PQPure)
	other := sharedIdentityKey(t, profile.PQPure, "another realm")
	_, err := link.Serve(t.Context(), Offer{Realm: servedRealm, Procedure: servedProcedure, Handler: echo, RealmKey: other.PublicKey()})
	if !errors.Is(err, record.ErrOrgDirectoryWrongRealm) {
		t.Errorf("Serve: %v, want ErrOrgDirectoryWrongRealm", err)
	}
	s.quiet(t)
}

// The advertisement is renewed at half its lifetime, each time with a new
// version.
func TestTheAdvertisementIsRenewed(t *testing.T) {
	shortAdvertisements(t, 2*time.Second, 100*time.Millisecond)
	link, s, fixture := startServing(t, profile.PQPure)
	serveEcho(t, link, fixture, echo)
	versions := map[[16]byte]bool{}
	for range 3 {
		wire, _ := fieldOfTest(s.nextControl(t), "advertisement").AsBytes()
		verified, err := record.Verify(wire, profile.PQPure, time.Now().UnixMilli())
		if err != nil {
			t.Fatalf("an advertisement: %v", err)
		}
		versions[verified.Record().Version] = true
	}
	if len(versions) != 3 {
		t.Error("a renewal repeated an advertisement's version")
	}
}

// When the chain can no longer be found, the advertisement lapses unrenewed:
// the procedure is no longer served, and Err says why.
func TestAnAdvertisementLapsesWhenItsChainIsGone(t *testing.T) {
	shortAdvertisements(t, 1*time.Second, 100*time.Millisecond)
	link, s, fixture := startServing(t, profile.PQPure)
	served := serveEcho(t, link, fixture, echo)
	s.nextControl(t)
	s.dht.mu.Lock()
	clear(s.dht.byKey)
	s.dht.mu.Unlock()
	select {
	case <-served.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the procedure is still served")
	}
	if !errors.Is(served.Err(), ErrRecordNotFound) {
		t.Errorf("Err: %v, want the missing record", served.Err())
	}
	_, request := s.call(t, link.NodeID(), servedProcedure, cbor.Map(nil), time.Now().Add(5*time.Second))
	reply, err := frame.VerifyReply(s.nextOther(t), request, profile.PQPure)
	if err != nil || reply.Code != "unknown_next_peer" {
		t.Errorf("after the lapse: %+v, %v", reply, err)
	}
}

// A handler that panics answers temporary_relay_failure and the link lives on.
func TestAPanickingHandlerAnswersTemporaryRelayFailure(t *testing.T) {
	link, s, fixture := startServing(t, profile.PQPure)
	serveEcho(t, link, fixture, func(context.Context, Request) (cbor.Value, error) { panic("boom") })
	s.nextControl(t)
	_, request := s.call(t, link.NodeID(), servedProcedure, cbor.Map(nil), time.Now().Add(5*time.Second))
	reply, err := frame.VerifyReply(s.nextOther(t), request, profile.PQPure)
	if err != nil || reply.Code != "temporary_relay_failure" {
		t.Errorf("the ERROR: %+v, %v", reply, err)
	}
	select {
	case <-link.Done():
		t.Errorf("the link ended: %v", link.Err())
	default:
	}
}

// A CALL for another node is not answered, and is counted.
func TestACallForAnotherNodeIsNotAnswered(t *testing.T) {
	link, s, fixture := startServing(t, profile.PQPure)
	serveEcho(t, link, fixture, echo)
	s.nextControl(t)
	s.call(t, s.nodeID, servedProcedure, cbor.Map(nil), time.Now().Add(5*time.Second))
	s.quiet(t)
	if n := link.Unrouted()["call_for_another_node"]; n != 1 {
		t.Errorf("counted %d calls for another node", n)
	}
}
