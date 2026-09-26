package stationlink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/seal"
	"github.com/macula-io/macula-go/ucan"
)

// A provider that names its KEM key (macula 13, E2E design §5.1 and amendment
// A1): its advertisement carries the key its keyring holds now, it opens a
// sealed CALL and seals every answer to it, it refuses in the clear, from the
// closed set, what it cannot open, and past its keyless window it refuses a
// clear CALL. The station here plays a caller that seals by hand.

// startSealedServing is startServing with a keyring and kem_advertise on.
func startSealedServing(t *testing.T, p profile.Profile) (*Link, *servingStation, realmFixture, *seal.Keyring) {
	t.Helper()
	ring, err := seal.NewKeyring(p, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	link, s, fixture := startServingWith(t, p, func(c *Config) { c.Keyring, c.KEMAdvertise = ring, true })
	return link, s, fixture, ring
}

// sealedCallKeys are what the hand-sealing caller keeps to open the reply.
type sealedCallKeys struct {
	kRep    [32]byte
	keyID   [seal.KeyIDSize]byte
	request seal.Request
}

// sealedCall sends the provider a CALL whose payload is sealed to pub, with
// deadline, and returns it verified and the keys to open its reply. keyID is
// the key id the sealed map names; a zero keyID names pub's own.
func (s *servingStation) sealedCall(t *testing.T, target [32]byte, procedure string, payload cbor.Value, deadline time.Time,
	pub *seal.PublicKey, keyID [seal.KeyIDSize]byte) (frame.VerifiedRequest, sealedCallKeys) {
	t.Helper()
	if keyID == ([seal.KeyIDSize]byte{}) {
		keyID = seal.KeyID(pub.Carried())
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	caller := s.caller.KeyID()
	ss, kemCt, err := seal.SenderSecret(pub)
	if err != nil {
		t.Fatal(err)
	}
	kReq, kRep := seal.CallKeys(ss, seal.FrameCall, seal.Parties{RequestID: id, Caller: caller, Target: target})
	request := seal.Request{FrameType: seal.FrameCall, Realm: servedRealm, Procedure: procedure, Caller: caller, Target: target,
		RequestID: id, Deadline: uint64(deadline.UnixMilli())}
	ct := seal.Seal(kReq, [seal.NonceSize]byte{}, seal.RequestAAD(request), cbor.Encode(payload))
	signed, err := frame.SignCall(frame.RequestSpec{RequestID: id, Realm: servedRealm, Procedure: procedure, Target: target,
		Deadline: request.Deadline, Sealed: &frame.Sealed{KeyID: keyID, KemCt: kemCt, Ct: ct}}, s.caller)
	if err != nil {
		t.Fatalf("SignCall: %v", err)
	}
	verified, err := frame.VerifyRequest(signed, s.profile)
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	s.send(cbor.Encode(signed))
	return verified, sealedCallKeys{kRep: kRep, keyID: keyID, request: request}
}

// opened is a sealed reply opened as its caller opens it: a RESULT's payload,
// or an ERROR's code and detail.
func (k sealedCallKeys) opened(t *testing.T, reply frame.VerifiedReply, requestHash [48]byte) (cbor.Value, string, string) {
	t.Helper()
	if reply.Sealed == nil {
		t.Fatalf("a clear %s answered a sealed request: %s", reply.FrameType, reply.Code)
	}
	if reply.Sealed.KeyID != k.keyID {
		t.Fatalf("the reply names key %x, the request was sealed to %x", reply.Sealed.KeyID, k.keyID)
	}
	plain, err := seal.Open(k.kRep, [seal.NonceSize]byte(reply.Sealed.Nonce),
		seal.ReplyAAD(k.request, reply.FrameType, requestHash, reply.RespondedBy), reply.Sealed.Ct)
	if err != nil {
		t.Fatalf("the sealed %s does not open: %v", reply.FrameType, err)
	}
	if reply.FrameType == "error" {
		code, detail, err := seal.OpenErrorPlain(plain)
		if err != nil {
			t.Fatal(err)
		}
		return cbor.Value{}, code, detail
	}
	payload, err := cbor.Decode(plain)
	if err != nil {
		t.Fatal(err)
	}
	return payload, "", ""
}

func serveOffer(t *testing.T, link *Link, o Offer) *Served {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	served, err := link.Serve(ctx, o)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	return served
}

func advertisedKEMKey(t *testing.T, s *servingStation) record.ProcedureAdvertisement {
	t.Helper()
	advertise := s.nextControl(t)
	wire, _ := fieldOfTest(advertise, "advertisement").AsBytes()
	verified, err := record.Verify(wire, s.profile, time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("the advertisement: %v", err)
	}
	return must[record.ProcedureAdvertisement](t)(record.ReadProcedureAdvertisement(verified.Record()))
}

func TestAKeyedProviderNamesItsKEMKey(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			link, s, fixture, ring := startSealedServing(t, p)
			serveEcho(t, link, fixture, echo)
			ad := advertisedKEMKey(t, s)
			if ad.KEMKeyID != ring.CurrentID() || len(ad.KEMKey) != seal.CarriedSize(p) {
				t.Errorf("the advertisement names key %x (%d bytes), the keyring holds %x", ad.KEMKeyID, len(ad.KEMKey), ring.CurrentID())
			}
		})
	}
	link, s, fixture, _ := startSealedServing(t, profile.PQPure)
	serveOffer(t, link, Offer{Realm: servedRealm, Procedure: servedProcedure, Handler: echo, RealmKey: fixture.realm.PublicKey(),
		Confidential: ConfidentialOff})
	if ad := advertisedKEMKey(t, s); ad.KEMKey != nil {
		t.Error("an offer with confidentiality off named a key")
	}
	plain, ps, pfixture := startServing(t, profile.PQPure)
	serveEcho(t, plain, pfixture, echo)
	if ad := advertisedKEMKey(t, ps); ad.KEMKey != nil {
		t.Error("a link with kem_advertise off named a key")
	}
	_, err := plain.Serve(t.Context(), Offer{Realm: servedRealm, Procedure: "mcl-echo/other", Handler: echo,
		RealmKey: pfixture.realm.PublicKey(), Confidential: ConfidentialRequired})
	if !errors.Is(err, ErrKEMAdvertiseDisabled) {
		t.Errorf("a required offer with kem_advertise off: %v, want ErrKEMAdvertiseDisabled", err)
	}
}

// A sealed CALL is opened, served on its plaintext, and answered sealed:
// a RESULT, a handler's error, an unknown procedure, a crash.
func TestASealedCallIsAnsweredSealed(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			link, s, fixture, ring := startSealedServing(t, p)
			var sawSealed bool
			serveEcho(t, link, fixture, func(_ context.Context, r Request) (cbor.Value, error) {
				sawSealed = r.Sealed
				if text, _ := r.Payload.AsText(); text == "fail" {
					return cbor.Value{}, errors.New("refused by the handler")
				}
				if text, _ := r.Payload.AsText(); text == "boom" {
					panic("boom")
				}
				return r.Payload, nil
			})
			s.nextControl(t)
			pub := ring.Current().PublicKey()
			deadline := time.Now().Add(5 * time.Second)
			for _, c := range []struct {
				name, procedure string
				payload         cbor.Value
				result          string
				code            string
				detail          string
			}{
				{"a result", servedProcedure, cbor.Text("hello"), "hello", "", ""},
				{"a handler's error", servedProcedure, cbor.Text("fail"), "", codeHandlerError, "refused by the handler"},
				{"a crash", servedProcedure, cbor.Text("boom"), "", codeHandlerCrashed, ""},
				{"an unknown procedure", "mcl-echo/nothing_here", cbor.Text("x"), "", codeUnknownProcedure, ""},
			} {
				request, keys := s.sealedCall(t, link.NodeID(), c.procedure, c.payload, deadline, pub, [8]byte{})
				reply, err := frame.VerifyReply(s.nextOther(t), request, p)
				if err != nil {
					t.Fatalf("%s: %v", c.name, err)
				}
				payload, code, detail := keys.opened(t, reply, request.RequestHash)
				if text, _ := payload.AsText(); text != c.result || code != c.code || detail != c.detail {
					t.Errorf("%s: opened %q, %q, %q", c.name, text, code, detail)
				}
			}
			if !sawSealed {
				t.Error("the handler was not told its request came sealed")
			}
		})
	}
}

// What a sealed ERROR says is sealed: an unknown procedure's answer and an
// unauthorized one are the same on the wire but for the sealed body.
func TestSealedErrorsShowNothingButTheirSealedBody(t *testing.T) {
	link, s, fixture, ring := startSealedServing(t, profile.PQPure)
	serveOffer(t, link, Offer{Realm: servedRealm, Procedure: servedProcedure, Handler: echo, RealmKey: fixture.realm.PublicKey(),
		Policy: gatedOnSomeoneElse()})
	s.nextControl(t)
	pub := ring.Current().PublicKey()
	deadline := time.Now().Add(5 * time.Second)
	shapes := map[string][]string{}
	for name, procedure := range map[string]string{"unauthorized": servedProcedure, "unknown": "mcl-echo/nothing_here"} {
		request, keys := s.sealedCall(t, link.NodeID(), procedure, cbor.Text("x"), deadline, pub, [8]byte{})
		v := s.nextOther(t)
		reply, err := frame.VerifyReply(v, request, profile.PQPure)
		if err != nil {
			t.Fatal(err)
		}
		if _, code, _ := keys.opened(t, reply, request.RequestHash); code != map[string]string{"unauthorized": codeUnauthorized,
			"unknown": codeUnknownProcedure}[name] {
			t.Errorf("%s opened as %q", name, code)
		}
		shapes[name] = replyShape(t, v)
	}
	if a, b := shapes["unauthorized"], shapes["unknown"]; !equalStrings(a, b) {
		t.Errorf("the two sealed ERRORs differ on the wire outside their sealed body:\n%v\n%v", a, b)
	}
}

func TestWhatDoesNotOpenIsRefusedInTheClear(t *testing.T) {
	link, s, fixture, ring := startSealedServing(t, profile.PQPure)
	serveEcho(t, link, fixture, echo)
	s.nextControl(t)
	current := hex.EncodeToString(func() []byte { id := ring.CurrentID(); return id[:] }())
	deadline := time.Now().Add(5 * time.Second)
	other := must[*seal.PrivateKey](t)(seal.GenerateKey(profile.PQPure)).PublicKey()
	for name, c := range map[string]struct {
		pub   *seal.PublicKey
		keyID [seal.KeyIDSize]byte
	}{
		"sealed to a key this node never held":      {other, [8]byte{}},
		"naming the current key, sealed to another": {other, ring.CurrentID()},
	} {
		request, _ := s.sealedCall(t, link.NodeID(), servedProcedure, cbor.Text("x"), deadline, c.pub, c.keyID)
		reply, err := frame.VerifyReply(s.nextOther(t), request, profile.PQPure)
		if err != nil || reply.Sealed != nil || reply.Code != codeSealedRefused || reply.Detail == nil || *reply.Detail != current {
			t.Errorf("%s: %+v, %v", name, reply, err)
		}
	}

	plain, ps, pfixture := startServing(t, profile.PQPure)
	serveEcho(t, plain, pfixture, echo)
	ps.nextControl(t)
	request, _ := ps.sealedCall(t, plain.NodeID(), servedProcedure, cbor.Text("x"), deadline, other, [8]byte{})
	reply, err := frame.VerifyReply(ps.nextOther(t), request, profile.PQPure)
	if err != nil || reply.Code != codeSealedRefused || reply.Detail == nil || *reply.Detail != "this node opens no sealed payload" {
		t.Errorf("a node without a keyring: %+v, %v", reply, err)
	}

	late, _ := s.sealedCall(t, link.NodeID(), servedProcedure, cbor.Text("x"), time.Now().Add(-6*time.Minute),
		ring.Current().PublicKey(), [8]byte{})
	reply, err = frame.VerifyReply(s.nextOther(t), late, profile.PQPure)
	if err != nil || reply.Sealed != nil || reply.Code != "expired" {
		t.Errorf("an admission refusal of a sealed CALL: %+v, %v", reply, err)
	}
}

// A procedure under `required` refuses a clear CALL at once; a keyed one under
// `preferred` takes clear CALLs only while its last keyless advertisement could
// still be served: the advertisement's lifetime and the clock tolerance from
// the moment it was first keyed.
func TestAKeyedProcedureRefusesClearCallsPastItsWindow(t *testing.T) {
	link, s, fixture, _ := startSealedServing(t, profile.PQPure)
	serveOffer(t, link, Offer{Realm: servedRealm, Procedure: servedProcedure, Handler: echo, RealmKey: fixture.realm.PublicKey(),
		Confidential: ConfidentialRequired})
	s.nextControl(t)
	_, request := s.call(t, link.NodeID(), servedProcedure, cbor.Text("x"), time.Now().Add(5*time.Second))
	if reply, err := frame.VerifyReply(s.nextOther(t), request, profile.PQPure); err != nil || reply.Code != codeSealedRequired {
		t.Errorf("a clear CALL to a required procedure: %+v, %v", reply, err)
	}

	within := serveOffer(t, link, Offer{Realm: servedRealm, Procedure: "mcl-echo/within", Handler: echo,
		RealmKey: fixture.realm.PublicKey()})
	s.nextControl(t)
	_, request = s.call(t, link.NodeID(), "mcl-echo/within", cbor.Text("x"), time.Now().Add(5*time.Second))
	if reply, err := frame.VerifyReply(s.nextOther(t), request, profile.PQPure); err != nil || reply.FrameType != "result" {
		t.Errorf("a clear CALL inside the window: %+v, %v", reply, err)
	}
	_ = within
	serveOffer(t, link, Offer{Realm: servedRealm, Procedure: "mcl-echo/past", Handler: echo, RealmKey: fixture.realm.PublicKey(),
		KeyedSince: time.Now().Add(-maxAdvertisementTTL - record.ClockToleranceMs*time.Millisecond - time.Second)})
	s.nextControl(t)
	_, request = s.call(t, link.NodeID(), "mcl-echo/past", cbor.Text("x"), time.Now().Add(5*time.Second))
	if reply, err := frame.VerifyReply(s.nextOther(t), request, profile.PQPure); err != nil || reply.Code != codeSealedRequired {
		t.Errorf("a clear CALL past the window: %+v, %v", reply, err)
	}
}

// replyShape is everything of a reply frame on the wire outside its sealed
// map's nonce and ct: its frame keys, its signed fields, and the sealed map's
// keys and key id.
func replyShape(t *testing.T, v cbor.Value) []string {
	t.Helper()
	var shape []string
	frameEntries, _ := v.AsMap()
	for _, e := range frameEntries {
		k, _ := e.Key.AsText()
		shape = append(shape, "frame:"+k)
	}
	reply, _ := v.Get("reply")
	tbsBytes, _ := reply.Get("tbs")
	raw, _ := tbsBytes.AsBytes()
	tbs := must[cbor.Value](t)(cbor.Decode(raw))
	entries, _ := tbs.AsMap()
	for _, e := range entries {
		k, _ := e.Key.AsText()
		switch k {
		case "request_id", "request_hash":
			shape = append(shape, "tbs:"+k)
		case "sealed":
			inner, _ := e.Val.AsMap()
			for _, s := range inner {
				sk, _ := s.Key.AsText()
				if sk == "key_id" || sk == "scheme" {
					shape = append(shape, "sealed:"+sk+"="+hex.EncodeToString(cbor.Encode(s.Val)))
				} else {
					shape = append(shape, "sealed:"+sk)
				}
			}
		default:
			shape = append(shape, "tbs:"+k+"="+hex.EncodeToString(cbor.Encode(e.Val)))
		}
	}
	return shape
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// gatedOnSomeoneElse is a policy no caller here holds a token for.
func gatedOnSomeoneElse() ucan.Policy {
	return ucan.UCANRequired{Issuer: [32]byte{0x42}}
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
