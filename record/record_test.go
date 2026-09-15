package record

import (
	"bytes"
	"crypto/fips140"
	"crypto/sha512"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_record_tests at merge-11.0.0 0d8abf3d for
// the record envelope: records are {key, tbs, signature} under
// MACULA-PQ-RECORD-V1, the signer's key arrives at Sign, and Verify refuses what
// the design refuses. Go keys have the identity and connect purposes only, so
// the cases that sign with a realm, org or foundation key are here as verifier
// cases over a tbs signed by hand, and those types' readers come with the
// authorization port. macula also verifies a record given as its {key, tbs,
// signature} map; Go verifies the wire form, which is what the DHT carries.

const (
	testMinute = int64(60_000)
	testHour   = 60 * testMinute
	testDay    = 24 * testHour
	kib        = 1024
)

type testKeys struct {
	node, other, connect *identity.NodeKey
}

var generatedKeys = sync.OnceValues(func() (testKeys, error) {
	var keys testKeys
	var err error
	if keys.node, err = identity.GenerateKey(identity.PurposeIdentity, profile.PQPure); err != nil {
		return testKeys{}, err
	}
	if keys.other, err = identity.GenerateKey(identity.PurposeIdentity, profile.PQPure); err != nil {
		return testKeys{}, err
	}
	keys.connect, err = identity.GenerateKey(identity.PurposeConnect, profile.PQPure)
	return keys, err
})

func keysFor(t *testing.T) testKeys {
	t.Helper()
	keys, err := generatedKeys()
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

func fill(b byte) (id [32]byte) {
	for i := range id {
		id[i] = b
	}
	return id
}

func idBytes(b byte) []byte {
	id := fill(b)
	return id[:]
}

func nowMs() int64 { return time.Now().UnixMilli() }

func signedNodeRecord(t *testing.T, key *identity.NodeKey) Record {
	t.Helper()
	return must[Record](t)(Sign(must[Record](t)(NewNodeRecord(key.KeyID(), nil, 0, NodeRecordOptions{})), key))
}

func wireOf(t *testing.T, r Record) []byte {
	t.Helper()
	return must[[]byte](t)(Encode(r))
}

func nodePayload(nodeID [32]byte) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		bytesEntry("node_id", nodeID[:]),
		bytesEntry("station_id", nodeID[:]),
		valueEntry("realms", cbor.List(nil)),
		uintEntry("capabilities", 0),
	})
}

func advertisementPayload(advertiser [32]byte) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		bytesEntry("realm_id", idBytes(0x11)),
		textEntry("procedure", "acme/echo_v1"),
		bytesEntry("advertiser_node", advertiser[:]),
		bytesEntry("serving_station", idBytes(0x77)),
	})
}

func contentAnnouncementPayload(announcer [32]byte) cbor.Value {
	mcid := make([]byte, 50)
	mcid[0], mcid[1] = 2, 0x55
	return cbor.Map([]cbor.MapEntry{
		bytesEntry("announcer_node", announcer[:]),
		bytesEntry("mcid", mcid),
		textEntry("endpoint", "quic://a.example:4433"),
	})
}

// recordFields is the tbs fields of a record of type t created at createdAt and
// living lifetimeMs, to sign by hand past what Sign would build; signing adds
// alg.
func recordFields(t *testing.T, recordType Type, payload cbor.Value, createdAt, lifetimeMs int64) []cbor.MapEntry {
	t.Helper()
	version := must[uuid.UUID](t)(uuid.NewV7())
	return []cbor.MapEntry{
		uintEntry("type", uint64(recordType)),
		bytesEntry("version", version[:]),
		uintEntry("created_at", uint64(createdAt)),
		uintEntry("expires_at", uint64(createdAt+lifetimeMs)),
		valueEntry("payload", payload),
	}
}

// nodeFields is the tbs fields of a node record about key's node, created at
// createdAt and living an hour.
func nodeFields(t *testing.T, key *identity.NodeKey, createdAt int64) []cbor.MapEntry {
	t.Helper()
	return recordFields(t, TypeNodeRecord, nodePayload(key.KeyID()), createdAt, testHour)
}

// signedByHand is the wire form of fields signed under objectLabel by key,
// whatever record rules they break.
func signedByHand(t *testing.T, objectLabel string, fields []cbor.MapEntry, key *identity.NodeKey) []byte {
	t.Helper()
	return cbor.Encode(must[identity.Object](t)(identity.SignObject(objectLabel, fields, key)).Value())
}

func withEntry(entries []cbor.MapEntry, name string, value cbor.Value) []cbor.MapEntry {
	return append(withoutEntry(entries, name), valueEntry(name, value))
}

func withoutEntry(entries []cbor.MapEntry, name string) []cbor.MapEntry {
	return slices.DeleteFunc(slices.Clone(entries), func(e cbor.MapEntry) bool {
		key, _ := e.Key.AsText()
		return key == name
	})
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

func sameValue(a, b cbor.Value) bool {
	return bytes.Equal(cbor.Encode(a), cbor.Encode(b))
}

//------------------------------------------------------------------
// Signing
//------------------------------------------------------------------

func TestASignedRecordCarriesKeyKeyIDAlgTBSAndSignature(t *testing.T) {
	keys := keysFor(t)
	r := signedNodeRecord(t, keys.node)
	switch {
	case !bytes.Equal(r.Key, keys.node.PublicKey()):
		t.Error("the signed record's key is not the signer's key as carried")
	case r.KeyID != keys.node.KeyID():
		t.Errorf("key id %x, want the signer's node_id", r.KeyID)
	case r.Alg != "ML-DSA-87":
		t.Errorf("alg %q, want ML-DSA-87", r.Alg)
	case len(r.Signature) != 4627:
		t.Errorf("a signature of %d bytes, want 4627", len(r.Signature))
	case len(r.TBS) == 0:
		t.Error("the signed record has no tbs")
	}
}

func TestTheTBSHoldsExactlyTheRecordFields(t *testing.T) {
	keys := keysFor(t)
	fields := must[cbor.Value](t)(cbor.Decode(signedNodeRecord(t, keys.node).TBS))
	if got, want := sortedKeys(fields), []string{"alg", "created_at", "expires_at", "payload", "type", "version"}; !slices.Equal(got, want) {
		t.Errorf("the tbs's fields: %v, want %v", got, want)
	}
}

func TestAnUnsignedRecordHasNoKeyAndNoSignature(t *testing.T) {
	r := must[Record](t)(NewNodeRecord(fill(1), nil, 0, NodeRecordOptions{}))
	switch {
	case r.Key != nil || r.Signature != nil || r.TBS != nil:
		t.Errorf("an unsigned record holds a key, tbs or signature: %+v", r)
	case r.Version == [16]byte{}:
		t.Error("an unsigned record has no version")
	case r.ExpiresAt <= r.CreatedAt:
		t.Errorf("an unsigned record expires at %d, created at %d", r.ExpiresAt, r.CreatedAt)
	}
	_, err := Encode(r)
	wantRefusal(t, "encode an unsigned record", err, ErrUnsigned)
}

func TestSignRefusesAKeyWhosePurposeDoesNotFitTheType(t *testing.T) {
	keys := keysFor(t)
	realmDirectory := must[Record](t)(unsigned(TypeRealmDirectory, cbor.Map([]cbor.MapEntry{bytesEntry("realm_id", idBytes(0x11))}), 0))
	delegation := must[Record](t)(unsigned(TypeProcedureDelegation,
		cbor.Map([]cbor.MapEntry{bytesEntry("org_key", idBytes(3)), bytesEntry("advertiser", idBytes(4))}), 0))
	trustList := must[Record](t)(unsigned(TypeFoundationRealmTrustList, cbor.Map(nil), 0))
	domain := must[Record](t)(Envelope(DomainTypeMin, cbor.Map(nil), nil, 0))
	node := must[Record](t)(NewNodeRecord(keys.connect.KeyID(), nil, 0, NodeRecordOptions{}))
	for _, c := range []struct {
		name string
		r    Record
		key  *identity.NodeKey
	}{
		{"a node record signed by a CONNECT key", node, keys.connect},
		{"a realm directory signed by an identity key", realmDirectory, keys.node},
		{"a procedure delegation signed by an identity key", delegation, keys.node},
		{"a foundation realm trust list signed by an identity key", trustList, keys.node},
		{"a domain record signed by a CONNECT key", domain, keys.connect},
	} {
		_, err := Sign(c.r, c.key)
		wantRefusal(t, c.name, err, ErrKeyPurposeMismatch)
	}
}

func TestSignRefusesANodeRecordForAnotherNode(t *testing.T) {
	keys := keysFor(t)
	_, err := Sign(must[Record](t)(NewNodeRecord(fill(9), nil, 0, NodeRecordOptions{})), keys.node)
	wantRefusal(t, "a node record naming another node", err, ErrKeyIDMismatch)
}

func TestSignRefusesARecordLargerThan256KiB(t *testing.T) {
	keys := keysFor(t)
	big := must[Record](t)(NewNodeRecord(keys.node.KeyID(), nil, 0, NodeRecordOptions{DisplayName: strings.Repeat("x", 256*kib)}))
	_, err := Sign(big, keys.node)
	wantRefusal(t, "a node record with a 256 KiB display name", err, ErrRecordTooLarge)
}

//------------------------------------------------------------------
// Verifying
//------------------------------------------------------------------

func TestARecordVerifiesFromItsWireForm(t *testing.T) {
	keys := keysFor(t)
	r := signedNodeRecord(t, keys.node)
	v := must[Record](t)(Verify(wireOf(t, r), profile.PQPure, nowMs()))
	if v.Type != r.Type || v.Version != r.Version || v.CreatedAt != r.CreatedAt || v.ExpiresAt != r.ExpiresAt ||
		v.KeyID != r.KeyID || v.Alg != r.Alg || !bytes.Equal(v.Key, r.Key) || !bytes.Equal(v.TBS, r.TBS) ||
		!bytes.Equal(v.Signature, r.Signature) || !sameValue(v.Payload, r.Payload) {
		t.Errorf("verified %+v, want the signed %+v", v, r)
	}
}

func TestAHybridRecordVerifies(t *testing.T) {
	key := must[*identity.NodeKey](t)(identity.GenerateKey(identity.PurposeIdentity, profile.PQHybrid))
	r := signedNodeRecord(t, key)
	if r.Alg != "ML-DSA-87-PS384" {
		t.Errorf("a pq_hybrid record's alg: %q, want ML-DSA-87-PS384", r.Alg)
	}
	wire := wireOf(t, r)
	if _, err := Verify(wire, profile.PQHybrid, nowMs()); err != nil {
		t.Errorf("verify a pq_hybrid record under pq_hybrid: %v", err)
	}
	_, err := Verify(wire, profile.PQPure, nowMs())
	wantRefusal(t, "a pq_hybrid record under pq_pure", err, ErrMalformed)
}

func TestARecordUnderAnotherProfileIsMalformed(t *testing.T) {
	keys := keysFor(t)
	_, err := Verify(wireOf(t, signedNodeRecord(t, keys.node)), profile.PQHybrid, nowMs())
	wantRefusal(t, "a pq_pure record under pq_hybrid", err, ErrMalformed)
}

func TestARecordSignedUnderAnotherLabelIsRefused(t *testing.T) {
	keys := keysFor(t)
	_, err := Verify(signedByHand(t, "MACULA-PQ-REPLY-V1", nodeFields(t, keys.node, nowMs()), keys.node), profile.PQPure, nowMs())
	wantRefusal(t, "a record signed under MACULA-PQ-REPLY-V1", err, identity.ErrObjectSignatureInvalid)
}

func TestATamperedTBSIsRefused(t *testing.T) {
	keys := keysFor(t)
	object := must[identity.Object](t)(identity.DecodeObject(wireOf(t, signedNodeRecord(t, keys.node))))
	object.TBS = bytes.Clone(object.TBS)
	object.TBS[20] ^= 1
	_, err := Verify(cbor.Encode(object.Value()), profile.PQPure, nowMs())
	wantRefusal(t, "a record with a changed tbs", err, identity.ErrObjectSignatureInvalid)
}

func TestARecordUnderAnotherKeyIsRefused(t *testing.T) {
	keys := keysFor(t)
	object := must[identity.Object](t)(identity.DecodeObject(wireOf(t, signedNodeRecord(t, keys.node))))
	object.Key = keys.other.PublicKey()
	_, err := Verify(cbor.Encode(object.Value()), profile.PQPure, nowMs())
	wantRefusal(t, "a record carrying another key", err, identity.ErrObjectSignatureInvalid)
}

func TestAHeldShapeIsMalformed(t *testing.T) {
	keys := keysFor(t)
	r := signedNodeRecord(t, keys.node)
	_, err := Verify(cbor.Encode(identity.HeldObject{TBS: r.TBS, Signature: r.Signature}.Value()), profile.PQPure, nowMs())
	wantRefusal(t, "a record without its key", err, ErrMalformed)
}

func TestGarbageIsMalformed(t *testing.T) {
	_, err := Verify([]byte{0xFF, 1, 2, 3}, profile.PQPure, nowMs())
	wantRefusal(t, "bytes that are not a record", err, ErrMalformed)
}

func TestARecordLargerThan256KiBIsRefusedBeforeAnyOtherCheck(t *testing.T) {
	keys := keysFor(t)
	nodeID := keys.node.KeyID()
	payload := cbor.Map([]cbor.MapEntry{
		bytesEntry("node_id", nodeID[:]),
		textEntry("display_name", strings.Repeat("x", 256*kib)),
	})
	wire := signedByHand(t, label, recordFields(t, TypeNodeRecord, payload, nowMs(), testHour), keys.node)
	if len(wire) <= 256*kib {
		t.Fatalf("the crafted record is %d bytes, want over 256 KiB", len(wire))
	}
	_, err := Verify(wire, profile.PQPure, nowMs())
	wantRefusal(t, "a record over 256 KiB", err, ErrRecordTooLarge)
	_, err = Verify(append(wire, 0), profile.PQPure, nowMs())
	wantRefusal(t, "a record over 256 KiB with a byte after it", err, ErrRecordTooLarge)
}

func TestTBSFieldsTheDesignDoesNotAllowAreMalformed(t *testing.T) {
	keys := keysFor(t)
	base := nodeFields(t, keys.node, nowMs())
	verify := func(fields []cbor.MapEntry) error {
		_, err := Verify(signedByHand(t, label, fields, keys.node), profile.PQPure, nowMs())
		return err
	}
	if err := verify(base); err != nil {
		t.Fatalf("the crafted node record: %v, want it verified", err)
	}
	for _, c := range []struct {
		name   string
		fields []cbor.MapEntry
	}{
		{"a field no record has", withEntry(base, "extra", cbor.Uint64(1))},
		{"no version", withoutEntry(base, "version")},
		{"a 15-byte version", withEntry(base, "version", cbor.Bytes(make([]byte, 15)))},
		{"a subject on a node record", withEntry(base, "subject", cbor.Bytes([]byte{1, 2}))},
		{"a type macula does not define", withEntry(base, "type", cbor.Uint64(0x07))},
		{"a payload that is a list", withEntry(base, "payload", cbor.List([]cbor.Value{cbor.Uint64(1)}))},
		{"a created_at as text", withEntry(base, "created_at", cbor.Text("now"))},
		{"a type of 256", withEntry(base, "type", cbor.Uint64(256))},
		{"a created_at of 2^53", withEntry(base, "created_at", cbor.Uint64(maxProtocolInt))},
		{"an expires_at of 2^53", withEntry(base, "expires_at", cbor.Uint64(maxProtocolInt))},
		{"created_at replaced by a key no record has", withEntry(withoutEntry(base, "created_at"), "extra", cbor.Uint64(0))},
		{"expires_at replaced by a key no record has", withEntry(withoutEntry(base, "expires_at"), "extra", cbor.Uint64(0))},
	} {
		wantRefusal(t, c.name, verify(c.fields), ErrMalformed)
	}
}

// A tbs key that is not text counts toward the tbs's size, as map_size/1
// counts it, so it neither takes a missing field's place nor sits beside the
// fields. SignObject builds no such tbs, so these are signed by hand.
func TestATBSKeyThatIsNotTextIsMalformed(t *testing.T) {
	keys := keysFor(t)
	base := withEntry(nodeFields(t, keys.node, nowMs()), "alg", cbor.Text("ML-DSA-87"))
	verify := func(fields []cbor.MapEntry) error {
		_, err := Verify(signedTBSByHand(t, label, cbor.Encode(cbor.Map(fields)), keys.node), profile.PQPure, nowMs())
		return err
	}
	if err := verify(base); err != nil {
		t.Fatalf("the node record signed by hand: %v, want it verified", err)
	}
	notText := cbor.MapEntry{Key: cbor.Uint64(7), Val: cbor.Uint64(0)}
	for _, c := range []struct {
		name   string
		fields []cbor.MapEntry
	}{
		{"created_at replaced by a key that is not text", append(withoutEntry(base, "created_at"), notText)},
		{"expires_at replaced by a key that is not text", append(withoutEntry(base, "expires_at"), notText)},
		{"a key that is not text beside every field", append(slices.Clone(base), notText)},
	} {
		wantRefusal(t, c.name, verify(c.fields), ErrMalformed)
	}
}

// signedTBSByHand is the wire form of tbs signed under objectLabel by key, as
// identity signs an object: the signature covers the label, a zero byte, the
// SHA-384 of the key as carried, and tbs.
func signedTBSByHand(t *testing.T, objectLabel string, tbs []byte, key *identity.NodeKey) []byte {
	t.Helper()
	carried := key.PublicKey()
	keyHash := sha512.Sum384(carried)
	message := append(append(append([]byte(objectLabel), 0), keyHash[:]...), tbs...)
	signature := must[[]byte](t)(key.Sign(message))
	return cbor.Encode(identity.Object{Key: carried, TBS: tbs, Signature: signature}.Value())
}

func TestANodeRecordNamingAnotherNodeIsRefused(t *testing.T) {
	keys := keysFor(t)
	fields := recordFields(t, TypeNodeRecord, nodePayload(fill(9)), nowMs(), testHour)
	_, err := Verify(signedByHand(t, label, fields, keys.node), profile.PQPure, nowMs())
	wantRefusal(t, "a node record naming another node", err, ErrKeyIDMismatch)
}

// A verifier refuses a payload its type's rules do not allow as malformed, as
// macula_record's payload_ok/2 does, and in verify/3's order: a record living
// past its type's maximum is refused for that before its payload is read, and a
// payload is read before the signer it names.
func TestAPayloadItsTypeDoesNotAllowIsMalformed(t *testing.T) {
	keys := keysFor(t)
	nodeID := keys.node.KeyID()
	entriesOf := func(v cbor.Value) []cbor.MapEntry {
		entries, _ := v.AsMap()
		return entries
	}
	contentID := func(tag byte) []byte {
		id := make([]byte, 50)
		id[0], id[1] = tag, 0x55
		return id
	}
	advertisement := entriesOf(advertisementPayload(nodeID))
	unknownKey := withEntry(advertisement, "session_token_hint", cbor.Text("h"))
	announcement := entriesOf(contentAnnouncementPayload(nodeID))
	withdrawing := func(withdrawn Type, slot ...cbor.MapEntry) []cbor.MapEntry {
		return append([]cbor.MapEntry{uintEntry("withdrawn_type", uint64(withdrawn)),
			bytesEntry("withdrawn_version", make([]byte, 16)), textEntry("reason", "revoked")}, slot...)
	}
	advertisementTombstone := withdrawing(TypeProcedureAdvertisement, bytesEntry("realm_id", idBytes(0x11)), textEntry("procedure", "acme/echo_v1"))
	endorsementTombstone := withdrawing(TypeRealmMemberEndorsement, bytesEntry("realm_id", idBytes(0x11)), bytesEntry("member_node", idBytes(2)))
	for _, c := range []struct {
		name       string
		recordType Type
		payload    []cbor.MapEntry
		lifetimeMs int64
		want       error
	}{
		{"an advertisement", TypeProcedureAdvertisement, advertisement, 5 * testMinute, nil},
		{"an advertisement with an authorization map", TypeProcedureAdvertisement,
			withEntry(advertisement, "authorization", cbor.Map([]cbor.MapEntry{uintEntry("anything", 1)})), 5 * testMinute, nil},
		{"an authorization that is not a map", TypeProcedureAdvertisement,
			withEntry(advertisement, "authorization", cbor.List([]cbor.Value{cbor.Uint64(1)})), 5 * testMinute, ErrMalformed},
		{"a fifth key that is not authorization", TypeProcedureAdvertisement, unknownKey, 5 * testMinute, ErrMalformed},
		{"an advertisement without serving_station", TypeProcedureAdvertisement, withoutEntry(advertisement, "serving_station"), 5 * testMinute, ErrMalformed},
		{"a realm_id of 31 bytes", TypeProcedureAdvertisement, withEntry(advertisement, "realm_id", cbor.Bytes(make([]byte, 31))), 5 * testMinute, ErrMalformed},
		{"a procedure as bytes", TypeProcedureAdvertisement, withEntry(advertisement, "procedure", cbor.Bytes([]byte("acme/x"))), 5 * testMinute, ErrMalformed},
		{"a content announcement", TypeContentAnnouncement, announcement, testHour, nil},
		{"a content id with tag 1", TypeContentAnnouncement, withEntry(announcement, "mcid", cbor.Bytes(contentID(1))), testHour, ErrMalformed},
		{"a tombstone of an advertisement", TypeTombstone, advertisementTombstone, 10 * testMinute, nil},
		{"a tombstone with a detail", TypeTombstone, withEntry(advertisementTombstone, "detail", cbor.Text("to beam01")), 10 * testMinute, nil},
		{"a tombstone missing a slot field", TypeTombstone, withoutEntry(advertisementTombstone, "procedure"), 10 * testMinute, ErrMalformed},
		{"a tombstone with an extra slot field", TypeTombstone,
			withEntry(advertisementTombstone, "member_node", cbor.Bytes(idBytes(2))), 10 * testMinute, ErrMalformed},
		{"a reason macula does not define", TypeTombstone, withEntry(advertisementTombstone, "reason", cbor.Text("retired")), 10 * testMinute, ErrMalformed},
		{"a detail that is not text", TypeTombstone, withEntry(advertisementTombstone, "detail", cbor.Bytes([]byte("not text"))), 10 * testMinute, ErrMalformed},
		{"a withdrawn_version of 15 bytes", TypeTombstone,
			withEntry(advertisementTombstone, "withdrawn_version", cbor.Bytes(make([]byte, 15))), 10 * testMinute, ErrMalformed},
		{"a tombstone without withdrawn_version", TypeTombstone, withoutEntry(advertisementTombstone, "withdrawn_version"), 10 * testMinute, ErrMalformed},
		{"a tombstone withdrawing a tombstone", TypeTombstone, withdrawing(TypeTombstone), 10 * testMinute, ErrMalformed},
		{"a tombstone withdrawing a type no key signs", TypeTombstone, withdrawing(0x07), 10 * testMinute, ErrMalformed},
		{"a tombstone of a realm member endorsement", TypeTombstone, endorsementTombstone, testHour, nil},
		{"an endorsement tombstone without member_node", TypeTombstone, withoutEntry(endorsementTombstone, "member_node"), testHour, ErrMalformed},
		{"an endorsement tombstone with a member_node of 31 bytes", TypeTombstone,
			withEntry(endorsementTombstone, "member_node", cbor.Bytes(make([]byte, 31))), testHour, ErrMalformed},
		{"a signer that is not its key", TypeProcedureAdvertisement,
			withEntry(advertisement, "advertiser_node", cbor.Bytes(idBytes(9))), 5 * testMinute, ErrKeyIDMismatch},
		{"a payload fault and a lifetime fault", TypeProcedureAdvertisement, unknownKey, 5*testMinute + 1, ErrLifetimeTooLong},
		{"a payload fault and a signer that is not its key", TypeProcedureAdvertisement,
			withEntry(unknownKey, "advertiser_node", cbor.Bytes(idBytes(9))), 5 * testMinute, ErrMalformed},
	} {
		now := nowMs()
		fields := recordFields(t, c.recordType, cbor.Map(c.payload), now, c.lifetimeMs)
		_, err := Verify(signedByHand(t, label, fields, keys.node), profile.PQPure, now)
		if c.want == nil {
			if err != nil {
				t.Errorf("%s: %v, want it verified", c.name, err)
			}
			continue
		}
		wantRefusal(t, c.name, err, c.want)
	}
}

// A verifier's clock may be 5 minutes from a record's created_at and expires_at,
// the 5 minutes themselves included.
func TestTheClockToleranceIsFiveMinutes(t *testing.T) {
	keys := keysFor(t)
	r := signedNodeRecord(t, keys.node)
	wire := wireOf(t, r)
	created, expires := int64(r.CreatedAt), int64(r.ExpiresAt)
	for _, c := range []struct {
		name string
		at   int64
		want error
	}{
		{"4 minutes before its creation", created - 4*testMinute, nil},
		{"5 minutes before its creation", created - 5*testMinute, nil},
		{"5 minutes and 1 ms before its creation", created - 5*testMinute - 1, ErrNotYetValid},
		{"6 minutes before its creation", created - 6*testMinute, ErrNotYetValid},
		{"4 minutes after its expiry", expires + 4*testMinute, nil},
		{"5 minutes after its expiry", expires + 5*testMinute, nil},
		{"5 minutes and 1 ms after its expiry", expires + 5*testMinute + 1, ErrExpired},
		{"6 minutes after its expiry", expires + 6*testMinute, ErrExpired},
	} {
		_, err := Verify(wire, profile.PQPure, c.at)
		if c.want == nil {
			if err != nil {
				t.Errorf("verified %s: %v, want it verified", c.name, err)
			}
			continue
		}
		wantRefusal(t, "verified "+c.name, err, c.want)
	}
}

// A record is refused, or refused a signature, for its first fault in macula's
// order: a record created too far ahead is not yet valid before its lifetime is
// read, and one living too long is refused for that before its payload is read.
func TestARecordIsRefusedForItsFirstFaultInMaculasOrder(t *testing.T) {
	keys := keysFor(t)
	now := nowMs()
	tooLong := recordFields(t, TypeNodeRecord, nodePayload(fill(9)), now+6*testMinute, 49*testHour)
	_, err := Verify(signedByHand(t, label, tooLong, keys.node), profile.PQPure, now)
	wantRefusal(t, "a record 6 minutes ahead, living 49 hours, naming another node", err, ErrNotYetValid)
	_, err = Verify(signedByHand(t, label, withEntry(tooLong, "created_at", cbor.Uint64(uint64(now))), keys.node), profile.PQPure, now)
	wantRefusal(t, "a record living 49 hours, naming another node", err, ErrLifetimeTooLong)
	longForAnother := must[Record](t)(NewNodeRecord(fill(9), nil, 0, NodeRecordOptions{TTLMs: uint64(49 * testHour)}))
	_, err = Sign(longForAnother, keys.connect)
	wantRefusal(t, "sign with a CONNECT key a node record living 49 hours for another node", err, ErrKeyPurposeMismatch)
	_, err = Sign(longForAnother, keys.node)
	wantRefusal(t, "sign a node record living 49 hours for another node", err, ErrLifetimeTooLong)
}

//------------------------------------------------------------------
// Lifetimes and bounds
//------------------------------------------------------------------

// Every type an identity key signs signs at its maximum lifetime and is refused
// a millisecond past it: a node record and a content announcement 48 hours; a
// procedure advertisement and a station endpoint 5 minutes; a domain record 7
// days.
func TestEachIdentityTypeSignsWithinItsMaximumLifetime(t *testing.T) {
	keys := keysFor(t)
	nodeID := keys.node.KeyID()
	for _, c := range []struct {
		name       string
		recordType Type
		max        int64
		payload    cbor.Value
	}{
		{"a node record", TypeNodeRecord, 48 * testHour, nodePayload(nodeID)},
		{"a content announcement", TypeContentAnnouncement, 48 * testHour, contentAnnouncementPayload(nodeID)},
		{"a procedure advertisement", TypeProcedureAdvertisement, 5 * testMinute, advertisementPayload(nodeID)},
		{"a station endpoint", TypeStationEndpoint, 5 * testMinute, cbor.Map([]cbor.MapEntry{uintEntry("quic_port", 4433)})},
		{"a domain record", DomainTypeMin, 7 * testDay, cbor.Map(nil)},
	} {
		if _, err := Sign(must[Record](t)(unsigned(c.recordType, c.payload, uint64(c.max))), keys.node); err != nil {
			t.Errorf("sign %s living its maximum: %v, want it signed", c.name, err)
		}
		_, err := Sign(must[Record](t)(unsigned(c.recordType, c.payload, uint64(c.max+1))), keys.node)
		wantRefusal(t, "sign "+c.name+" living 1 ms past its maximum", err, ErrLifetimeTooLong)
	}
}

// A verifier accepts every type at its maximum lifetime and refuses it a
// millisecond past as lifetime_too_long, with a tombstone living its withdrawn
// type's maximum plus twice the clock tolerance.
func TestARecordLivingPastItsTypesMaximumIsRefused(t *testing.T) {
	keys := keysFor(t)
	nodeID := keys.node.KeyID()
	keyID := identity.KeyIDOf(keys.node.PublicKey(), profile.PQPure)
	realm := cbor.Map([]cbor.MapEntry{bytesEntry("realm_id", idBytes(0x11))})
	for _, c := range []struct {
		name       string
		recordType Type
		max        int64
		payload    cbor.Value
	}{
		{"a node record", TypeNodeRecord, 48 * testHour, nodePayload(nodeID)},
		{"a content announcement", TypeContentAnnouncement, 48 * testHour, contentAnnouncementPayload(nodeID)},
		{"a procedure advertisement", TypeProcedureAdvertisement, 5 * testMinute, advertisementPayload(nodeID)},
		{"a station endpoint", TypeStationEndpoint, 5 * testMinute, cbor.Map(nil)},
		{"realm stations", TypeRealmStations, 6 * testHour, realm},
		{"an org directory", TypeOrgDirectory, 6 * testHour, cbor.Map([]cbor.MapEntry{
			bytesEntry("realm_id", idBytes(0x11)), textEntry("org_name", "acme"), bytesEntry("org_key", idBytes(4))})},
		{"a procedure delegation", TypeProcedureDelegation, 6 * testHour, cbor.Map([]cbor.MapEntry{
			bytesEntry("org_key", keyID[:]), bytesEntry("advertiser", idBytes(8))})},
		{"a realm member endorsement", TypeRealmMemberEndorsement, 30 * testDay, cbor.Map([]cbor.MapEntry{
			bytesEntry("realm_id", idBytes(0x11)), bytesEntry("member_node", nodeID[:])})},
		{"a realm directory, which has no rule of its own", TypeRealmDirectory, 30 * testDay, realm},
		{"a domain record", DomainTypeMin, 7 * testDay, cbor.Map(nil)},
		{"a tombstone withdrawing a procedure advertisement", TypeTombstone, 15 * testMinute, cbor.Map([]cbor.MapEntry{
			uintEntry("withdrawn_type", uint64(TypeProcedureAdvertisement)), bytesEntry("withdrawn_version", make([]byte, 16)),
			textEntry("reason", "shutdown"), bytesEntry("realm_id", idBytes(0x11)), textEntry("procedure", "acme/echo_v1")})},
	} {
		now := nowMs()
		if _, err := Verify(signedByHand(t, label, recordFields(t, c.recordType, c.payload, now, c.max), keys.node), profile.PQPure, now); err != nil {
			t.Errorf("verify %s living its maximum: %v, want it verified", c.name, err)
		}
		_, err := Verify(signedByHand(t, label, recordFields(t, c.recordType, c.payload, now, c.max+1), keys.node), profile.PQPure, now)
		wantRefusal(t, "verify "+c.name+" living 1 ms past its maximum", err, ErrLifetimeTooLong)
	}
}

// A record whose expires_at is not after its created_at is refused as
// lifetime_reversed, at Sign and at Verify, even with created_at two minutes
// ahead, inside the clock tolerance, and a zero lifetime is reversed too.
func TestARecordThatExpiresNoLaterThanItIsCreatedIsRefused(t *testing.T) {
	keys := keysFor(t)
	created := nowMs() + 2*testMinute
	for _, c := range []struct {
		name     string
		lifetime int64
	}{
		{"expiring 1 ms before its creation", -1},
		{"expiring as it is created", 0},
	} {
		r := must[Record](t)(NewNodeRecord(keys.node.KeyID(), nil, 0, NodeRecordOptions{}))
		r.CreatedAt, r.ExpiresAt = uint64(created), uint64(created+c.lifetime)
		_, err := Sign(r, keys.node)
		wantRefusal(t, "sign a record "+c.name, err, ErrLifetimeReversed)
		fields := recordFields(t, TypeNodeRecord, r.Payload, created, c.lifetime)
		_, err = Verify(signedByHand(t, label, fields, keys.node), profile.PQPure, nowMs())
		wantRefusal(t, "verify a record "+c.name, err, ErrLifetimeReversed)
	}
}

// A builder given no ttl takes 48 hours, or its type's maximum when that is
// shorter: a procedure advertisement lives 5 minutes.
func TestABuilderGivenNoTTLTakes48HoursOrItsTypesShorterMaximum(t *testing.T) {
	keys := keysFor(t)
	for _, c := range []struct {
		name string
		r    Record
		want int64
	}{
		{"a node record", must[Record](t)(NewNodeRecord(keys.node.KeyID(), nil, 0, NodeRecordOptions{})), 48 * testHour},
		{"a procedure advertisement", must[Record](t)(unsigned(TypeProcedureAdvertisement, advertisementPayload(keys.node.KeyID()), 0)), 5 * testMinute},
		{"a domain record", must[Record](t)(Envelope(DomainTypeMin, cbor.Map(nil), nil, 0)), 48 * testHour},
	} {
		if lived := int64(c.r.ExpiresAt) - int64(c.r.CreatedAt); lived != c.want {
			t.Errorf("%s built without a ttl lives %d ms, want %d", c.name, lived, c.want)
		}
	}
}

// A payload is refused before anything is signed when its encoding is over 256
// KiB, or when it nests past the 63 levels a record's tbs leaves it under the
// decoding rule's 64.
func TestAPayloadPastTheRecordBoundsIsRefusedBeforeSigning(t *testing.T) {
	nested := func(depth int) cbor.Value {
		v := cbor.Uint64(1)
		for range depth {
			v = cbor.Map([]cbor.MapEntry{valueEntry("n", v)})
		}
		return v
	}
	if err := PayloadBounded(nested(63)); err != nil {
		t.Errorf("a payload nested 63 levels: %v, want it bounded", err)
	}
	wantRefusal(t, "a payload nested 64 levels", PayloadBounded(nested(64)), ErrMalformed)
	if err := PayloadBounded(cbor.Map([]cbor.MapEntry{bytesEntry("a", make([]byte, 200*kib))})); err != nil {
		t.Errorf("a payload of 200 KiB: %v, want it bounded", err)
	}
	wantRefusal(t, "a payload of 256 KiB", PayloadBounded(cbor.Map([]cbor.MapEntry{bytesEntry("a", make([]byte, 256*kib))})), ErrRecordTooLarge)
}

//------------------------------------------------------------------
// Key ids and domain records
//------------------------------------------------------------------

func TestADomainRecordIsNamedByTheKeyIDEvenForAnIdentityKey(t *testing.T) {
	keys := keysFor(t)
	r := must[Record](t)(Sign(must[Record](t)(Envelope(DomainTypeMin, cbor.Map([]cbor.MapEntry{uintEntry("fact", 1)}), nil, 0)), keys.node))
	keyID := identity.KeyIDOf(keys.node.PublicKey(), profile.PQPure)
	if r.KeyID != keyID || keyID == keys.node.KeyID() {
		t.Errorf("a domain record's key id %x, want the key id %x, which is not the node_id", r.KeyID, keyID)
	}
	if v := must[Record](t)(Verify(wireOf(t, r), profile.PQPure, nowMs())); v.KeyID != keyID {
		t.Errorf("the verified domain record's key id %x, want %x", v.KeyID, keyID)
	}
}

func TestADomainRecordCarriesItsSubjectInTBS(t *testing.T) {
	keys := keysFor(t)
	r := must[Record](t)(Sign(must[Record](t)(Envelope(DomainTypeMin+1, cbor.Map(nil), []byte("station-1"), 0)), keys.node))
	subject, _ := must[cbor.Value](t)(cbor.Decode(r.TBS)).Get("subject")
	if b, _ := subject.AsBytes(); string(b) != "station-1" {
		t.Errorf("the tbs's subject: %v, want station-1", subject)
	}
	if v := must[Record](t)(Verify(wireOf(t, r), profile.PQPure, nowMs())); string(v.Subject) != "station-1" {
		t.Errorf("the verified subject: %q, want station-1", v.Subject)
	}
}

func TestEnvelopeRefusesABuiltInType(t *testing.T) {
	_, err := Envelope(TypeNodeRecord, cbor.Map(nil), nil, 0)
	wantRefusal(t, "an envelope for a node record", err, ErrNotADomainType)
}

//------------------------------------------------------------------
// Refresh
//------------------------------------------------------------------

func TestRefreshKeepsTypePayloadAndLifetimeAndTakesALaterVersion(t *testing.T) {
	keys := keysFor(t)
	r := signedNodeRecord(t, keys.node)
	time.Sleep(2 * time.Millisecond)
	f := must[Record](t)(Refresh(r, keys.node))
	switch {
	case f.Type != r.Type || !sameValue(f.Payload, r.Payload):
		t.Errorf("the refreshed record %+v, want the type and payload of %+v", f, r)
	case f.ExpiresAt-f.CreatedAt != r.ExpiresAt-r.CreatedAt:
		t.Errorf("the refreshed record lives %d ms, want %d", f.ExpiresAt-f.CreatedAt, r.ExpiresAt-r.CreatedAt)
	case bytes.Compare(f.Version[:], r.Version[:]) <= 0:
		t.Errorf("the refreshed version %x is not after %x", f.Version, r.Version)
	}
	if _, err := Verify(wireOf(t, f), profile.PQPure, nowMs()); err != nil {
		t.Errorf("verify the refreshed record: %v", err)
	}
}

//------------------------------------------------------------------
// Node records
//------------------------------------------------------------------

func TestANodeRecordCarriesItsPayloadAndReadsBack(t *testing.T) {
	keys := keysFor(t)
	nodeID := keys.node.KeyID()
	station, lat, lng := fill(5), 50.8, 4.0
	opts := NodeRecordOptions{StationID: &station, Kind: "station", Hostname: "beam00", Lat: &lat, Lng: &lng,
		Peers: [][32]byte{fill(7), fill(6), fill(7)}, DisplayName: "Beam 00"}
	r := must[Record](t)(Sign(must[Record](t)(NewNodeRecord(nodeID, [][32]byte{fill(0x11)}, 3, opts)), keys.node))
	v := must[Record](t)(Verify(wireOf(t, r), profile.PQPure, nowMs()))
	latText, _ := v.Payload.Get("lat")
	lngText, _ := v.Payload.Get("lng")
	if a, _ := latText.AsText(); a != "50.8" {
		t.Errorf("lat travels as %v, want 50.8", latText)
	}
	if a, _ := lngText.AsText(); a != "4.0" {
		t.Errorf("lng travels as %v, want 4.0", lngText)
	}
	node := must[NodeRecord](t)(ReadNodeRecord(v))
	switch {
	case node.NodeID != nodeID || node.StationID != station:
		t.Errorf("node_id %x and station_id %x, want %x and %x", node.NodeID, node.StationID, nodeID, station)
	case !slices.Equal(node.Realms, [][32]byte{fill(0x11)}) || node.Capabilities != 3:
		t.Errorf("realms %x and capabilities %d, want one realm and 3", node.Realms, node.Capabilities)
	case node.Kind != "station" || node.Hostname != "beam00" || node.DisplayName != "Beam 00":
		t.Errorf("kind, hostname and display name: %q, %q, %q", node.Kind, node.Hostname, node.DisplayName)
	case node.Lat == nil || *node.Lat != 50.8 || node.Lng == nil || *node.Lng != 4:
		t.Errorf("lat and lng: %v, %v, want 50.8 and 4", node.Lat, node.Lng)
	case !slices.Equal(node.Peers, [][32]byte{fill(6), fill(7)}):
		t.Errorf("peers %x, want fill(6) and fill(7), sorted and once each", node.Peers)
	}
	_, err := ReadNodeRecord(Record{Type: TypeStationEndpoint, Payload: cbor.Map(nil)})
	wantRefusal(t, "read a station endpoint as a node record", err, ErrMalformed)
}

//------------------------------------------------------------------
// The binary's module
//------------------------------------------------------------------

// A binary built with GOFIPS140=v1.0.0 cannot check a record's signature, so
// Verify says so with identity.ErrPostQuantumUnavailable alone, not as a
// malformed record or a signature that does not verify. In any other binary the
// same record reaches the signature check and is refused as an invalid
// signature, and nothing else. Which way a run goes is read from crypto/fips140,
// not from the check under test. CI runs this test both ways.
func TestARecordVerifierSaysWhetherTheBinaryHasMLDSA(t *testing.T) {
	object := identity.Object{
		Key:       make([]byte, 2592),
		TBS:       cbor.Encode(cbor.Map(nil)),
		Signature: make([]byte, identity.SignatureSize(profile.PQPure)),
	}
	_, err := Verify(cbor.Encode(object.Value()), profile.PQPure, nowMs())
	want, notWant := identity.ErrObjectSignatureInvalid, identity.ErrPostQuantumUnavailable
	if strings.HasPrefix(fips140.Version(), "v1.0.") {
		want, notWant = identity.ErrPostQuantumUnavailable, identity.ErrObjectSignatureInvalid
	}
	if !errors.Is(err, want) || errors.Is(err, notWant) || errors.Is(err, ErrMalformed) {
		t.Errorf("Verify with the module %s: %v, want %v alone, not %v or a malformed record", fips140.Version(), err, want, notWant)
	}
}
