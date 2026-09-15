package frame

import (
	"crypto/sha512"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_frame_publication_tests at merge-11.0.0
// 335b114f (DESIGN_PQ_SIGNED_FRAMES_AND_RECORDS.md: Publications; D17). PUBLISH
// is {version, frame_type, publication}, EVENT adds delivered_via, and Plumtree
// GOSSIP adds its round. publication is {key, tbs, signature} under
// MACULA-PQ-PUBLICATION-V1, signed by the publisher, and the same bytes ride in
// every frame made from it, so its tbs holds no frame_type. Two of macula's cases
// are not here: IHAVE and GRAFT naming a publication by its hash belong to the
// Plumtree frames a station builds, and the removal of the old publisher
// signature to the cutover, which removes the classical frames.

const (
	testNow    = int64(1789000000000)
	testMinute = int64(60_000)
)

// publishSpecAt is the publication the tests sign, published at publishedAt.
func publishSpecAt(publishedAt int64) PublicationSpec {
	return PublicationSpec{
		Realm:       testRealm(),
		Topic:       "weather.tienen",
		Seq:         7,
		PublishedAt: uint64(publishedAt),
		Payload:     cbor.Map([]cbor.MapEntry{uintEntry("celsius", 21)}),
	}
}

func withTTL(spec PublicationSpec, ttlMs uint64) PublicationSpec {
	spec.TTLMs = &ttlMs
	return spec
}

func publishedFrame(t *testing.T, spec PublicationSpec, key *identity.NodeKey) cbor.Value {
	t.Helper()
	return onWire(t, must[cbor.Value](t)(SignPublish(spec, key)))
}

// publicationTBS is the fields of a publication as its signer puts them in tbs;
// signing adds alg.
func publicationTBS(key *identity.NodeKey, publishedAt int64) []cbor.MapEntry {
	publisher, realm := key.KeyID(), testRealm()
	return []cbor.MapEntry{
		bytesEntry("publisher", publisher[:]),
		bytesEntry("realm", realm[:]),
		textEntry("topic", "weather.tienen"),
		uintEntry("seq", 7),
		uintEntry("published_at", uint64(publishedAt)),
		uintEntry("payload", 1),
	}
}

func verifyCraftedPublication(t *testing.T, tbs []cbor.MapEntry, key *identity.NodeKey) (VerifiedPublication, error) {
	t.Helper()
	return VerifyPublication(onWire(t, crafted(frameTypePublish, "publication", signedWith(t, publicationLabel, tbs, key))), profile.PQPure, testNow)
}

// carrying is a frame of frameType carrying the publication a PUBLISH carries,
// with the field name set to value when name is not empty.
func carrying(t *testing.T, publish cbor.Value, frameType, name string, value cbor.Value) cbor.Value {
	t.Helper()
	publication, _ := publish.Get("publication")
	v := crafted(frameType, "publication", publication)
	if name != "" {
		v = frameWith(v, name, value)
	}
	return onWire(t, v)
}

// wantFreshness checks that err is a *FreshnessError for want, by ms.
func wantFreshness(t *testing.T, name string, err, want error, ms int64) {
	t.Helper()
	var freshness *FreshnessError
	if !errors.As(err, &freshness) || freshness.Err != want || freshness.Ms != ms {
		t.Errorf("%s: %v, want %v by %d ms", name, err, want, ms)
	}
}

func verifyAt(t *testing.T, v cbor.Value, nowMs int64) (VerifiedPublication, error) {
	t.Helper()
	return VerifyPublication(v, profile.PQPure, nowMs)
}

func TestAPublishCarriesASignedPublicationThatVerifies(t *testing.T) {
	keys := requestKeysFor(t)
	publish := publishedFrame(t, publishSpecAt(testNow), keys.caller)
	if got, want := sortedKeys(publish), []string{"frame_type", "publication", "version"}; !slices.Equal(got, want) {
		t.Errorf("a PUBLISH's fields: %v, want %v", got, want)
	}
	publicationValue, _ := publish.Get("publication")
	if got, want := sortedKeys(publicationValue), []string{"key", "signature", "tbs"}; !slices.Equal(got, want) {
		t.Errorf("its publication's fields: %v, want %v", got, want)
	}
	object := objectOf(t, publish, "publication")
	verified, err := verifyAt(t, publish, testNow)
	if err != nil {
		t.Fatalf("VerifyPublication: %v", err)
	}
	wantPayload := cbor.Map([]cbor.MapEntry{uintEntry("celsius", 21)})
	switch {
	case verified.Realm != testRealm() || verified.Topic != "weather.tienen" || verified.Seq != 7 || verified.PublishedAt != uint64(testNow):
		t.Errorf("verified fields: %+v, want the realm, topic, seq and published_at signed", verified)
	case verified.Publisher != keys.caller.KeyID():
		t.Errorf("publisher: %x, want the key id of the key", verified.Publisher)
	case !slices.Equal(verified.Key, object.Key):
		t.Error("the verified key is not the key the publication carries")
	case verified.PublicationHash != sha512.Sum384(object.TBS):
		t.Error("publication_hash is not the SHA-384 of the tbs")
	case !sameValue(verified.Payload, wantPayload):
		t.Errorf("payload: %v, want %v", verified.Payload, wantPayload)
	case verified.TTLMs != nil:
		t.Errorf("ttl_ms: %d, want none", *verified.TTLMs)
	}
}

func TestAnEventCarriesTheSamePublicationBytes(t *testing.T) {
	keys := requestKeysFor(t)
	publish := publishedFrame(t, publishSpecAt(testNow), keys.caller)
	event := carrying(t, publish, frameTypeEvent, "delivered_via", cbor.Text("plumtree"))
	if got, want := sortedKeys(event), []string{"delivered_via", "frame_type", "publication", "version"}; !slices.Equal(got, want) {
		t.Errorf("an EVENT's fields: %v, want %v", got, want)
	}
	object := objectOf(t, publish, "publication")
	fromPublish := must[VerifiedPublication](t)(verifyAt(t, publish, testNow))
	fromEvent := must[VerifiedPublication](t)(verifyAt(t, event, testNow))
	if fromPublish.PublicationHash != sha512.Sum384(object.TBS) || fromPublish.Publisher != keys.caller.KeyID() {
		t.Fatalf("the PUBLISH verified as %+v, want its publication's hash and publisher", fromPublish)
	}
	if fromEvent.PublicationHash != fromPublish.PublicationHash || fromEvent.Publisher != fromPublish.Publisher || fromEvent.ExpiresAt != fromPublish.ExpiresAt {
		t.Errorf("the EVENT verified as %+v, want the PUBLISH's %+v", fromEvent, fromPublish)
	}
}

func TestAGossipCarriesTheSamePublicationBytesAndItsRound(t *testing.T) {
	keys := requestKeysFor(t)
	gossip := carrying(t, publishedFrame(t, publishSpecAt(testNow), keys.caller), frameTypePlumtreeGossip, "round", cbor.Uint64(2))
	if got, want := sortedKeys(gossip), []string{"frame_type", "publication", "round", "version"}; !slices.Equal(got, want) {
		t.Errorf("a GOSSIP's fields: %v, want %v", got, want)
	}
	if verified, err := verifyAt(t, gossip, testNow); err != nil || verified.Seq != 7 {
		t.Errorf("verify the GOSSIP: (%+v, %v), want seq 7", verified, err)
	}
}

func TestThePublicationTBSHoldsNoFrameType(t *testing.T) {
	keys := requestKeysFor(t)
	object := objectOf(t, publishedFrame(t, publishSpecAt(testNow), keys.caller), "publication")
	fields := must[cbor.Value](t)(cbor.Decode(object.TBS))
	alg, _ := fields.Get("alg")
	if _, has := fields.Get("frame_type"); has {
		t.Error("the publication's tbs holds frame_type")
	}
	if _, has := fields.Get("publisher"); !has || textOf(alg) != "ML-DSA-87" {
		t.Errorf("the publication's tbs: %v, want publisher and alg ML-DSA-87", fields)
	}
}

func TestAPublisherThatIsNotTheKeyIDOfItsKeyIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	other := keys.other.KeyID()
	_, err := verifyCraftedPublication(t, withEntry(publicationTBS(keys.caller, testNow), "publisher", cbor.Bytes(other[:])), keys.caller)
	wantStreamRefusal(t, "a publisher that is not the key id of its key", err, ErrKeyIDMismatch)
}

func TestATamperedPublicationIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	publish := must[cbor.Value](t)(SignPublish(publishSpecAt(testNow), keys.caller))
	_, err := verifyAt(t, onWire(t, withFlippedTBS(t, publish, "publication")), testNow)
	wantStreamRefusal(t, "a publication with a changed tbs", err, identity.ErrObjectSignatureInvalid)
}

func TestAPublicationUnderTheOtherProfileIsMalformed(t *testing.T) {
	keys := requestKeysFor(t)
	_, err := VerifyPublication(publishedFrame(t, publishSpecAt(testNow), keys.caller), profile.PQHybrid, testNow)
	wantStreamRefusal(t, "a pq_pure publication under pq_hybrid", err, ErrMalformedFrame)
}

func TestPublicationFieldsTheDesignDoesNotAllowAreMalformed(t *testing.T) {
	keys := requestKeysFor(t)
	base := publicationTBS(keys.caller, testNow)
	if _, err := verifyCraftedPublication(t, base, keys.caller); err != nil {
		t.Fatalf("the crafted publication: %v, want it verified", err)
	}
	if verified, err := verifyCraftedPublication(t, withEntry(base, "ttl_ms", cbor.Uint64(60_000)), keys.caller); err != nil ||
		verified.TTLMs == nil || *verified.TTLMs != 60_000 {
		t.Errorf("a publication with a ttl_ms of 60000: (%+v, %v), want it verified with that ttl_ms", verified, err)
	}
	realm := testRealm()
	for _, c := range []struct {
		name string
		tbs  []cbor.MapEntry
	}{
		{"a field no publication has", withEntry(base, "extra", cbor.Uint64(1))},
		{"a frame_type in the tbs", withEntry(base, "frame_type", cbor.Text(frameTypePublish))},
		{"no payload", withoutEntry(base, "payload")},
		{"a topic as bytes", withEntry(base, "topic", cbor.Bytes([]byte("weather.tienen")))},
		{"a 31-byte realm", withEntry(base, "realm", cbor.Bytes(realm[:31]))},
		{"a seq of 2^53", withEntry(base, "seq", cbor.Uint64(maxProtocolInt))},
		{"a published_at as text", withEntry(base, "published_at", cbor.Text("now"))},
		{"a ttl_ms of -1", withEntry(base, "ttl_ms", cbor.Int(-1))},
	} {
		_, err := verifyCraftedPublication(t, c.tbs, keys.caller)
		wantStreamRefusal(t, c.name, err, ErrMalformedFrame)
	}
}

// A topic is text of at most 512 bytes: the builder refuses a longer one and one
// that is not UTF-8, and a verifier refuses a publication whose topic is longer.
func TestAPublicationTopicIsTextOfAtMost512Bytes(t *testing.T) {
	keys := requestKeysFor(t)
	long := strings.Repeat("t", 512)
	withTopic := func(topic string) PublicationSpec {
		spec := publishSpecAt(testNow)
		spec.Topic = topic
		return spec
	}
	if verified, err := verifyAt(t, publishedFrame(t, withTopic(long), keys.caller), testNow); err != nil || verified.Topic != long {
		t.Errorf("a 512-byte topic: (%+v, %v), want it verified", verified, err)
	}
	_, err := SignPublish(withTopic(long+"t"), keys.caller)
	wantRefusal(t, "build with a 513-byte topic", err, ErrTextTooLong)
	_, err = SignPublish(withTopic("\xff\xfe"), keys.caller)
	wantRefusal(t, "build with a topic that is not UTF-8", err, ErrInvalidText)
	_, err = verifyCraftedPublication(t, withEntry(publicationTBS(keys.caller, testNow), "topic", cbor.Text(long+"t")), keys.caller)
	wantStreamRefusal(t, "a publication with a 513-byte topic", err, ErrMalformedFrame)
}

// A publication published up to 5 minutes ahead of the verifier's clock
// verifies, the 5 minutes themselves included, and one further ahead is refused
// by how far past them it is.
func TestAPublicationMoreThan5MinutesAheadIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	verify := func(publishedAt int64) error {
		_, err := verifyAt(t, publishedFrame(t, publishSpecAt(publishedAt), keys.caller), testNow)
		return err
	}
	for _, ahead := range []int64{4 * testMinute, 5 * testMinute} {
		if err := verify(testNow + ahead); err != nil {
			t.Errorf("a publication %d ms ahead: %v, want it verified", ahead, err)
		}
	}
	wantFreshness(t, "5 minutes and 1 ms ahead", verify(testNow+5*testMinute+1), ErrNotYetValid, 1)
	wantFreshness(t, "6 minutes ahead", verify(testNow+6*testMinute), ErrNotYetValid, testMinute)
}

func TestAPublicationPastItsTTLPlus5MinutesIsRefused(t *testing.T) {
	keys := requestKeysFor(t)
	verify := func(publishedAt int64) error {
		_, err := verifyAt(t, publishedFrame(t, withTTL(publishSpecAt(publishedAt), uint64(testMinute)), keys.caller), testNow)
		return err
	}
	if err := verify(testNow - 5*testMinute); err != nil {
		t.Errorf("a 1-minute publication published 5 minutes ago: %v, want it verified", err)
	}
	wantFreshness(t, "a 1-minute publication published 7 minutes ago", verify(testNow-7*testMinute), ErrExpired, testMinute)
}

func TestWithoutTTLAPublicationLives10MinutesPlus5(t *testing.T) {
	keys := requestKeysFor(t)
	verify := func(publishedAt int64) error {
		_, err := verifyAt(t, publishedFrame(t, publishSpecAt(publishedAt), keys.caller), testNow)
		return err
	}
	if err := verify(testNow - 14*testMinute); err != nil {
		t.Errorf("a publication published 14 minutes ago: %v, want it verified", err)
	}
	wantFreshness(t, "a publication published 16 minutes ago", verify(testNow-16*testMinute), ErrExpired, testMinute)
}

// ExpiresAt is the last moment a verifier accepts the publication: a subscriber
// keeps a delivered publication's hash until then, and refuses any copy that
// arrives later.
func TestAVerifiedPublicationCarriesItsExpiryTheMomentVerifiersRefuseIt(t *testing.T) {
	keys := requestKeysFor(t)
	publish := publishedFrame(t, withTTL(publishSpecAt(testNow), uint64(2*testMinute)), keys.caller)
	if verified := must[VerifiedPublication](t)(verifyAt(t, publish, testNow)); verified.ExpiresAt != uint64(testNow+7*testMinute) {
		t.Errorf("ExpiresAt: %d, want %d", verified.ExpiresAt, testNow+7*testMinute)
	}
	if _, err := verifyAt(t, publish, testNow+7*testMinute); err != nil {
		t.Errorf("verified at its expiry: %v, want it verified", err)
	}
	_, err := verifyAt(t, publish, testNow+7*testMinute+1)
	wantFreshness(t, "verified 1 ms after its expiry", err, ErrExpired, 1)
}

func TestWithoutTTLTheExpiryIs15MinutesAfterPublishing(t *testing.T) {
	keys := requestKeysFor(t)
	publish := publishedFrame(t, publishSpecAt(testNow), keys.caller)
	if verified := must[VerifiedPublication](t)(verifyAt(t, publish, testNow)); verified.ExpiresAt != uint64(testNow+15*testMinute) {
		t.Errorf("ExpiresAt: %d, want %d", verified.ExpiresAt, testNow+15*testMinute)
	}
	if _, err := verifyAt(t, publish, testNow+15*testMinute); err != nil {
		t.Errorf("verified at its expiry: %v, want it verified", err)
	}
	_, err := verifyAt(t, publish, testNow+15*testMinute+1)
	wantFreshness(t, "verified 1 ms after its expiry", err, ErrExpired, 1)
}

// ttl_ms is at most one hour: a publication carrying more is malformed, and
// SignPublish refuses to sign one.
func TestATTLOverAnHourIsMalformed(t *testing.T) {
	keys := requestKeysFor(t)
	base := publicationTBS(keys.caller, testNow)
	if verified, err := verifyCraftedPublication(t, withEntry(base, "ttl_ms", cbor.Uint64(3_600_000)), keys.caller); err != nil ||
		verified.TTLMs == nil || *verified.TTLMs != 3_600_000 {
		t.Errorf("a ttl_ms of one hour: (%+v, %v), want it verified", verified, err)
	}
	_, err := verifyCraftedPublication(t, withEntry(base, "ttl_ms", cbor.Uint64(3_600_001)), keys.caller)
	wantStreamRefusal(t, "a ttl_ms of one hour and 1 ms", err, ErrMalformedFrame)
	_, err = SignPublish(withTTL(publishSpecAt(testNow), 3_600_001), keys.caller)
	wantRefusal(t, "build with a ttl_ms of one hour and 1 ms", err, ErrOutOfRange)
}

// A frame around a publication is read as a received frame is decoded before its
// publication is verified: exactly version, frame_type and publication, with an
// EVENT's delivered_via and a GOSSIP's round, of the protocol's version.
func TestAFrameAroundAPublicationIsReadAsAReceivedFrameIs(t *testing.T) {
	keys := requestKeysFor(t)
	publish := must[cbor.Value](t)(SignPublish(publishSpecAt(testNow), keys.caller))
	event := carrying(t, publish, frameTypeEvent, "delivered_via", cbor.Text("direct"))
	gossip := carrying(t, publish, frameTypePlumtreeGossip, "round", cbor.Uint64(maxProtocolInt-1))
	for name, v := range map[string]cbor.Value{"an EVENT delivered direct": event, "a GOSSIP of round 2^53 - 1": gossip} {
		if _, err := verifyAt(t, v, testNow); err != nil {
			t.Errorf("%s: %v, want it verified", name, err)
		}
	}
	for _, c := range []struct {
		name  string
		frame cbor.Value
	}{
		{"a PUBLISH of another version", frameWith(publish, "version", cbor.Uint64(ProtocolVersion+1))},
		{"a PUBLISH without its version", frameWithout(publish, "version")},
		{"a PUBLISH with a delivered_via", frameWith(publish, "delivered_via", cbor.Text("direct"))},
		{"an EVENT without its delivered_via", frameWithout(event, "delivered_via")},
		{"an EVENT delivered another way", frameWith(event, "delivered_via", cbor.Text("relay"))},
		{"an EVENT with a round", frameWith(event, "round", cbor.Uint64(1))},
		{"a GOSSIP without its round", frameWithout(gossip, "round")},
		{"a GOSSIP of round 2^53", frameWith(gossip, "round", cbor.Uint64(maxProtocolInt))},
		{"a frame type that carries no publication", frameWith(publish, "frame_type", cbor.Text(frameTypeCall))},
	} {
		_, err := verifyAt(t, onWire(t, c.frame), testNow)
		wantStreamRefusal(t, c.name, err, ErrMalformedFrame)
	}
}

// A publication build with more than one fault is refused for the first in
// macula's order: the key, then the topic, then the payload, then a field's
// range.
func TestAPublicationBuildIsRefusedForItsFirstFaultInMaculasOrder(t *testing.T) {
	keys := requestKeysFor(t)
	connectKey := must[*identity.NodeKey](t)(identity.GenerateKey(identity.PurposeConnect, profile.PQPure))
	unsendable := cbor.Map([]cbor.MapEntry{textEntry("unsendable", "\xff")})
	spec := publishSpecAt(testNow)
	spec.Topic, spec.Payload, spec.Seq = strings.Repeat("t", 513), unsendable, maxProtocolInt

	_, err := SignPublish(spec, connectKey)
	wantRefusal(t, "a CONNECT key, a 513-byte topic, an unsendable payload and a seq of 2^53", err, ErrUnsignable)
	_, err = SignPublish(spec, keys.caller)
	wantRefusal(t, "a 513-byte topic, an unsendable payload and a seq of 2^53", err, ErrTextTooLong)
	spec.Topic = "weather.tienen"
	_, err = SignPublish(spec, keys.caller)
	if want := CheckPayload(unsendable); err == nil || err.Error() != want.Error() {
		t.Errorf("an unsendable payload and a seq of 2^53: %v, want %v", err, want)
	}
	spec.Payload = cbor.Uint64(1)
	_, err = SignPublish(spec, keys.caller)
	wantRefusal(t, "a seq of 2^53", err, ErrOutOfRange)
	spec.Seq, spec.PublishedAt = 7, maxProtocolInt
	_, err = SignPublish(spec, keys.caller)
	wantRefusal(t, "a published_at of 2^53", err, ErrOutOfRange)
}
