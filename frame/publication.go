package frame

import (
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// The frame types that carry a publication, and a publication's time rules
// (D17): a verifier accepts a publication published up to 5 minutes ahead of its
// clock, until its ttl_ms, or 10 minutes without one, and 5 minutes more have
// passed; a ttl_ms is at most one hour.
const (
	frameTypePublish        = "publish"
	frameTypeEvent          = "event"
	frameTypePlumtreeGossip = "plumtree_gossip"

	publicationToleranceMs  = 5 * 60_000
	publicationDefaultTTLMs = 10 * 60_000
	publicationMaxTTLMs     = 60 * 60_000
)

// The refusals of a publication for its time. A verifier returns either as a
// *FreshnessError, which says by how many milliseconds.
var (
	// ErrNotYetValid is a publication published more than 5 minutes ahead of
	// the verifier's clock.
	ErrNotYetValid = errors.New("frame: a publication not yet valid")
	// ErrExpired is a publication past its expiry.
	ErrExpired = errors.New("frame: a publication past its expiry")
)

// FreshnessError is a publication refused for its time, as macula_frame's
// {not_yet_valid, AheadMs} and {expired, PastMs} name it: Err is ErrNotYetValid,
// with Ms how far past the 5 minutes ahead it may be, or ErrExpired, with Ms how
// far past its expiry.
type FreshnessError struct {
	Err error
	Ms  int64
}

func (e *FreshnessError) Error() string { return fmt.Sprintf("%v, by %d ms", e.Err, e.Ms) }

func (e *FreshnessError) Unwrap() error { return e.Err }

// PublicationSpec is a publication as its publisher gives it to SignPublish: a
// realm, a topic, the publisher's own seq, when it was published in Unix
// milliseconds, a payload, and a ttl_ms, nil for the 10 minutes a publication
// lives without one.
type PublicationSpec struct {
	Realm       [32]byte
	Topic       string
	Seq         uint64
	PublishedAt uint64
	Payload     cbor.Value
	TTLMs       *uint64
}

// VerifiedPublication is a publication that verified: its fields, the
// publisher's key as carried, PublicationHash, the SHA-384 of its tbs, which
// deduplication and Plumtree bookkeeping key on, and ExpiresAt, the last moment
// a verifier accepts it: PublishedAt plus its ttl_ms, or 10 minutes without one,
// plus 5 minutes. A subscriber keeps a delivered publication's hash until then.
// TTLMs is nil when the publication carries none.
type VerifiedPublication struct {
	Publisher       [32]byte
	Realm           [32]byte
	Topic           string
	Seq             uint64
	PublishedAt     uint64
	TTLMs           *uint64
	Payload         cbor.Value
	Key             []byte
	PublicationHash [48]byte
	ExpiresAt       uint64
}

// SignPublish signs a publication with the publisher's identity key as a
// PUBLISH, as macula_frame's publish/2 builds one: publisher is the key's key
// id, and publication is a signed object under MACULA-PQ-PUBLICATION-V1 whose
// tbs holds no frame_type, since the same bytes ride in every EVENT and GOSSIP
// made from it. It checks in the order of publish/2 and refuses a key that is
// not an identity key (ErrUnsignable); a seq or published_at of 2^53 or more
// (ErrOutOfRange), which publish/2's head refuses with the key; a topic a
// station refuses, with CheckPublication, over 512 bytes (ErrTextTooLong) or not
// UTF-8 (ErrInvalidText); a payload the wire cannot carry (CheckPayload's
// refusal); and a ttl_ms over one hour (ErrOutOfRange).
func SignPublish(spec PublicationSpec, key *identity.NodeKey) (cbor.Value, error) {
	if err := publicationBuildable(spec, key); err != nil {
		return cbor.Value{}, err
	}
	publisher := key.KeyID()
	fields := []cbor.MapEntry{
		bytesEntry("publisher", publisher[:]),
		bytesEntry("realm", spec.Realm[:]),
		textEntry("topic", spec.Topic),
		uintEntry("seq", spec.Seq),
		uintEntry("published_at", spec.PublishedAt),
		valueEntry("payload", spec.Payload),
	}
	if spec.TTLMs != nil {
		fields = append(fields, uintEntry("ttl_ms", *spec.TTLMs))
	}
	publication, err := identity.SignObject(publicationLabel, fields, key)
	if err != nil {
		return cbor.Value{}, err
	}
	return cbor.Map([]cbor.MapEntry{
		uintEntry("version", ProtocolVersion),
		textEntry("frame_type", frameTypePublish),
		valueEntry("publication", publication.Value()),
	}), nil
}

// publicationBuildable runs a publication build's checks in the order of
// macula's publish/2: the key and the ranges of seq and published_at, which its
// head refuses, then the realm and topic, then the payload, then the range of
// ttl_ms, which optional_ttl/2 refuses last.
func publicationBuildable(spec PublicationSpec, key *identity.NodeKey) error {
	if err := identitySigner(key); err != nil {
		return err
	}
	if spec.Seq >= maxProtocolInt || spec.PublishedAt >= maxProtocolInt {
		return fmt.Errorf("%w: a seq or published_at of 2^53 or more", ErrOutOfRange)
	}
	if err := boundedText("topic", spec.Topic, maxTopicBytes); err != nil {
		return err
	}
	if err := CheckPayload(spec.Payload); err != nil {
		return err
	}
	if spec.TTLMs != nil && *spec.TTLMs > publicationMaxTTLMs {
		return fmt.Errorf("%w: a ttl_ms of %d, over one hour", ErrOutOfRange, *spec.TTLMs)
	}
	return nil
}

// maxTopicBytes is the bound of a topic, UTF-8 bytes on the wire, as a
// station's receive rule reads a SUBSCRIBE's and an UNSUBSCRIBE's and its
// publication table reads a publication's.
const maxTopicBytes = 512

// publicationFrameFields are the fields each frame that carries a publication
// has besides version, frame_type and publication: an EVENT's delivered_via and
// a GOSSIP's round.
var publicationFrameFields = map[string]map[string]fieldRule{
	frameTypePublish:        {},
	frameTypeEvent:          {"delivered_via": textIn("plumtree", "direct")},
	frameTypePlumtreeGossip: {"round": protocolUint},
}

// publicationTable is the fields a publication's tbs may hold, each with its
// rule, as macula_frame's publication_table/0 reads them.
var publicationTable = map[string]fieldRule{
	"alg":          anyValue,
	"publisher":    bytesOf(32),
	"realm":        bytesOf(32),
	"topic":        textWithin(maxTopicBytes),
	"seq":          protocolUint,
	"published_at": protocolUint,
	"ttl_ms":       protocolUint,
	"payload":      anyValue,
}

// VerifyPublication verifies the publication a received PUBLISH, EVENT or
// GOSSIP carries, under the connection's profile p and the verifier's clock
// nowMs in Unix milliseconds, as macula_frame's verify_publication/3 does: the
// frame is exactly version, frame_type and publication, with an EVENT's
// delivered_via or a GOSSIP's round, of the protocol's version; then the
// publication's signature and fields, a ttl_ms of at most one hour, publisher as
// the key id of its key, a published_at no more than 5 minutes ahead of nowMs,
// and nowMs no later than its ExpiresAt. The origin station checks this before
// fan-out, and every subscriber before delivery. It refuses with
// ErrMalformedFrame, identity.ErrObjectSignatureInvalid, ErrKeyIDMismatch, or a
// *FreshnessError wrapping ErrNotYetValid or ErrExpired, and in a binary without
// ML-DSA with identity.ErrPostQuantumUnavailable.
func VerifyPublication(v cbor.Value, p profile.Profile, nowMs int64) (VerifiedPublication, error) {
	frameTypeValue, _ := v.Get("frame_type")
	frameType := textOf(frameTypeValue)
	extra, carriesPublication := publicationFrameFields[frameType]
	if !carriesPublication {
		return VerifiedPublication{}, ErrMalformedFrame
	}
	_, object, ok := receivedFrame(v, "publication", carriedObject, extra, frameType)
	for name := range extra {
		if _, has := v.Get(name); !has {
			ok = false
		}
	}
	if !ok {
		return VerifiedPublication{}, ErrMalformedFrame
	}
	verified, err := identity.VerifyObject(publicationLabel, object, p)
	if err != nil {
		return VerifiedPublication{}, objectRefusal(err)
	}
	fields, ok := readFields(verified.Fields, publicationTable)
	if !ok || !hasFields(fields, "publisher", "realm", "topic", "seq", "published_at", "payload") {
		return VerifiedPublication{}, ErrMalformedFrame
	}
	publication := verifiedPublication(verified, fields)
	// validFrom is the first moment a verifier accepts the publication: 5
	// minutes before it was published.
	validFrom := int64(publication.PublishedAt) - publicationToleranceMs
	switch {
	case publication.TTLMs != nil && *publication.TTLMs > publicationMaxTTLMs:
		return VerifiedPublication{}, ErrMalformedFrame
	case publication.Publisher != identity.NodeIDOf(verified.Key, p):
		return VerifiedPublication{}, ErrKeyIDMismatch
	case validFrom > nowMs:
		return VerifiedPublication{}, &FreshnessError{Err: ErrNotYetValid, Ms: validFrom - nowMs}
	case nowMs > int64(publication.ExpiresAt):
		return VerifiedPublication{}, &FreshnessError{Err: ErrExpired, Ms: nowMs - int64(publication.ExpiresAt)}
	}
	return publication, nil
}

// verifiedPublication is a verified publication's fields, which its table read,
// with its hash and expiry.
func verifiedPublication(verified identity.VerifiedObject, fields map[string]cbor.Value) VerifiedPublication {
	seq, _ := fields["seq"].AsInt64()
	publishedAt, _ := fields["published_at"].AsInt64()
	publication := VerifiedPublication{
		Topic:           textOf(fields["topic"]),
		Seq:             uint64(seq),
		PublishedAt:     uint64(publishedAt),
		Payload:         fields["payload"],
		Key:             verified.Key,
		PublicationHash: sha512.Sum384(verified.TBS),
	}
	fixedBytes(publication.Publisher[:], fields["publisher"])
	fixedBytes(publication.Realm[:], fields["realm"])
	ttl := uint64(publicationDefaultTTLMs)
	if value, has := fields["ttl_ms"]; has {
		n, _ := value.AsInt64()
		ttl = uint64(n)
		publication.TTLMs = &ttl
	}
	publication.ExpiresAt = publication.PublishedAt + ttl + publicationToleranceMs
	return publication
}
