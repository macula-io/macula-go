package record

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
)

// ErrNotAContentID is a content id that is not 50 bytes of tag 2: the tag, a
// codec byte and a SHA-384 hash (D24).
var ErrNotAContentID = errors.New("record: not a tag 2 content id of 50 bytes")

// ContentAnnouncementOptions are a content announcement's fields beyond its
// announcer and content id, as macula_record's content_announcement/3 takes
// them (macula 12.6.0, D27): where it is served, which every announcement
// names, then the content's Name, left out when empty, and its Size and
// ChunkCount, left out when nil. TTLMs is 0 for the default, 48 hours.
type ContentAnnouncementOptions struct {
	// Where the content is served (D27): the realm the content procedure is
	// served in, the station the announcer is reachable through, and the
	// announcer's content procedure.
	RealmID        [32]byte
	ServingStation [32]byte
	Procedure      string
	Name           string
	Size           *uint64
	ChunkCount     *uint64
	TTLMs          uint64
}

// NewContentAnnouncement is an unsigned announcement, by the node
// announcerNode, which signs it, that it shares the content with the tag 2
// content id mcid, served on opts.Procedure in opts.RealmID and reachable
// through opts.ServingStation. A content id of another size or tag is
// ErrNotAContentID, and an empty procedure ErrMalformed.
func NewContentAnnouncement(announcerNode [32]byte, mcid []byte, opts ContentAnnouncementOptions) (Record, error) {
	if !isContentID(cbor.Bytes(mcid)) {
		return Record{}, fmt.Errorf("%w: %d bytes", ErrNotAContentID, len(mcid))
	}
	if opts.Procedure == "" {
		return Record{}, fmt.Errorf("%w: a content announcement names its content procedure", ErrMalformed)
	}
	entries := []cbor.MapEntry{
		bytesEntry("announcer_node", bytes.Clone(announcerNode[:])),
		bytesEntry("mcid", bytes.Clone(mcid)),
		bytesEntry("realm_id", bytes.Clone(opts.RealmID[:])),
		bytesEntry("serving_station", bytes.Clone(opts.ServingStation[:])),
		textEntry("procedure", opts.Procedure),
	}
	if opts.Name != "" {
		entries = append(entries, textEntry("name", opts.Name))
	}
	if opts.Size != nil {
		entries = append(entries, uintEntry("size", *opts.Size))
	}
	if opts.ChunkCount != nil {
		entries = append(entries, uintEntry("chunk_count", *opts.ChunkCount))
	}
	return unsigned(TypeContentAnnouncement, cbor.Map(entries), opts.TTLMs)
}

// ContentAnnouncement is a content announcement's payload, as macula_record's
// read_content_announcement/1 reads it. A field the payload leaves out, or
// carries as another kind, is zero or nil.
type ContentAnnouncement struct {
	AnnouncerNode  [32]byte
	MCID           []byte
	RealmID        [32]byte
	ServingStation [32]byte
	Procedure      string
	Name           string
	Size           *uint64
	ChunkCount     *uint64
}

// ReadContentAnnouncement reads a content announcement's payload. A record of
// another type is ErrMalformed.
func ReadContentAnnouncement(r Record) (ContentAnnouncement, error) {
	if r.Type != TypeContentAnnouncement {
		return ContentAnnouncement{}, fmt.Errorf("%w: a record of type %#02x is not a content announcement", ErrMalformed, uint8(r.Type))
	}
	mcid, _ := payloadField(r.Payload, "mcid").AsBytes()
	procedure, _ := payloadField(r.Payload, "procedure").AsText()
	name, _ := payloadField(r.Payload, "name").AsText()
	announcement := ContentAnnouncement{
		MCID:       bytes.Clone(mcid),
		Procedure:  procedure,
		Name:       name,
		Size:       optionalUint(r.Payload, "size"),
		ChunkCount: optionalUint(r.Payload, "chunk_count"),
	}
	readID(announcement.AnnouncerNode[:], payloadField(r.Payload, "announcer_node"))
	readID(announcement.RealmID[:], payloadField(r.Payload, "realm_id"))
	readID(announcement.ServingStation[:], payloadField(r.Payload, "serving_station"))
	return announcement, nil
}

// optionalUint is a non-negative integer field of payload, or nil when the
// payload leaves it out or carries another kind.
func optionalUint(payload cbor.Value, name string) *uint64 {
	value, present := payload.Get(name)
	n, isInt := value.AsInt64()
	if !present || !isInt || n < 0 {
		return nil
	}
	u := uint64(n)
	return &u
}
