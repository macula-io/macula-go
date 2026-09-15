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

// ContentAnnouncementOptions are a content announcement's optional fields, as
// macula_record's content_announcement/4 takes them: the content's Name, left
// out when empty, and its Size and ChunkCount, left out when nil. TTLMs is 0
// for the default, 48 hours.
type ContentAnnouncementOptions struct {
	Name       string
	Size       *uint64
	ChunkCount *uint64
	TTLMs      uint64
}

// NewContentAnnouncement is an unsigned announcement, by the node
// announcerNode, which signs it, that it shares the content with the tag 2
// content id mcid at endpoint. A content id of another size or tag is
// ErrNotAContentID.
func NewContentAnnouncement(announcerNode [32]byte, mcid []byte, endpoint string, opts ContentAnnouncementOptions) (Record, error) {
	if !isContentID(cbor.Bytes(mcid)) {
		return Record{}, fmt.Errorf("%w: %d bytes", ErrNotAContentID, len(mcid))
	}
	entries := []cbor.MapEntry{
		bytesEntry("announcer_node", bytes.Clone(announcerNode[:])),
		bytesEntry("mcid", bytes.Clone(mcid)),
		textEntry("endpoint", endpoint),
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
	AnnouncerNode [32]byte
	MCID          []byte
	Endpoint      string
	Name          string
	Size          *uint64
	ChunkCount    *uint64
}

// ReadContentAnnouncement reads a content announcement's payload. A record of
// another type is ErrMalformed.
func ReadContentAnnouncement(r Record) (ContentAnnouncement, error) {
	if r.Type != TypeContentAnnouncement {
		return ContentAnnouncement{}, fmt.Errorf("%w: a record of type %#02x is not a content announcement", ErrMalformed, uint8(r.Type))
	}
	mcid, _ := payloadField(r.Payload, "mcid").AsBytes()
	endpoint, _ := payloadField(r.Payload, "endpoint").AsText()
	name, _ := payloadField(r.Payload, "name").AsText()
	announcement := ContentAnnouncement{
		MCID:       bytes.Clone(mcid),
		Endpoint:   endpoint,
		Name:       name,
		Size:       optionalUint(r.Payload, "size"),
		ChunkCount: optionalUint(r.Payload, "chunk_count"),
	}
	readID(announcement.AnnouncerNode[:], payloadField(r.Payload, "announcer_node"))
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
