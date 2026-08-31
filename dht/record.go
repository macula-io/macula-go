// Package dht implements the subset of Macula's PKARR-compatible signed DHT
// records that direct-dial resolution needs: procedure_advertisement and
// station_endpoint construction, signing, verification, and storage-key
// derivation, plus thin wrappers around the mesh's _dht.* RPC procedures.
//
// Ported from macula-io/macula's src/record/macula_record.erl and
// src/macula.erl (the put_record/find_record/find_records facade) — see
// macula_record.erl's module doc for the full record format (Part 6 §9)
// and signing domain (Part 6 §10.2). Only the two record types direct-dial
// needs are ported; add more constructors here as other direct-dial
// consumers (streaming, content) are built.
package dht

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

// Record type tags — macula_record.erl's ?TYPE_* constants.
const (
	TypeProcedureAdvertisement uint8 = 0x06
	TypeContentAnnouncement    uint8 = 0x11
	TypeStationEndpoint        uint8 = 0x12
)

// DefaultTTL matches macula_record's ?DEFAULT_TTL_MS (48h) — the TTL a
// procedure_advertisement gets when the caller doesn't specify one.
const DefaultTTL = 48 * time.Hour

// sigDomain is the Ed25519 signature domain separator — macula_record's
// ?SIG_DOMAIN. 17 bytes: "macula-v2-record" (16 ASCII) plus a trailing NUL.
const sigDomain = "macula-v2-record\x00"

// Record mirrors macula_record.erl's envelope map (type/key/version/
// created_at/expires_at/payload/signature). subject_id is not carried —
// neither record type this package builds uses it.
type Record struct {
	Type      uint8
	Key       []byte     // 32B: envelope signer's Ed25519 pubkey
	Version   []byte     // 16B: UUIDv7
	CreatedAt int64      // ms since epoch
	ExpiresAt int64      // ms since epoch
	Payload   cbor.Value // KindMap
	Signature []byte     // 64B, set by Sign
}

// NewProcedureAdvertisement builds an UNSIGNED procedure_advertisement
// record naming servingStation as procedureURI's current handler.
// procedureURI should be the realm-qualified discovery URI (see
// DiscoveryURI), matching macula_direct_dial's own convention — the
// advertiser and the resolver must derive the identical URI or the DHT
// storage key (ProcedureKey) will not agree. Sign before PutRecord.
// Mirrors macula_record:procedure_advertisement/3,4 (cert_chain and the
// other opt-in fields are not ported — see this package's README/report;
// out of scope until direct-dial itself is proven live).
func NewProcedureAdvertisement(advertiserNode []byte, procedureURI string, servingStation []byte, ttl time.Duration) (Record, error) {
	if len(advertiserNode) != 32 {
		return Record{}, fmt.Errorf("dht: advertiser node must be 32 bytes, got %d", len(advertiserNode))
	}
	if len(servingStation) != 32 {
		return Record{}, fmt.Errorf("dht: serving station must be 32 bytes, got %d", len(servingStation))
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	payload := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("procedure_uri"), Val: cbor.Text(procedureURI)},
		{Key: cbor.Text("advertiser_node"), Val: cbor.Bytes(advertiserNode)},
		{Key: cbor.Text("serving_station"), Val: cbor.Bytes(servingStation)},
	})
	return newEnvelope(TypeProcedureAdvertisement, advertiserNode, payload, ttl), nil
}

func newEnvelope(typ uint8, key []byte, payload cbor.Value, ttl time.Duration) Record {
	now := time.Now().UnixMilli()
	return Record{
		Type:      typ,
		Key:       key,
		Version:   uuidV7(now),
		CreatedAt: now,
		ExpiresAt: now + ttl.Milliseconds(),
		Payload:   payload,
	}
}

// uuidV7 builds a 16-byte UUIDv7 (RFC 9562 §5.7) for the given millisecond
// timestamp — matches macula_record_uuid:v7/1's bit layout: 48b ms | 4b
// ver=7 | 12b rand_a | 2b var=0b10 | 62b rand_b. Bytes 6..15 are filled
// with 10 random bytes up front, then the fixed version/variant bits are
// overlaid on top of (not instead of) their random neighbours, so the
// surrounding bits stay exactly as random as the spec requires without
// needing sub-byte arithmetic across the two random fields.
func uuidV7(ms int64) []byte {
	out := make([]byte, 16)
	out[0] = byte(ms >> 40)
	out[1] = byte(ms >> 32)
	out[2] = byte(ms >> 24)
	out[3] = byte(ms >> 16)
	out[4] = byte(ms >> 8)
	out[5] = byte(ms)
	_, _ = rand.Read(out[6:16])
	out[6] = 0x70 | (out[6] & 0x0F) // version=7 in top nibble; low nibble is randA's top bits
	out[8] = 0x80 | (out[8] & 0x3F) // variant=0b10 in top 2 bits; low 6 bits are randB's top bits
	return out
}

// canonicalUnsigned builds the exact bytes macula_record:canonical_unsigned/1
// signs and verifies: deterministic CBOR of the envelope map using the
// COMPACT single-letter keys (t/k/v/c/x/p), signature excluded. This is a
// DIFFERENT representation from the full-field-name map PutRecord sends as
// RPC args (see wire.go) — the compact form exists only to be signed/
// verified, never sent on the wire as such.
func canonicalUnsigned(r Record) []byte {
	entries := []cbor.MapEntry{
		{Key: cbor.Text("t"), Val: cbor.Uint64(uint64(r.Type))},
		{Key: cbor.Text("k"), Val: cbor.Bytes(r.Key)},
		{Key: cbor.Text("v"), Val: cbor.Bytes(r.Version)},
		{Key: cbor.Text("c"), Val: cbor.Int(r.CreatedAt)},
		{Key: cbor.Text("x"), Val: cbor.Int(r.ExpiresAt)},
		{Key: cbor.Text("p"), Val: r.Payload},
	}
	return cbor.Encode(cbor.Map(entries))
}

// Sign returns r with Signature set to the Ed25519 signature over
// sigDomain || canonicalUnsigned(r), matching macula_record:sign/2.
func Sign(r Record, id identity.KeyPair) Record {
	msg := append([]byte(sigDomain), canonicalUnsigned(r)...)
	r.Signature = id.Sign(msg)
	return r
}

// ErrInvalidSignature and ErrExpired are returned by Verify — distinguished
// because a caller resolving a record (e.g. directdial's retry loop) should
// retry past a stale-but-once-valid replica, never past a forged one. See
// macula_direct_dial.erl's on_endpoint_verified/3 for the Erlang reference
// doing exactly this branch.
var (
	ErrInvalidSignature = fmt.Errorf("dht: signature invalid")
	ErrExpired          = fmt.Errorf("dht: record expired")
	ErrNotFound         = fmt.Errorf("dht: record not found")
)

// Verify checks r's Ed25519 signature against its own Key, then its
// expiry. Matches macula_record:verify/1.
func Verify(r Record) error {
	if len(r.Signature) != 64 || len(r.Key) != 32 {
		return ErrInvalidSignature
	}
	msg := append([]byte(sigDomain), canonicalUnsigned(r)...)
	if !identity.Verify(r.Key, msg, r.Signature) {
		return ErrInvalidSignature
	}
	if r.ExpiresAt > 0 && time.Now().UnixMilli() >= r.ExpiresAt {
		return ErrExpired
	}
	return nil
}

// storageDomainStationEndpoint namespaces station_endpoint storage keys so
// they don't collide with node_record, which keys on the same pubkey —
// macula_record's ?STORAGE_DOMAIN_STATION_ENDPOINT.
const storageDomainStationEndpoint = "station_endpoint"

// ProcedureKey is the DHT storage key for a procedure_advertisement by its
// (already realm-qualified — see DiscoveryURI) URI: SHA-256(uri). Matches
// macula_record:procedure_key/1 and storage_key/1's own
// ?TYPE_PROCEDURE_ADVERTISEMENT clause (which hashes the same payload
// field independently — the two are required to agree).
func ProcedureKey(procedureURI string) [32]byte {
	return sha256.Sum256([]byte(procedureURI))
}

// StationEndpointKey is the DHT storage key for a station's own
// station_endpoint record: SHA-256("station_endpoint" || pubkey). Matches
// macula_record:station_endpoint_key/1.
func StationEndpointKey(stationPubkey []byte) [32]byte {
	buf := make([]byte, 0, len(storageDomainStationEndpoint)+len(stationPubkey))
	buf = append(buf, storageDomainStationEndpoint...)
	buf = append(buf, stationPubkey...)
	return sha256.Sum256(buf)
}

// DiscoveryURI matches macula_direct_dial's discovery_uri/2: the DHT
// lookup/advertisement key input is hex(realm) + "/" + procedure, so the
// same procedure name under different realms doesn't collide in the DHT.
// The advertiser and every resolver must derive this identically.
func DiscoveryURI(realm []byte, procedure string) string {
	const hexDigits = "0123456789ABCDEF"
	hexRealm := make([]byte, len(realm)*2)
	for i, b := range realm {
		hexRealm[i*2] = hexDigits[b>>4]
		hexRealm[i*2+1] = hexDigits[b&0x0F]
	}
	return string(hexRealm) + "/" + procedure
}

// ProcedureAdvertisement is a procedure_advertisement record's fields, read
// out of its payload — mirrors macula_record:read_procedure_advertisement/1.
// CertChain is nil when the advertisement carries no cert_chain field (the
// common, unmanaged-realm case); see VerifyAdvertisementCertChain.
type ProcedureAdvertisement struct {
	ProcedureURI   string
	AdvertiserNode []byte
	ServingStation []byte
	CertChain      []byte // optional: leaf-first PEM bundle, leaf ++ org CA
}

// ReadProcedureAdvertisement extracts a procedure_advertisement record's
// typed fields, or an error if r isn't one or is malformed.
func ReadProcedureAdvertisement(r Record) (ProcedureAdvertisement, error) {
	if r.Type != TypeProcedureAdvertisement {
		return ProcedureAdvertisement{}, fmt.Errorf("dht: not a procedure_advertisement record (type=%d)", r.Type)
	}
	uri, uok := textField(r.Payload, "procedure_uri")
	adv, aok := bytesField(r.Payload, "advertiser_node")
	station, sok := bytesField(r.Payload, "serving_station")
	if !uok || !aok || !sok || len(adv) != 32 || len(station) != 32 {
		return ProcedureAdvertisement{}, fmt.Errorf("dht: malformed procedure_advertisement payload")
	}
	certChain, _ := bytesField(r.Payload, "cert_chain") // absent is valid, not an error
	return ProcedureAdvertisement{
		ProcedureURI:   uri,
		AdvertiserNode: adv,
		ServingStation: station,
		CertChain:      certChain,
	}, nil
}

// NewProcedureAdvertisementWithCertChain is NewProcedureAdvertisement plus
// an embedded X.509 service-cert chain (leaf-first PEM: leaf ++ org CA),
// for Slice 7c Direction B managed-realm authorization — see
// VerifyAdvertisementCertChain for the corresponding check. Opt-in: plain
// NewProcedureAdvertisement is unaffected and remains the right choice for
// unmanaged realms.
func NewProcedureAdvertisementWithCertChain(advertiserNode []byte, procedureURI string, servingStation []byte, ttl time.Duration, certChainPEM []byte) (Record, error) {
	rec, err := NewProcedureAdvertisement(advertiserNode, procedureURI, servingStation, ttl)
	if err != nil {
		return Record{}, err
	}
	entries, ok := rec.Payload.AsMap()
	if !ok {
		return Record{}, fmt.Errorf("dht: internal: procedure_advertisement payload is not a map")
	}
	entries = append(entries, cbor.MapEntry{Key: cbor.Text("cert_chain"), Val: cbor.Bytes(certChainPEM)})
	rec.Payload = cbor.Map(entries)
	return rec, nil
}

// StationEndpoint is a station_endpoint record's fields, read out of its
// payload — mirrors macula_record:read_station_endpoint/1.
type StationEndpoint struct {
	QuicPort       uint16
	HostAdvertised []string
}

// ReadStationEndpoint extracts a station_endpoint record's typed fields,
// or an error if r isn't one or is malformed.
func ReadStationEndpoint(r Record) (StationEndpoint, error) {
	if r.Type != TypeStationEndpoint {
		return StationEndpoint{}, fmt.Errorf("dht: not a station_endpoint record (type=%d)", r.Type)
	}
	portV, ok := r.Payload.Get("quic_port")
	if !ok {
		return StationEndpoint{}, fmt.Errorf("dht: station_endpoint missing quic_port")
	}
	portI, ok := portV.AsInt64()
	if !ok || portI <= 0 || portI > 65535 {
		return StationEndpoint{}, fmt.Errorf("dht: station_endpoint has a malformed quic_port")
	}
	var hosts []string
	if hv, ok := r.Payload.Get("host_advertised"); ok {
		if list, ok := hv.AsList(); ok {
			for _, item := range list {
				// macula_record.erl's with_host_list/2 puts each host in
				// as a bare Erlang binary, unlike every other string
				// field in this file (which wraps with {text, Bin}) —
				// so on the wire these are CBOR BYTE strings (major type
				// 2), not text strings, confirmed against a real
				// station's own published record. AsText() alone finds
				// nothing here; try bytes first, text as a fallback in
				// case a future publisher wraps these properly.
				if b, ok := item.AsBytes(); ok {
					hosts = append(hosts, string(b))
					continue
				}
				if s, ok := item.AsText(); ok {
					hosts = append(hosts, s)
				}
			}
		}
	}
	return StationEndpoint{QuicPort: uint16(portI), HostAdvertised: hosts}, nil
}

// ContentAnnouncement is a content_announcement record's fields, read out
// of its payload — mirrors macula_record:read_content_announcement/1. Name/
// Size/ChunkCount are optional metadata (zero value when absent), matching
// the reference's own content_announcement_opts().
type ContentAnnouncement struct {
	AnnouncerNode []byte
	MCID          []byte
	Endpoint      string // a dialable seed URL, e.g. "https://host:4433" — matches macula_client:seed()'s own format, NOT a station_endpoint's split host/port
	Name          string
	Size          int64
	ChunkCount    int64
}

// NewContentAnnouncement builds an UNSIGNED content_announcement record
// naming announcerNode as reachable at endpoint for mcid. Sign before
// PutRecord. Mirrors macula_record:content_announcement/3,4 — the optional
// name/size/chunk_count metadata fields are not ported (this package's
// GetDirect doesn't need them to resolve and dial; add them if a future
// caller needs to prioritize candidates without fetching the manifest).
func NewContentAnnouncement(announcerNode []byte, mcid []byte, endpoint string, ttl time.Duration) (Record, error) {
	if len(announcerNode) != 32 {
		return Record{}, fmt.Errorf("dht: announcer node must be 32 bytes, got %d", len(announcerNode))
	}
	if len(mcid) != 34 {
		return Record{}, fmt.Errorf("dht: mcid must be 34 bytes, got %d", len(mcid))
	}
	payload := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("announcer_node"), Val: cbor.Bytes(announcerNode)},
		{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid)},
		{Key: cbor.Text("endpoint"), Val: cbor.Text(endpoint)},
	})
	return newEnvelope(TypeContentAnnouncement, announcerNode, payload, ttl), nil
}

// ReadContentAnnouncement extracts a content_announcement record's typed
// fields, or an error if r isn't one or is malformed.
func ReadContentAnnouncement(r Record) (ContentAnnouncement, error) {
	if r.Type != TypeContentAnnouncement {
		return ContentAnnouncement{}, fmt.Errorf("dht: not a content_announcement record (type=%d)", r.Type)
	}
	announcer, aok := bytesField(r.Payload, "announcer_node")
	mcid, mok := bytesField(r.Payload, "mcid")
	endpoint, eok := textField(r.Payload, "endpoint")
	if !aok || !mok || !eok || len(announcer) != 32 || len(mcid) != 34 {
		return ContentAnnouncement{}, fmt.Errorf("dht: malformed content_announcement payload")
	}
	out := ContentAnnouncement{AnnouncerNode: announcer, MCID: mcid, Endpoint: endpoint}
	if v, ok := r.Payload.Get("name"); ok {
		if s, ok := v.AsText(); ok {
			out.Name = s
		}
	}
	if v, ok := r.Payload.Get("size"); ok {
		if n, ok := v.AsInt64(); ok {
			out.Size = n
		}
	}
	if v, ok := r.Payload.Get("chunk_count"); ok {
		if n, ok := v.AsInt64(); ok {
			out.ChunkCount = n
		}
	}
	return out, nil
}

// ContentKey is the DHT storage key for every content_announcement naming
// mcid: SHA-256(mcid). Matches macula_record:content_key/1. Consumers use
// this with FindRecords (there may be more than one announcer) before
// holding any record.
func ContentKey(mcid []byte) [32]byte {
	return sha256.Sum256(mcid)
}

func textField(v cbor.Value, name string) (string, bool) {
	fv, ok := v.Get(name)
	if !ok {
		return "", false
	}
	return fv.AsText()
}

func bytesField(v cbor.Value, name string) ([]byte, bool) {
	fv, ok := v.Get(name)
	if !ok {
		return nil, false
	}
	return fv.AsBytes()
}
