package record

import (
	"bytes"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
)

// A provider names its KEM key in its advertisement (macula 13's E2E design,
// amendment A1): kem_key, the key as carried, with kem_key_id, its seal key
// id, both or neither. The payload rule is macula_record's
// advertisement_payload_ok/1 with kem_key_pair/1.

func kemKeyOf(t *testing.T, p profile.Profile) []byte {
	t.Helper()
	key, err := seal.GenerateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey().Carried()
}

func TestAKEMKeyTravelsAsAPairOrNotAtAll(t *testing.T) {
	advertisement, _ := advertisementPayload(fill(1)).AsMap()
	pure, hybrid := kemKeyOf(t, profile.PQPure), kemKeyOf(t, profile.PQHybrid)
	pureID, hybridID := seal.KeyID(pure), seal.KeyID(hybrid)
	keyed := func(key, id []byte) []cbor.MapEntry {
		return withEntry(withEntry(advertisement, "kem_key", cbor.Bytes(key)), "kem_key_id", cbor.Bytes(id))
	}
	authorization := cbor.Map([]cbor.MapEntry{uintEntry("anything", 1)})
	short := make([]byte, 1000)
	shortID := seal.KeyID(short)
	for _, c := range []struct {
		name    string
		payload []cbor.MapEntry
		ok      bool
	}{
		{"no key", advertisement, true},
		{"a pq_pure key and its id", keyed(pure, pureID[:]), true},
		{"a pq_hybrid key and its id", keyed(hybrid, hybridID[:]), true},
		{"a key and its id beside an authorization", withEntry(keyed(pure, pureID[:]), "authorization", authorization), true},
		{"an id that is not its key's", keyed(pure, hybridID[:]), false},
		{"a key alone", withEntry(advertisement, "kem_key", cbor.Bytes(pure)), false},
		{"an id alone", withEntry(advertisement, "kem_key_id", cbor.Bytes(pureID[:])), false},
		{"a key of no profile's size, with its id", keyed(short, shortID[:]), false},
		{"a key as text", withEntry(withEntry(advertisement, "kem_key", cbor.Text("k")), "kem_key_id", cbor.Bytes(pureID[:])), false},
		{"a key and id beside a fifth unknown key", withEntry(keyed(pure, pureID[:]), "hint", cbor.Text("h")), false},
	} {
		if got := payloadOK(TypeProcedureAdvertisement, cbor.Map(c.payload)); got != c.ok {
			t.Errorf("%s: payload ok %v, want %v", c.name, got, c.ok)
		}
	}
}

// The builder names the key with its id, and the reader gives both back; an
// advertisement without one reads as naming none.
func TestAnAdvertisementNamesItsKEMKey(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		key := kemKeyOf(t, p)
		r := must[Record](t)(NewProcedureAdvertisement(fill(1), fill(0x11), "acme/x", fill(0x77),
			ProcedureAdvertisementOptions{KEMKey: key}))
		if !payloadOK(r.Type, r.Payload) {
			t.Fatalf("%s: the builder made a payload the rule refuses", p)
		}
		read := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(r))
		if !bytes.Equal(read.KEMKey, key) || read.KEMKeyID != seal.KeyID(key) {
			t.Errorf("%s: read key %d bytes, id %x", p, len(read.KEMKey), read.KEMKeyID)
		}
	}
	plain := must[Record](t)(NewProcedureAdvertisement(fill(1), fill(0x11), "acme/x", fill(0x77), ProcedureAdvertisementOptions{}))
	if read := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(plain)); read.KEMKey != nil {
		t.Errorf("an advertisement without a key reads as naming one")
	}
	if _, err := NewProcedureAdvertisement(fill(1), fill(0x11), "acme/x", fill(0x77),
		ProcedureAdvertisementOptions{KEMKey: make([]byte, 1000)}); err == nil {
		t.Error("the builder named a key of no profile's size")
	}
}
