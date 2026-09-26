package teststation

import (
	"crypto/sha256"
	"time"

	"github.com/google/uuid"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// Realm is a test realm with one org: its realm key names the org's key in an
// org directory, and the org key delegates its procedures to advertisers.
// Go keys are identity or CONNECT keys only, so the realm's and org's records
// are signed as the signed objects they are, under the record label, as a
// realm and an org sign them.
type Realm struct {
	Name    string
	ID      [32]byte
	Org     string
	Key     *identity.NodeKey
	OrgKey  *identity.NodeKey
	profile profile.Profile
}

// NewRealm is a test realm named name with the org org. Its id is the SHA-256
// of its name, as a realm's is, so a UCAN that grants in the realm by name
// grants in it.
func NewRealm(t T, p profile.Profile, name, org string) Realm {
	t.Helper()
	return Realm{Name: name, ID: sha256.Sum256([]byte(name)), Org: org, Key: Key(t, p, "realm "+name), OrgKey: Key(t, p, "org "+name+"/"+org), profile: p}
}

// RealmKey is the realm key as carried, the key a member pins for the realm.
func (r Realm) RealmKey() []byte { return r.Key.PublicKey() }

// Admit puts the realm's org directory, and the org's delegation to each
// advertiser, in station's DHT, living an hour.
func (r Realm) Admit(t T, station *Station, advertisers ...[32]byte) {
	t.Helper()
	orgKeyID := identity.KeyIDOf(r.OrgKey.PublicKey(), r.profile)
	station.Put(signed(t, 0x15, cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("realm_id"), Val: cbor.Bytes(r.ID[:])},
		{Key: cbor.Text("org_name"), Val: cbor.Text(r.Org)},
		{Key: cbor.Text("org_key"), Val: cbor.Bytes(orgKeyID[:])},
	}), r.Key))
	for _, advertiser := range advertisers {
		station.Put(signed(t, 0x16, cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("org_key"), Val: cbor.Bytes(orgKeyID[:])},
			{Key: cbor.Text("advertiser"), Val: cbor.Bytes(advertiser[:])},
		}), r.OrgKey))
	}
}

func signed(t T, recordType uint64, payload cbor.Value, key *identity.NodeKey) []byte {
	t.Helper()
	version, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("teststation: version: %v", err)
	}
	now := uint64(time.Now().UnixMilli())
	object, err := identity.SignObject("MACULA-PQ-RECORD-V1", []cbor.MapEntry{
		{Key: cbor.Text("type"), Val: cbor.Uint64(recordType)},
		{Key: cbor.Text("version"), Val: cbor.Bytes(version[:])},
		{Key: cbor.Text("created_at"), Val: cbor.Uint64(now)},
		{Key: cbor.Text("expires_at"), Val: cbor.Uint64(now + 3_600_000)},
		{Key: cbor.Text("payload"), Val: payload},
	}, key)
	if err != nil {
		t.Fatalf("teststation: sign: %v", err)
	}
	return cbor.Encode(object.Value())
}
