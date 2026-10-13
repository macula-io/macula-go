package record

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// A tombstone of a tag a 1.0 custodian does not know (a post-1.0 tag) is
// stored content-blind (WIRE_1_0.md 5.1, with #98): bounded by the row it
// names plus 10 minutes, whatever row that is, and placed at the withdrawn
// record's slot, H(withdrawn type | signer key id | subject), from its
// payload's subject; a reader refuses it as type_unknown.
func TestATombstoneOfAnUnknownTagIsStoredContentBlind(t *testing.T) {
	keys := keysFor(t)
	const unknownTag = 0x18
	subject := []byte("thing-7")
	payload := func(withSubject bool) cbor.Value {
		entries := []cbor.MapEntry{uintEntry("withdrawn_type", unknownTag), bytesEntry("withdrawn_version", make([]byte, 16)),
			textEntry("reason", "revoked")}
		if withSubject {
			entries = append(entries, bytesEntry("subject", subject))
		}
		return cbor.Map(entries)
	}
	signed := func(row uint8, lifetimeMs int64, withSubject bool) []byte {
		fields := recordFields(t, TypeTombstone, payload(withSubject), nowMs(), lifetimeMs)
		return signedByHand(t, label, withEntry(fields, "lifetime_class", cbor.Uint64(uint64(row))), keys.node)
	}
	keyID := identity.KeyIDOf(keys.node.PublicKey(), profile.PQPure)
	want := derived(unknownTag, keyID[:], lengthPrefixed(subject))
	for _, c := range []struct {
		name       string
		row        uint8
		lifetimeMs int64
	}{
		{"naming row 0, at 5 minutes plus 10", lifetimeClass5Minutes, 15 * testMinute},
		{"naming row 3, at 48 hours", lifetimeClass48Hours, 48 * testHour},
	} {
		slot, err := CheckAsCustodian(signed(c.row, c.lifetimeMs, true), profile.PQPure, nowMs())
		if err != nil || slot != want {
			t.Errorf("%s: (%x, %v), want it stored at %x", c.name, slot, err, want)
		}
	}
	_, err := CheckAsCustodian(signed(lifetimeClass5Minutes, 15*testMinute+1, true), profile.PQPure, nowMs())
	wantRefusal(t, "past its row plus 10 minutes", err, ErrLifetimeTooLong)
	_, err = CheckAsCustodian(signed(lifetimeClass5Minutes, 5*testMinute, false), profile.PQPure, nowMs())
	wantRefusal(t, "without a subject", err, ErrSubjectMissing)
	_, err = Verify(signed(lifetimeClass5Minutes, 5*testMinute, true), profile.PQPure, nowMs())
	wantRefusal(t, "at a reader", err, ErrTypeUnknown)
}
