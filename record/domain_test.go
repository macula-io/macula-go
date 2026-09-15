package record

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_record_domain_tests at merge-11.0.0
// 81e2eca1. A domain record's subject is a non-empty binary: Envelope refuses
// an empty one (ErrInvalidSubject), and Sign and every verifier refuse it as
// malformed, since it would name a slot apart from no subject, and so does a
// tombstone's slot. A tombstone names a withdrawn type from 1 to 255, and a
// domain record's tombstone signs within the domain maximum plus twice the
// clock tolerance, on the record's slot. macula's domain_record_checked/1 is a
// pool's check before it signs a domain record as its node, and Go has no such
// pool.

func TestAnEmptySubjectIsRefusedByEnvelope(t *testing.T) {
	_, err := Envelope(DomainTypeMin, cbor.Map(nil), []byte{}, 0)
	wantRefusal(t, "an envelope with an empty subject", err, ErrInvalidSubject)
	r, err := Envelope(DomainTypeMin, cbor.Map(nil), nil, 0)
	if err != nil || r.Subject != nil {
		t.Errorf("an envelope without a subject: %v, with subject %q, want none", err, r.Subject)
	}
}

// A verifier refuses a domain record with an empty subject. Sign signs none, so
// this one is signed by hand, as macula's test signs it with
// signed_by_another_stack.
func TestAnEmptySubjectIsRefusedByAVerifier(t *testing.T) {
	keys := keysFor(t)
	fields := append(recordFields(t, DomainTypeMin, cbor.Map(nil), nowMs(), testHour), bytesEntry("subject", []byte{}))
	_, err := Verify(signedByHand(t, label, fields, keys.node), profile.PQPure, nowMs())
	wantRefusal(t, "a domain record with an empty subject", err, ErrMalformed)
}

// Sign refuses an empty subject as a verifier would, after the key's purpose,
// as macula's sign/2 does: with an identity key the record is malformed, and a
// CONNECT key, whose purpose signs no domain type, is refused for its purpose
// first.
func TestAnEmptySubjectIsRefusedBySign(t *testing.T) {
	keys := keysFor(t)
	r := must[Record](t)(Envelope(DomainTypeMin, cbor.Map(nil), nil, 0))
	r.Subject = []byte{}
	_, err := Sign(r, keys.node)
	wantRefusal(t, "sign a domain record with an empty subject", err, ErrMalformed)
	_, err = Sign(r, keys.connect)
	wantRefusal(t, "sign with a CONNECT key a domain record with an empty subject", err, ErrKeyPurposeMismatch)
}

// A tombstone of a domain record carries none of the record's slot fields, or
// its subject, which is not empty.
func TestAnEmptySubjectIsRefusedInATombstonesSlot(t *testing.T) {
	keys := keysFor(t)
	withdrawing := func(slot ...cbor.MapEntry) []cbor.MapEntry {
		return append([]cbor.MapEntry{uintEntry("withdrawn_type", uint64(DomainTypeMin)),
			bytesEntry("withdrawn_version", make([]byte, 16)), textEntry("reason", "shutdown")}, slot...)
	}
	for _, c := range []struct {
		name    string
		payload []cbor.MapEntry
		want    error
	}{
		{"a tombstone of a domain record without a subject", withdrawing(), nil},
		{"a tombstone of a domain record with its subject", withdrawing(bytesEntry("subject", []byte("s1"))), nil},
		{"a tombstone of a domain record with an empty subject", withdrawing(bytesEntry("subject", []byte{})), ErrMalformed},
	} {
		now := nowMs()
		fields := recordFields(t, TypeTombstone, cbor.Map(c.payload), now, testDay)
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

// A domain record's tombstone signs within the domain maximum plus twice the
// clock tolerance, on the record's slot, and a millisecond past that bound is
// refused.
func TestADomainRecordTombstoneSignsWithinTheMaximumAndTwiceTheToleranceOnItsSlot(t *testing.T) {
	keys := keysFor(t)
	withdrawn := must[Record](t)(Sign(must[Record](t)(Envelope(DomainTypeMin, cbor.Map(nil), []byte("s1"), uint64(7*testDay))), keys.node))
	tombstone := must[Record](t)(NewTombstone(withdrawn, ReasonShutdown, TombstoneOptions{}))
	tombstone.ExpiresAt = tombstone.CreatedAt + uint64(7*testDay+10*testMinute)
	atBound := must[Record](t)(Sign(tombstone, keys.node))
	if _, err := Verify(wireOf(t, atBound), profile.PQPure, nowMs()); err != nil {
		t.Errorf("verify the tombstone at its bound: %v", err)
	}
	if must[[32]byte](t)(StorageKey(atBound)) != must[[32]byte](t)(StorageKey(withdrawn)) {
		t.Error("the domain record's tombstone does not take its slot")
	}
	tombstone.ExpiresAt++
	_, err := Sign(tombstone, keys.node)
	wantRefusal(t, "sign the domain record's tombstone 1 ms past its bound", err, ErrLifetimeTooLong)
}

// A tombstone names a withdrawn type from 1 to 255, since every record type is
// a tag in that range, and a type beyond it would be read by its low byte: one
// naming 0x100 is malformed however it was signed, and one naming 0xFF still
// verifies. Sign refuses the one naming 0x100, so it is signed by hand, as
// macula's test signs it with signed_by_another_stack.
func TestATombstoneNamesAWithdrawnTypeWithinTheTypeRange(t *testing.T) {
	keys := keysFor(t)
	withdrawn := must[Record](t)(Sign(must[Record](t)(Envelope(0xFF, cbor.Map(nil), nil, 0)), keys.node))
	tombstone := func(withdrawnType uint64) Record {
		payload := cbor.Map([]cbor.MapEntry{uintEntry("withdrawn_type", withdrawnType),
			bytesEntry("withdrawn_version", withdrawn.Version[:]), textEntry("reason", "shutdown")})
		return must[Record](t)(unsigned(TypeTombstone, payload, withdrawn.ExpiresAt-withdrawn.CreatedAt+ClockToleranceMs))
	}
	if _, err := Verify(wireOf(t, must[Record](t)(Sign(tombstone(0xFF), keys.node))), profile.PQPure, nowMs()); err != nil {
		t.Errorf("a tombstone naming 0xFF: %v, want it verified", err)
	}
	_, err := Verify(signedByHand(t, label, tbsFields(tombstone(0x100)), keys.node), profile.PQPure, nowMs())
	wantRefusal(t, "a tombstone naming 0x100", err, ErrMalformed)
}
