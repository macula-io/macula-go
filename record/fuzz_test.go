package record

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/internal/wire10vectors"
	"github.com/macula-io/macula-go/profile"
)

// FuzzVerify holds the record decoder to macula-go#39's invariant on any byte
// string a peer can send: a record that verifies, re-encodes and verifies again
// to the same storage key, or a typed refusal -- never a panic, and never a
// record read past its bounds. The seed corpus is every record object of the
// shared wire 1.0 vectors, read from their files through internal/wire10vectors
// with each case's own verification time; custodian.json's cases name one of
// these objects by id (`object_of`), so seeding from the objects covers both
// classes.
//
// A hang is the package test timeout: Verify refuses a wire form over
// MaxRecordBytes before reading it, and the CBOR decoding rule behind it bounds
// depth, element count and the bytes it needs.

// fuzzProfiles are macula's two profiles: a record verifies under its own and is
// refused under the other, and both are refusals this target must accept.
var fuzzProfiles = []profile.Profile{profile.PQHybrid, profile.PQPure}

// FuzzVerify holds Verify and CheckAsCustodian to the invariant, under both
// profiles and at the time each case was written for.
func FuzzVerify(f *testing.F) {
	seedRecordObjects(f)
	refusals := recordRefusals()
	f.Fuzz(func(t *testing.T, wire []byte, nowMs int64) {
		for _, p := range fuzzProfiles {
			checkOneProfile(t, wire, nowMs, p, refusals)
		}
	})
}

// seedRecordObjects adds every record object of the shared vectors with its
// case's verification time.
func seedRecordObjects(f *testing.F) {
	file, err := wire10vectors.Load("verify")
	if err != nil {
		f.Fatalf("verify: %v", err)
	}
	for _, c := range file.Cases {
		wire, err := c.Hex("object")
		if err != nil {
			f.Fatalf("verify %s: %v", c.ID, err)
		}
		f.Add(wire, c.Int("now_ms"))
	}
}

// recordRefusals are every error Verify can return: the refusals of
// WIRE_1_0.md section 5.2, which the vector tests already name, and the
// refusal a binary without ML-DSA gives before it reads anything.
func recordRefusals() []error {
	out := make([]error, 0, len(wireRefusals)+1)
	for _, refusal := range wireRefusals {
		if !slices.Contains(out, refusal) {
			out = append(out, refusal)
		}
	}
	return append(out, identity.ErrPostQuantumUnavailable)
}

func refusedAsOneOf(t *testing.T, err error, refusals []error) {
	t.Helper()
	for _, refusal := range refusals {
		if errors.Is(err, refusal) {
			return
		}
	}
	t.Fatalf("refused with an error that is not one of the package's: %v", err)
}

// checkOneProfile holds one verification to the invariant: a typed refusal, or a
// record whose re-encoding still verifies and still stores at the same key.
func checkOneProfile(t *testing.T, wire []byte, nowMs int64, p profile.Profile, refusals []error) {
	t.Helper()
	verified, err := Verify(wire, p, nowMs)
	if err != nil {
		refusedAsOneOf(t, err, refusals)
		return
	}
	encoded := checkReEncodes(t, verified, p, nowMs)
	checkSameSlot(t, wire, encoded, p, nowMs)
}

// checkReEncodes verifies a record's encoding again at the same time and
// requires the second encoding to be the same bytes; it returns the encoding.
func checkReEncodes(t *testing.T, verified Verified, p profile.Profile, nowMs int64) []byte {
	t.Helper()
	encoded, err := Encode(verified.Record())
	if err != nil {
		t.Fatalf("a verified record does not encode: %v", err)
	}
	again, err := Verify(encoded, p, nowMs)
	if err != nil {
		t.Fatalf("a verified record does not verify after a re-encode: %v", err)
	}
	second, err := Encode(again.Record())
	if err != nil {
		t.Fatalf("a re-verified record does not encode: %v", err)
	}
	if !bytes.Equal(encoded, second) {
		t.Fatalf("re-encoding is not deterministic: %x, then %x", encoded, second)
	}
	return encoded
}

// checkSameSlot requires a record and its re-encoding to be stored at one key: a
// re-encode may not move what a station files it under.
func checkSameSlot(t *testing.T, wire, encoded []byte, p profile.Profile, nowMs int64) {
	t.Helper()
	first, err := CheckAsCustodian(wire, p, nowMs)
	if err != nil {
		t.Fatalf("a verified record is refused by a custodian: %v", err)
	}
	other, err := CheckAsCustodian(encoded, p, nowMs)
	if err != nil || other != first {
		t.Fatalf("a re-encoded record stores at another key: %x, then %x (%v)", first, other, err)
	}
}
