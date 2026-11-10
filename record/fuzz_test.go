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
// shared wire 1.0 vectors (verify.json and custodian.json), read from their
// files through internal/wire10vectors, with each case's own verification time.
//
// A hang is the package test timeout: Verify refuses a wire form over
// MaxRecordBytes before reading it, and the CBOR decoding rule behind it bounds
// depth, element count and the bytes it needs.

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

// FuzzVerify holds Verify and CheckAsCustodian to the invariant, under both of
// macula's profiles and at the time the case was written for. verify.json holds
// every object; custodian.json's cases name one of them by id (`object_of`), so
// seeding from the objects covers both classes.
func FuzzVerify(f *testing.F) {
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
	refusals := recordRefusals()
	profiles := []profile.Profile{profile.PQHybrid, profile.PQPure}
	f.Fuzz(func(t *testing.T, wire []byte, nowMs int64) {
		for _, p := range profiles {
			verified, err := Verify(wire, p, nowMs)
			if err != nil {
				refusedAsOneOf(t, err, refusals)
				continue
			}
			// What verifies re-encodes, verifies again at the same time, and
			// names the same storage key both times: a record's slot is the
			// station's, so a re-encode may not move it.
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
			first, err := CheckAsCustodian(wire, p, nowMs)
			if err != nil {
				t.Fatalf("a verified record is refused by a custodian: %v", err)
			}
			if other, err := CheckAsCustodian(encoded, p, nowMs); err != nil || other != first {
				t.Fatalf("a re-encoded record stores at another key: %x, then %x (%v)", first, other, err)
			}
		}
	})
}
