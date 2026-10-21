package record

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/internal/wire10vectors"
	"github.com/macula-io/macula-go/profile"
)

// The wire 1.0 record vectors (macula priv/vectors/wire_1_0, macula#100): a
// reader (Verify) runs verify.json and check_order.json's reader cases; a
// custodian (CheckAsCustodian, the checks a station stores by) runs
// custodian.json and check_order.json's custodian cases. Each refusal is the
// first fault in WIRE_1_0.md section 5.2's order.

// wireRefusals are the refusal names of section 5.2, by the error that carries
// each.
var wireRefusals = map[string]error{
	"record_too_large":        ErrRecordTooLarge,
	"malformed":               ErrMalformed,
	"alg_unsupported":         identity.ErrObjectAlgUnsupported,
	"signature_invalid":       identity.ErrObjectSignatureInvalid,
	"not_yet_valid":           ErrNotYetValid,
	"expired":                 ErrExpired,
	"lifetime_reversed":       ErrLifetimeReversed,
	"lifetime_class_unknown":  ErrLifetimeClassUnknown,
	"lifetime_too_long":       ErrLifetimeTooLong,
	"subject_missing":         ErrSubjectMissing,
	"type_unknown":            ErrTypeUnknown,
	"schema_unsupported":      ErrSchemaUnsupported,
	"lifetime_class_mismatch": ErrLifetimeClassMismatch,
	"extension_unsupported":   frame.ErrExtensionUnsupported,
	"mcid_tag_unknown":        ErrMcidTagUnknown,
	"key_id_mismatch":         ErrKeyIDMismatch,
}

func wantRefusalNamed(t *testing.T, err error, name string) {
	t.Helper()
	want, known := wireRefusals[name]
	if !known {
		t.Fatalf("no error carries the refusal %s", name)
	}
	if !errors.Is(err, want) {
		t.Fatalf("%v, want %s", err, name)
	}
	for other, e := range wireRefusals {
		if other != name && e != want && errors.Is(err, e) {
			t.Fatalf("%v is %s as well as %s", err, other, name)
		}
	}
}

func vectorObjects(t *testing.T) map[string][]byte {
	t.Helper()
	f, err := wire10vectors.Load("verify")
	if err != nil {
		t.Fatal(err)
	}
	objects := make(map[string][]byte, len(f.Cases))
	for _, c := range f.Cases {
		if objects[c.ID], err = c.Hex("object"); err != nil {
			t.Fatal(err)
		}
	}
	return objects
}

func TestTheWireOneReaderVectors(t *testing.T) {
	for _, class := range []string{"verify", "check_order"} {
		for _, c := range readWireOneCases(t, class) {
			if role := c.ExpectText("role"); role != "" && role != "reader" {
				continue
			}
			t.Run(c.ID, func(t *testing.T) {
				checkReaderVector(t, c)
			})
		}
	}
}

// readWireOneCases is the cases of one wire 1.0 vector class.
func readWireOneCases(t *testing.T, class string) []wire10vectors.Case {
	t.Helper()
	f, err := wire10vectors.Load(class)
	if err != nil {
		t.Fatal(err)
	}
	return f.Cases
}

// checkReaderVector holds Verify to one reader vector's verdict, and a counted
// extension where the vector names one.
func checkReaderVector(t *testing.T, c wire10vectors.Case) {
	t.Helper()
	wire, err := c.Hex("object")
	if err != nil {
		t.Fatal(err)
	}
	before := frame.WireCounters().ExtIgnored
	_, err = Verify(wire, profile.Profile(c.Profile), c.Int("now_ms"))
	switch c.Outcome() {
	case "accept":
		if err != nil {
			t.Fatalf("%v, want it verified", err)
		}
		if c.ExpectText("count") == "wire_ext_ignored" && sum(frame.WireCounters().ExtIgnored) == sum(before) {
			t.Errorf("wire_ext_ignored did not count")
		}
	case "refuse":
		wantRefusalNamed(t, err, c.Reason())
	default:
		t.Fatalf("outcome %q has no check here", c.Outcome())
	}
}

func TestTheWireOneCustodianVectors(t *testing.T) {
	objects := vectorObjects(t)
	for _, class := range []string{"custodian", "check_order"} {
		for _, c := range readWireOneCases(t, class) {
			if role := c.ExpectText("role"); class == "check_order" && role != "custodian" {
				continue
			}
			t.Run(c.ID, func(t *testing.T) {
				checkCustodianVector(t, objects, c)
			})
		}
	}
}

// checkCustodianVector holds CheckAsCustodian to one custodian vector's
// verdict, over the object the vector names or carries.
func checkCustodianVector(t *testing.T, objects map[string][]byte, c wire10vectors.Case) {
	t.Helper()
	wire := objects[c.Text("object_of")]
	if c.Text("object") != "" {
		wire, _ = hex.DecodeString(c.Text("object"))
	}
	if wire == nil {
		t.Fatalf("no object for %s", c.Text("object_of"))
	}
	_, err := CheckAsCustodian(wire, profile.Profile(c.Profile), c.Int("now_ms"))
	switch c.Outcome() {
	case "store":
		if err != nil {
			t.Fatalf("%v, want it stored", err)
		}
	case "refuse":
		wantRefusalNamed(t, err, c.Reason())
	default:
		t.Fatalf("outcome %q has no check here", c.Outcome())
	}
}

func sum(m map[string]uint64) (n uint64) {
	for _, v := range m {
		n += v
	}
	return n
}
