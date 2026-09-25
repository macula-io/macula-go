package record

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// ownNamespaceVerdict is one row of macula's own-namespace fixtures
// (test/fixtures/own_namespace/verdicts.json, copied into testdata by
// scripts/interop/copy_own_namespace_fixtures.sh): a signed advertisement,
// the time to evaluate it at, and the verdicts macula_record's
// own_namespace/1 and verify_authorization/3 (with no realm key) reach.
type ownNamespaceVerdict struct {
	File                string `json:"file"`
	NowMs               int64  `json:"now_ms"`
	Procedure           string `json:"procedure"`
	Profile             string `json:"profile"`
	OwnNamespace        string `json:"own_namespace"`
	VerifyAuthorization string `json:"verify_authorization"`
}

// refusalOf is the Go refusal for a macula refusal's name.
var refusalOf = map[string]error{
	"ok":                        nil,
	"not_own_namespace":         ErrNotOwnNamespace,
	"malformed":                 ErrMalformed,
	"authorization_not_allowed": ErrAuthorizationNotAllowed,
	"no_authorization":          ErrNoAuthorization,
}

// TestOwnNamespaceFixtures holds OwnNamespace and VerifyAuthorization to the
// verdicts macula reaches on the same signed records, under both profiles.
func TestOwnNamespaceFixtures(t *testing.T) {
	dir := filepath.Join("testdata", "own_namespace")
	raw, err := os.ReadFile(filepath.Join(dir, "verdicts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var verdicts []ownNamespaceVerdict
	if err := json.Unmarshal(raw, &verdicts); err != nil {
		t.Fatal(err)
	}
	if len(verdicts) != 14 {
		t.Fatalf("%d verdicts, want the 7 cases under both profiles", len(verdicts))
	}
	for _, v := range verdicts {
		t.Run(v.File, func(t *testing.T) {
			wantOwn, known := refusalOf[v.OwnNamespace]
			wantVerify, knownVerify := refusalOf[v.VerifyAuthorization]
			if !known || !knownVerify {
				t.Fatalf("an unknown verdict: %q / %q", v.OwnNamespace, v.VerifyAuthorization)
			}
			p, err := profile.Parse(v.Profile)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := os.ReadFile(filepath.Join(dir, v.File))
			if err != nil {
				t.Fatal(err)
			}
			verified, err := Verify(wire, p, v.NowMs)
			if err != nil {
				t.Fatalf("the fixture does not verify: %v", err)
			}
			if ad := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(verified.Record())); ad.Procedure != v.Procedure {
				t.Fatalf("procedure %q, the verdicts name %q", ad.Procedure, v.Procedure)
			}
			if got := OwnNamespace(verified); !errors.Is(got, wantOwn) || (wantOwn == nil) != (got == nil) {
				t.Errorf("OwnNamespace = %v, want %v", got, wantOwn)
			}
			got := VerifyAuthorization(verified, Trust{Profile: p}, v.NowMs)
			if !errors.Is(got, wantVerify) || (wantVerify == nil) != (got == nil) {
				t.Errorf("VerifyAuthorization = %v, want %v", got, wantVerify)
			}
		})
	}
}
