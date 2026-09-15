package identity

import (
	"crypto/fips140"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// A binary built with GOFIPS140=v1.0.0 has no ML-DSA, and says so on its first
// key operation: CheckPostQuantum, GenerateKey, GenerateIdentityKey and LoadKey
// return ErrPostQuantumUnavailable, LoadKey before it reads the file. Any other
// binary generates keys and reads key files. CI runs this test both ways; which
// way a run goes is read from crypto/fips140, not from the check under test.
func TestAKeyOperationSaysWhetherTheBinaryHasMLDSA(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no key file here")
	_, generateErr := GenerateKey(PurposeConnect, profile.PQPure)
	_, identityErr := GenerateIdentityKey(profile.PQPure, 0)
	_, loadErr := LoadKey(missing, PurposeConnect, profile.PQPure)
	checkErr := CheckPostQuantum()

	if strings.HasPrefix(fips140.Version(), "v1.0.") {
		for name, err := range map[string]error{
			"CheckPostQuantum":    checkErr,
			"GenerateKey":         generateErr,
			"GenerateIdentityKey": identityErr,
			"LoadKey":             loadErr,
		} {
			if !errors.Is(err, ErrPostQuantumUnavailable) {
				t.Errorf("%s with the module %s: %v, want ErrPostQuantumUnavailable", name, fips140.Version(), err)
			}
		}
		return
	}
	if checkErr != nil || generateErr != nil || identityErr != nil {
		t.Errorf("with the module %s: CheckPostQuantum %v, GenerateKey %v, GenerateIdentityKey %v, want no errors",
			fips140.Version(), checkErr, generateErr, identityErr)
	}
	if !errors.Is(loadErr, fs.ErrNotExist) {
		t.Errorf("LoadKey of a missing file with the module %s: %v, want it not found", fips140.Version(), loadErr)
	}
}
