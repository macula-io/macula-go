// Package wire10vectors reads macula's wire 1.0 conformance vectors
// (priv/vectors/wire_1_0, macula#97), which scripts/interop/copy_wire_1_0_vectors.sh
// copies into testdata/wire_1_0 pinned by macula commit, for the runners each
// package holds itself to: every stack runs the same cases and must agree on
// every verdict (macula docs/design/WIRE_1_0.md section 9).
package wire10vectors

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// File is one class's vector file.
type File struct {
	Wire   string `json:"wire"`
	Class  string `json:"class"`
	Format int    `json:"format"`
	Cases  []Case `json:"cases"`
}

// Case is one vector: what goes in and the verdict every stack must reach.
type Case struct {
	ID        string         `json:"id"`
	Profile   string         `json:"profile"`
	Covers    []string       `json:"covers"`
	LandsWith []string       `json:"lands_with"`
	Input     map[string]any `json:"input"`
	Expect    map[string]any `json:"expect"`
}

// Dir is testdata/wire_1_0 at the module root.
func Dir() string {
	_, here, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(here), "..", "..", "testdata", "wire_1_0")
}

// Load reads one class's file, refusing one of another wire, class or format.
func Load(class string) (File, error) {
	data, err := os.ReadFile(filepath.Join(Dir(), class+".json"))
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("%s.json: %w", class, err)
	}
	if f.Wire != "1.0" || f.Class != class || f.Format != 1 {
		return File{}, fmt.Errorf("%s.json: wire %q class %q format %d, want 1.0 %s 1", class, f.Wire, f.Class, f.Format, class)
	}
	return f, nil
}

// Hex is the input field name, hex-decoded.
func (c Case) Hex(name string) ([]byte, error) {
	s, ok := c.Input[name].(string)
	if !ok {
		return nil, fmt.Errorf("%s: no input %s", c.ID, name)
	}
	return hex.DecodeString(s)
}

// Text is the input field name as text, "" when absent.
func (c Case) Text(name string) string {
	s, _ := c.Input[name].(string)
	return s
}

// Int is the input field name as an integer, 0 when absent.
func (c Case) Int(name string) int64 {
	n, _ := c.Input[name].(float64)
	return int64(n)
}

// Outcome is the expected outcome: accept, refuse, ignore, fallback, store or
// abort_stream.
func (c Case) Outcome() string { s, _ := c.Expect["outcome"].(string); return s }

// Reason is the expected refusal name, "" when none.
func (c Case) Reason() string { s, _ := c.Expect["reason"].(string); return s }

// ExpectText is the expect field name as text, "" when absent.
func (c Case) ExpectText(name string) string { s, _ := c.Expect[name].(string); return s }

// ExpectInt is the expect field name as an integer, 0 when absent.
func (c Case) ExpectInt(name string) int64 { n, _ := c.Expect[name].(float64); return int64(n) }

// Keys is keys.json: the fixed public keys, per profile and role, in carried
// form, with their key ids.
type Keys struct {
	Profiles map[string]map[string]struct {
		Key   string `json:"key"`
		KeyID string `json:"key_id"`
	} `json:"profiles"`
}

// LoadKeys reads keys.json.
func LoadKeys() (Keys, error) {
	data, err := os.ReadFile(filepath.Join(Dir(), "keys.json"))
	if err != nil {
		return Keys{}, err
	}
	var k Keys
	if err := json.Unmarshal(data, &k); err != nil {
		return Keys{}, fmt.Errorf("keys.json: %w", err)
	}
	return k, nil
}

// KeyID is the key id of a profile's role (station_identity, client_identity,
// client_connect, org, ...).
func (k Keys) KeyID(profile, role string) ([32]byte, error) {
	var id [32]byte
	b, err := hex.DecodeString(k.Profiles[profile][role].KeyID)
	if err != nil || len(b) != len(id) {
		return id, fmt.Errorf("keys.json: no key id for %s %s", profile, role)
	}
	copy(id[:], b)
	return id, nil
}

// Key is the carried-form public key of a profile's role.
func (k Keys) Key(profile, role string) ([]byte, error) {
	b, err := hex.DecodeString(k.Profiles[profile][role].Key)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("keys.json: no key for %s %s", profile, role)
	}
	return b, nil
}
