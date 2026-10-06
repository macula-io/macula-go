package record

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// realmMemberEndorsementVectors is macula's
// test/vectors/realm_member_endorsement_v1.json (sha256
// 9989f9cd7d154af25b959ea6c7b068be8818175e6792f16d12cf1992f7163a4f), copied
// into testdata by scripts/interop/copy_realm_member_endorsement_vectors.sh:
// endorsements a realm key signed, thirteen per profile, each with the member
// and the time macula_hyparview_endorsement:verify_endorsement/4 checked it for
// and its verdict, the endorsed roles or the refusal's name. Signing is
// randomized, so the committed file is the vector.
type realmMemberEndorsementVectors struct {
	Realm    string `json:"realm"`
	Profiles map[string]struct {
		RealmKey string `json:"realm_key"`
		Cases    []struct {
			Name    string   `json:"name"`
			Record  string   `json:"record"`
			Member  string   `json:"member"`
			NowMs   int64    `json:"now_ms"`
			Roles   []string `json:"roles"`
			Refused string   `json:"refused"`
		} `json:"cases"`
	} `json:"profiles"`
}

// refusalNames is each refusal by the name macula gives it.
var refusalNames = map[string]error{
	"not_yet_valid":               ErrNotYetValid,
	"expired":                     ErrExpired,
	"endorsement_expired":         ErrEndorsementExpired,
	"wrong_member":                ErrWrongMember,
	"wrong_realm":                 ErrWrongRealm,
	"untrusted_signer":            ErrUntrustedSigner,
	"wrong_type":                  ErrWrongType,
	"endorsement_window_too_long": ErrEndorsementWindowTooLong,
	"endorsement_window_reversed": ErrEndorsementWindowReversed,
	"malformed":                   ErrMalformed,
}

// TestRealmMemberEndorsementVectors holds VerifyRealmMemberEndorsement to
// macula's verify_endorsement/4 on every case: the same roles where macula
// admits, the same refusal where it refuses.
func TestRealmMemberEndorsementVectors(t *testing.T) {
	vectors := readEndorsementVectors(t)
	realm := id32(t, vectors.Realm)
	cases := 0
	for name, p := range vectors.Profiles {
		trust := Trust{Profile: profile.Profile(name), RealmKey: decodeHex(t, p.RealmKey)}
		for _, c := range p.Cases {
			cases++
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				roles, err := VerifyRealmMemberEndorsement(decodeHex(t, c.Record), trust, realm, id32(t, c.Member), c.NowMs)
				if c.Refused == "" {
					if err != nil || !slices.Equal(roles, c.Roles) {
						t.Fatalf("got %v, %v; macula admits with roles %v", roles, err, c.Roles)
					}
					return
				}
				want, named := refusalNames[c.Refused]
				if !named {
					t.Fatalf("macula refuses %s, a name this test does not map", c.Refused)
				}
				if !errors.Is(err, want) || roles != nil {
					t.Fatalf("got %v, %v; macula refuses %s", roles, err, c.Refused)
				}
			})
		}
	}
	if cases != 26 {
		t.Errorf("%d cases, want 13 per profile", cases)
	}
}

// An endorsement checked without a realm key is refused by name, not taken
// as signed by no one.
func TestAnEndorsementNeedsTheRealmKey(t *testing.T) {
	vectors := readEndorsementVectors(t)
	p := vectors.Profiles[string(profile.PQPure)]
	c := p.Cases[0]
	_, err := VerifyRealmMemberEndorsement(decodeHex(t, c.Record), Trust{Profile: profile.PQPure},
		id32(t, vectors.Realm), id32(t, c.Member), c.NowMs)
	if !errors.Is(err, ErrNoRealmKey) {
		t.Fatalf("got %v, want ErrNoRealmKey", err)
	}
}

// The trusted realm key is compared by its key id, as macula's trust holds it.
func TestTheVectorRealmKeyIsTheEndorsementsSigner(t *testing.T) {
	vectors := readEndorsementVectors(t)
	for name, p := range vectors.Profiles {
		verified, err := Verify(decodeHex(t, p.Cases[0].Record), profile.Profile(name), p.Cases[0].NowMs)
		if err != nil {
			t.Fatalf("%s: Verify: %v", name, err)
		}
		if got := verified.Record().KeyID; got != identity.KeyIDOf(decodeHex(t, p.RealmKey), profile.Profile(name)) {
			t.Errorf("%s: the record's key id %x is not the realm key's", name, got)
		}
	}
}

func readEndorsementVectors(t *testing.T) realmMemberEndorsementVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "realm_member_endorsement_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors realmMemberEndorsementVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func id32(t *testing.T, s string) [32]byte {
	t.Helper()
	var id [32]byte
	if copy(id[:], decodeHex(t, s)) != 32 {
		t.Fatalf("%s is not 32 bytes", s)
	}
	return id
}

// A window from -2^63 to 2^63-1 is far over 30 days. Its length overflows
// int64, so it must be refused by its own name rather than wrap to a negative
// length and admit at every time, as macula's bignum arithmetic refuses it.
func TestAWindowWhoseLengthOverflowsIsTooLong(t *testing.T) {
	realmKey := authorizationKeysFor(t).realm
	realm, member := [32]byte{1}, [32]byte{2}
	payload := cbor.Map([]cbor.MapEntry{
		bytesEntry("realm_id", realm[:]),
		bytesEntry("member_node", member[:]),
		valueEntry("roles", cbor.List([]cbor.Value{cbor.Text("peer")})),
		valueEntry("valid_from", cbor.NegInt(math.MaxInt64)),
		valueEntry("valid_until", cbor.Int(math.MaxInt64)),
	})
	now := nowMs()
	wire := signedByHand(t, label, recordFields(t, TypeRealmMemberEndorsement, payload, now, testHour), realmKey)
	trust := Trust{Profile: realmKey.Profile(), RealmKey: realmKey.PublicKey()}
	if roles, err := VerifyRealmMemberEndorsement(wire, trust, realm, member, now); !errors.Is(err, ErrEndorsementWindowTooLong) {
		t.Fatalf("got %v, %v; want ErrEndorsementWindowTooLong", roles, err)
	}
}
