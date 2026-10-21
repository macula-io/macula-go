package group

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/ucan"
)

// The vectors are macula's test/vectors/e2e_seal_v1_group_keys.json, copied
// by scripts/interop/copy_group_keys_vectors.sh: the group_keys_v1 CALL and
// RESULT payloads as macula encodes them, and the org's group_keys grants
// with the verdict macula_ucan:authorize/3 reaches on each. Every byte and
// every verdict here must be macula's.

type vectorEpoch struct {
	ID           string `json:"id"`
	Key          string `json:"key"`
	IssuedAt     int64  `json:"issued_at"`
	PublishUntil int64  `json:"publish_until"`
	AcceptUntil  int64  `json:"accept_until"`
}

type vectorFile struct {
	Payloads struct {
		CallCurrent struct {
			CBOR   string `json:"cbor"`
			Prefix string `json:"prefix"`
		} `json:"call_current"`
		CallByID struct {
			CBOR    string `json:"cbor"`
			Prefix  string `json:"prefix"`
			EpochID string `json:"epoch_id"`
		} `json:"call_by_id"`
		Result struct {
			CBOR   string        `json:"cbor"`
			Prefix string        `json:"prefix"`
			Policy string        `json:"policy"`
			Epochs []vectorEpoch `json:"epochs"`
		} `json:"result"`
	} `json:"payloads"`
	Profiles map[string]struct {
		Cases []vectorGrant `json:"cases"`
	} `json:"profiles"`
	Refusals []string `json:"refusals"`
}

// vectorGrant is one org's group_keys grant and the verdict macula reaches on
// it.
type vectorGrant struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Policy struct {
		Kind  string `json:"kind"`
		KeyID string `json:"key_id"`
		Can   string `json:"can"`
	} `json:"policy"`
	Context struct {
		Caller    string `json:"caller"`
		Now       int64  `json:"now"`
		Realm     string `json:"realm"`
		Procedure string `json:"procedure"`
	} `json:"context"`
	Verdict string `json:"verdict"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "e2e_seal_v1_group_keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Profiles) != 2 || len(v.Payloads.Result.Epochs) == 0 {
		t.Fatalf("vectors hold %d profiles and %d epochs", len(v.Profiles), len(v.Payloads.Result.Epochs))
	}
	return v
}

func unhex(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("%q is not hex", text)
	}
	return b
}

func TestVectorsCallPayloads(t *testing.T) {
	v := loadVectors(t)
	current := v.Payloads.CallCurrent
	if got := cbor.Encode(CurrentRequest(current.Prefix)); !bytes.Equal(got, unhex(t, current.CBOR)) {
		t.Fatalf("call_current %x, macula's %s", got, current.CBOR)
	}
	byID := v.Payloads.CallByID
	if got := cbor.Encode(ByIDRequest(byID.Prefix, [IDSize]byte(unhex(t, byID.EpochID)))); !bytes.Equal(got, unhex(t, byID.CBOR)) {
		t.Fatalf("call_by_id %x, macula's %s", got, byID.CBOR)
	}
}

func TestVectorsResultPayload(t *testing.T) {
	r := loadVectors(t).Payloads.Result
	decoded, err := cbor.Decode(unhex(t, r.CBOR))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := ParseReply(r.Prefix, decoded)
	if err != nil {
		t.Fatalf("macula's result does not parse: %v", err)
	}
	if reply.Policy != Policy(r.Policy) || len(reply.Epochs) != len(r.Epochs) {
		t.Fatalf("parsed policy %s and %d epochs, macula's %s and %d", reply.Policy, len(reply.Epochs), r.Policy, len(r.Epochs))
	}
	for i, want := range r.Epochs {
		got := reply.Epochs[i]
		if hex.EncodeToString(got.ID[:]) != want.ID || hex.EncodeToString(got.Key[:]) != want.Key ||
			got.IssuedAt != want.IssuedAt || got.PublishUntil != want.PublishUntil || got.AcceptUntil != want.AcceptUntil {
			t.Fatalf("epoch %d parsed as %+v, macula's %+v", i, got, want)
		}
	}
	if got := cbor.Encode(ReplyValue(reply)); !bytes.Equal(got, unhex(t, r.CBOR)) {
		t.Fatalf("result re-encoded as %x, macula's %s", got, r.CBOR)
	}
	if _, err := ParseReply("io.macula/other/chat", decoded); err != ErrMalformedReply {
		t.Fatalf("a reply echoing another prefix: %v", err)
	}
}

func TestVectorsOrgGrantsAuthorizeAsMacula(t *testing.T) {
	v := loadVectors(t)
	for name, p := range v.Profiles {
		prof, err := profile.Parse(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range p.Cases {
			t.Run(name+"/"+c.Name, func(t *testing.T) { assertGrantAuthorizesAsMacula(t, prof, c) })
		}
	}
}

// assertGrantAuthorizesAsMacula checks the org's grant, under its realm member
// policy, reaches macula's verdict: granted, or the refusal macula names.
func assertGrantAuthorizesAsMacula(t *testing.T, prof profile.Profile, c vectorGrant) {
	t.Helper()
	if c.Policy.Kind != "realm_member_required" {
		t.Fatalf("a policy of kind %q", c.Policy.Kind)
	}
	policy := ucan.RealmMemberRequired{KeyID: [32]byte(unhex(t, c.Policy.KeyID)), Can: c.Policy.Can}
	ctx := ucan.Context{Caller: [32]byte(unhex(t, c.Context.Caller)), Profile: prof, Now: c.Context.Now,
		Proofs:  map[string][]byte{},
		Request: &ucan.Request{Realm: [32]byte(unhex(t, c.Context.Realm)), Procedure: c.Context.Procedure}}
	_, err := ucan.Authorize([]byte(c.Token), policy, ctx)
	got := "ok"
	if err != nil {
		got = ucan.RefusalName(err)
	}
	if got != c.Verdict {
		t.Fatalf("verdict %s (%v), macula's is %s", got, err, c.Verdict)
	}
}

func TestVectorsRefusalsAreTheClosedSet(t *testing.T) {
	for _, name := range loadVectors(t).Refusals {
		if _, known := refusals[name]; !known {
			t.Fatalf("macula refuses a pull as %q, which the keyring does not read", name)
		}
	}
}
