package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// hexBytes is bytes written as hex in JSON.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	*h = b
	return err
}

type hexSignedTBS struct {
	TBS       hexBytes `json:"tbs"`
	Signature hexBytes `json:"signature"`
}

func (h hexSignedTBS) signed() SignedTBS {
	return SignedTBS{TBS: h.TBS, Signature: h.Signature}
}

// erlangBindings is testdata/erlang_bindings.json: TLS and CONNECT bindings and
// their status statements, made at fixed times by macula's own
// macula_key_bindings and macula_node_keys, in both profiles.
type erlangBindings struct {
	Generator string `json:"generator"`
	Entries   []struct {
		Profile        string       `json:"profile"`
		NowMs          int64        `json:"now_ms"`
		IdentityKey    hexBytes     `json:"identity_key"`
		NodeID         hexBytes     `json:"node_id"`
		Leaf           hexBytes     `json:"leaf"`
		TLSBinding     hexSignedTBS `json:"tls_binding"`
		TLSStatus      hexSignedTBS `json:"tls_status"`
		ConnectKey     hexBytes     `json:"connect_key"`
		ConnectBinding hexSignedTBS `json:"connect_binding"`
		ConnectStatus  hexSignedTBS `json:"connect_status"`
	} `json:"entries"`
}

func otherProfile(p profile.Profile) profile.Profile {
	if p == profile.PQPure {
		return profile.PQHybrid
	}
	return profile.PQPure
}

// Bindings and statements macula made verify here as they verify there, are
// refused where macula refuses them, and carry tbs bytes this package's
// encoder writes byte for byte.
func TestBindingsAndStatementsMadeByMaculaVerify(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "erlang_bindings.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc erlangBindings
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Entries) != 2 {
		t.Fatalf("%d entries, want one per profile", len(doc.Entries))
	}
	for _, e := range doc.Entries {
		t.Run(e.Profile, func(t *testing.T) {
			p, err := profile.Parse(e.Profile)
			if err != nil {
				t.Fatalf("profile: %v", err)
			}
			if nodeID := NodeIDOf(e.IdentityKey, p); !bytes.Equal(nodeID[:], e.NodeID) {
				t.Errorf("node_id %x, macula derived %x", nodeID, []byte(e.NodeID))
			}
			tls, connect := e.TLSBinding.signed(), e.ConnectBinding.signed()
			for name, tbs := range map[string][]byte{
				"TLS binding": tls.TBS, "TLS status": e.TLSStatus.TBS,
				"CONNECT binding": connect.TBS, "CONNECT status": e.ConnectStatus.TBS,
			} {
				if v, err := cbor.Decode(tbs); err != nil || !bytes.Equal(cbor.Encode(v), tbs) {
					t.Errorf("%s: macula's tbs does not re-encode to the same bytes here (%v)", name, err)
				}
			}

			info, err := VerifyTLSBinding(tls, e.IdentityKey, p, e.Leaf, e.NowMs)
			if err != nil || !bytes.Equal(info.NodeID[:], e.NodeID) || info.NotAfter != e.NowMs+7*dayMs {
				t.Errorf("TLS binding: (%+v, %v), want it verified for macula's node_id until 7 days on", info, err)
			}
			_, err = VerifyStatus(e.TLSStatus.signed(), tls, e.IdentityKey, p, e.NowMs)
			checkRefusal(t, "the TLS status", err, nil)
			_, err = VerifyConnectBinding(connect, e.IdentityKey, p, e.ConnectKey, e.NowMs)
			checkRefusal(t, "the CONNECT binding", err, nil)
			_, err = VerifyStatus(e.ConnectStatus.signed(), connect, e.IdentityKey, p, e.NowMs)
			checkRefusal(t, "the CONNECT status", err, nil)

			_, err = VerifyTLSBinding(tls, e.IdentityKey, p, append(bytes.Clone(e.Leaf), 0), e.NowMs)
			checkRefusal(t, "the TLS binding for another leaf", err, ErrBindingKeyMismatch)
			_, err = VerifyTLSBinding(connect, e.IdentityKey, p, e.ConnectKey, e.NowMs)
			checkRefusal(t, "the CONNECT binding as a TLS binding", err, ErrBindingSignatureInvalid)
			_, err = VerifyStatus(e.TLSStatus.signed(), connect, e.IdentityKey, p, e.NowMs)
			checkRefusal(t, "the TLS status for the CONNECT binding", err, ErrStatusBindingMismatch)
			_, err = VerifyTLSBinding(tls, e.IdentityKey, otherProfile(p), e.Leaf, e.NowMs)
			checkRefusal(t, "the TLS binding under the other profile", err, ErrBindingSignatureInvalid)
			_, err = VerifyTLSBinding(tls, e.IdentityKey, p, e.Leaf, e.NowMs+7*dayMs+6*minuteMs)
			checkRefusal(t, "the TLS binding 7 days and 6 minutes on", err, ErrBindingExpired)
		})
	}
}
