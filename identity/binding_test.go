package identity

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"sync"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

const (
	bindingNow          = int64(1789000000000)
	minuteMs            = int64(60000)
	hourMs              = 60 * minuteMs
	dayMs               = 24 * hourMs
	tlsBindingLabel     = "MACULA-PQ-BINDING-TLS-V1"
	connectBindingLabel = "MACULA-PQ-BINDING-CONNECT-V1"
	statusLabel         = "MACULA-PQ-STATUS-V1"
)

var testLeaf = []byte("the strict DER leaf certificate this connection presented")

var (
	pureConnectKey   = sync.OnceValues(func() (*NodeKey, error) { return GenerateKey(PurposeConnect, profile.PQPure) })
	hybridConnectKey = sync.OnceValues(func() (*NodeKey, error) { return GenerateKey(PurposeConnect, profile.PQHybrid) })
)

// bindingKeys is a profile's identity key and CONNECT key.
type bindingKeys struct {
	identity *NodeKey
	connect  *NodeKey
}

func keysFor(t *testing.T, p profile.Profile) bindingKeys {
	t.Helper()
	if p == profile.PQPure {
		return bindingKeys{identity: sharedKey(t, pureIdentityKey), connect: sharedKey(t, pureConnectKey)}
	}
	return bindingKeys{identity: sharedKey(t, hybridIdentityKey), connect: sharedKey(t, hybridConnectKey)}
}

func forEachProfile(t *testing.T, run func(t *testing.T, p profile.Profile, keys bindingKeys)) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) { run(t, p, keysFor(t, p)) })
	}
}

// issued is the structure an issuing call returns, failing t on its error:
// issued(t)(TLSBinding(...)).
func issued(t *testing.T) func(SignedTBS, error) SignedTBS {
	t.Helper()
	return func(s SignedTBS, err error) SignedTBS {
		t.Helper()
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return s
	}
}

func withFlippedSignature(s SignedTBS) SignedTBS {
	return SignedTBS{TBS: s.TBS, Signature: flippedAt(s.Signature, 10)}
}

// checkRefusal fails t unless err is want, or nil when want is nil.
func checkRefusal(t *testing.T, name string, err, want error) {
	t.Helper()
	if want == nil && err != nil {
		t.Errorf("%s: %v, want it accepted", name, err)
	}
	if want != nil && !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", name, err, want)
	}
}

func TestATLSBindingVerifiesWithinItsValidityAndFiveMinutesOfTolerance(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		binding := issued(t)(TLSBinding(keys.identity, testLeaf, bindingNow, bindingNow+7*dayMs))
		public := keys.identity.PublicKey()
		nodeID, _ := keys.identity.NodeID()

		info, err := VerifyTLSBinding(binding, public, p, testLeaf, bindingNow+hourMs)
		if err != nil || info != (BindingInfo{Use: BindingTLS, NodeID: nodeID, NotAfter: bindingNow + 7*dayMs}) {
			t.Fatalf("VerifyTLSBinding = (%+v, %v), want the binding's use, node_id and not_after", info, err)
		}
		cases := []struct {
			name string
			leaf []byte
			now  int64
			want error
		}{
			{"4 minutes before not_before", testLeaf, bindingNow - 4*minuteMs, nil},
			{"4 minutes after not_after", testLeaf, bindingNow + 7*dayMs + 4*minuteMs, nil},
			{"6 minutes before not_before", testLeaf, bindingNow - 6*minuteMs, ErrBindingNotYetValid},
			{"6 minutes after not_after", testLeaf, bindingNow + 7*dayMs + 6*minuteMs, ErrBindingExpired},
			{"another leaf", []byte("another leaf"), bindingNow, ErrBindingKeyMismatch},
		}
		for _, c := range cases {
			_, err := VerifyTLSBinding(binding, public, p, c.leaf, c.now)
			checkRefusal(t, c.name, err, c.want)
		}
		_, err = VerifyTLSBinding(withFlippedSignature(binding), public, p, testLeaf, bindingNow)
		checkRefusal(t, "an altered signature", err, ErrBindingSignatureInvalid)
	})
}

// A binding for one use never verifies as the other, because its signature
// covers its own use's label.
func TestAConnectBindingVerifiesOnlyForItsKeyAndItsUse(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		public := keys.identity.PublicKey()
		connect := keys.connect.PublicKey()
		binding := issued(t)(ConnectBinding(keys.identity, connect, bindingNow, bindingNow+dayMs))

		info, err := VerifyConnectBinding(binding, public, p, connect, bindingNow)
		if err != nil || info.Use != BindingConnect || info.NotAfter != bindingNow+dayMs {
			t.Fatalf("VerifyConnectBinding = (%+v, %v), want a connect binding until not_after", info, err)
		}
		_, err = VerifyConnectBinding(binding, public, p, append(bytes.Clone(connect), 0), bindingNow)
		checkRefusal(t, "another CONNECT key", err, ErrBindingKeyMismatch)
		_, err = VerifyTLSBinding(binding, public, p, connect, bindingNow)
		checkRefusal(t, "a CONNECT binding verified as a TLS binding", err, ErrBindingSignatureInvalid)
	})
}

func TestAStatusStatementKeepsItsBindingInForceForAtMostAnHour(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		public := keys.identity.PublicKey()
		binding := issued(t)(TLSBinding(keys.identity, testLeaf, bindingNow, bindingNow+7*dayMs))
		other := issued(t)(TLSBinding(keys.identity, testLeaf, bindingNow, bindingNow+7*dayMs))
		status := issued(t)(StatusStatement(keys.identity, binding, bindingNow, bindingNow+hourMs))
		later := issued(t)(StatusStatement(keys.identity, binding, bindingNow+10*minuteMs, bindingNow+70*minuteMs))

		expiresAt, err := VerifyStatus(status, binding, public, p, bindingNow+10*minuteMs)
		if err != nil || expiresAt != bindingNow+hourMs {
			t.Fatalf("VerifyStatus = (%d, %v), want it to expire an hour after issue", expiresAt, err)
		}
		cases := []struct {
			name      string
			statement SignedTBS
			binding   SignedTBS
			now       int64
			want      error
		}{
			{"4 minutes after expiry", status, binding, bindingNow + hourMs + 4*minuteMs, nil},
			{"6 minutes after expiry", status, binding, bindingNow + hourMs + 6*minuteMs, ErrStatusExpired},
			{"issued 10 minutes ahead", later, binding, bindingNow, ErrStatusFutureDated},
			{"for another binding", status, other, bindingNow, ErrStatusBindingMismatch},
			{"an altered signature", withFlippedSignature(status), binding, bindingNow, ErrStatusSignatureInvalid},
		}
		for _, c := range cases {
			_, err := VerifyStatus(c.statement, c.binding, public, p, c.now)
			checkRefusal(t, c.name, err, c.want)
		}
	})
}

func TestASignedStructureIsExactlyTheMapOfItsTBSAndSignature(t *testing.T) {
	signed := SignedTBS{TBS: []byte{0xa0}, Signature: []byte{1, 2, 3}}
	parsed, err := ParseSignedTBS(signed.Value())
	if err != nil || !bytes.Equal(parsed.TBS, signed.TBS) || !bytes.Equal(parsed.Signature, signed.Signature) {
		t.Fatalf("ParseSignedTBS(Value()) = (%+v, %v), want the same structure back", parsed, err)
	}
	entry := func(key string, v cbor.Value) cbor.MapEntry { return cbor.MapEntry{Key: cbor.Text(key), Val: v} }
	tbs, signature := entry("tbs", cbor.Bytes(signed.TBS)), entry("signature", cbor.Bytes(signed.Signature))
	cases := []struct {
		name string
		v    cbor.Value
	}{
		{"no signature", cbor.Map([]cbor.MapEntry{tbs})},
		{"no tbs", cbor.Map([]cbor.MapEntry{signature})},
		{"an extra key", cbor.Map([]cbor.MapEntry{tbs, signature, entry("extra", cbor.Bytes(nil))})},
		{"a text tbs", cbor.Map([]cbor.MapEntry{entry("tbs", cbor.Text("a0")), signature})},
		{"an integer signature", cbor.Map([]cbor.MapEntry{tbs, entry("signature", cbor.Int(1))})},
		{"not a map", cbor.Bytes(signed.TBS)},
	}
	for _, c := range cases {
		_, err := ParseSignedTBS(c.v)
		checkRefusal(t, c.name, err, ErrMalformedFrame)
	}
}

// tbsFields is a TLS binding's fields, as a signer that follows the design
// writes them.
func tbsFields(keys bindingKeys, p profile.Profile) map[string]cbor.Value {
	nodeID, _ := keys.identity.NodeID()
	leafHash := sha512.Sum384(testLeaf)
	definition, _ := p.Definition()
	return map[string]cbor.Value{
		"label":        cbor.Text(tlsBindingLabel),
		"node_id":      cbor.Bytes(nodeID[:]),
		"use":          cbor.Text("tls"),
		"subject_hash": cbor.Bytes(leafHash[:]),
		"binding_id":   cbor.Bytes(make([]byte, 16)),
		"not_before":   cbor.Int(bindingNow),
		"not_after":    cbor.Int(bindingNow + dayMs),
		"hash_alg":     cbor.Text("SHA-384"),
		"sig_alg":      cbor.Text(definition.SigAlg),
	}
}

// withTBSField is fields with key set to v.
func withTBSField(fields map[string]cbor.Value, key string, v cbor.Value) map[string]cbor.Value {
	out := make(map[string]cbor.Value, len(fields)+1)
	for k, value := range fields {
		out[k] = value
	}
	out[key] = v
	return out
}

func encodedTBS(fields map[string]cbor.Value) []byte {
	entries := make([]cbor.MapEntry, 0, len(fields))
	for k, v := range fields {
		entries = append(entries, cbor.MapEntry{Key: cbor.Text(k), Val: v})
	}
	return cbor.Encode(cbor.Map(entries))
}

// withDuplicateUse is fields encoded with a second "use" key, which only a
// hand-built encoding can carry.
func withDuplicateUse(fields map[string]cbor.Value) []byte {
	out := []byte{0xa0 + byte(len(fields)+1)}
	for k, v := range fields {
		out = append(out, cbor.Encode(cbor.Text(k))...)
		out = append(out, cbor.Encode(v)...)
	}
	out = append(out, cbor.Encode(cbor.Text("use"))...)
	return append(out, cbor.Encode(cbor.Text("connect"))...)
}

func signedWith(t *testing.T, key *NodeKey, label string, tbs []byte) SignedTBS {
	t.Helper()
	signature, err := key.Sign(append(append([]byte(label), 0), tbs...))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return SignedTBS{TBS: tbs, Signature: signature}
}

// Structures the identity key signed, but that the design does not allow.
func TestSignedBindingsAndStatementsTheDesignDoesNotAllowAreRefused(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		public := keys.identity.PublicKey()
		fields := tbsFields(keys, p)
		sign := func(f map[string]cbor.Value) SignedTBS {
			return signedWith(t, keys.identity, tlsBindingLabel, encodedTBS(f))
		}
		verify := func(s SignedTBS) error {
			_, err := VerifyTLSBinding(s, public, p, testLeaf, bindingNow)
			return err
		}
		binding := issued(t)(TLSBinding(keys.identity, testLeaf, bindingNow, bindingNow+dayMs))
		nodeID, _ := keys.identity.NodeID()
		bindingHash := sha512.Sum384(binding.TBS)
		definition, _ := p.Definition()
		statusFields := map[string]cbor.Value{
			"label":        cbor.Text(statusLabel),
			"node_id":      cbor.Bytes(nodeID[:]),
			"binding_hash": cbor.Bytes(bindingHash[:]),
			"issued_at":    cbor.Int(bindingNow),
			"expires_at":   cbor.Int(bindingNow + hourMs),
			"sig_alg":      cbor.Text(definition.SigAlg),
		}
		verifyStatus := func(f map[string]cbor.Value) error {
			_, err := VerifyStatus(signedWith(t, keys.identity, statusLabel, encodedTBS(f)), binding, public, p, bindingNow)
			return err
		}

		cases := []struct {
			name string
			err  error
			want error
		}{
			{"the fields as the design writes them", verify(sign(fields)), nil},
			{"another node_id", verify(sign(withTBSField(fields, "node_id", cbor.Bytes(bytes.Repeat([]byte{1}, 32))))), ErrNodeIDMismatch},
			{"the connect use under the TLS label", verify(sign(withTBSField(fields, "use", cbor.Text("connect")))), ErrBindingWrongUse},
			{"an unknown key", verify(sign(withTBSField(fields, "comment", cbor.Text("x")))), ErrMalformedFrame},
			{"a window of 8 days", verify(sign(withTBSField(fields, "not_after", cbor.Int(bindingNow+8*dayMs)))), ErrMalformedFrame},
			{"a 32-byte subject hash", verify(sign(withTBSField(fields, "subject_hash", cbor.Bytes(make([]byte, 32))))), ErrMalformedFrame},
			{"another signature algorithm", verify(sign(withTBSField(fields, "sig_alg", cbor.Text("EdDSA")))), ErrMalformedFrame},
			{"a duplicate use key", verify(signedWith(t, keys.identity, tlsBindingLabel, withDuplicateUse(fields))), ErrMalformedFrame},
			{"binding times at 2^53", verify(sign(withTBSField(withTBSField(fields, "not_before", cbor.Int(1<<53)), "not_after", cbor.Int(1<<53+dayMs)))), ErrMalformedFrame},
			{"the status as the design writes it", verifyStatus(statusFields), nil},
			{"a statement valid for 2 hours", verifyStatus(withTBSField(statusFields, "expires_at", cbor.Int(bindingNow+2*hourMs))), ErrMalformedFrame},
			{"statement times at 2^53", verifyStatus(withTBSField(withTBSField(statusFields, "issued_at", cbor.Int(1<<53)), "expires_at", cbor.Int(1<<53+minuteMs))), ErrMalformedFrame},
		}
		for _, c := range cases {
			checkRefusal(t, c.name, c.err, c.want)
		}
	})
}

// Nothing is issued that a verifier would refuse for its shape.
func TestBindingsAndStatementsAreIssuedOnlyWithinTheirLimits(t *testing.T) {
	keys := keysFor(t, profile.PQPure)
	binding := issued(t)(TLSBinding(keys.identity, testLeaf, bindingNow, bindingNow+dayMs))
	_, connectIssuer := ConnectBinding(keys.connect, keys.connect.PublicKey(), bindingNow, bindingNow+dayMs)
	_, backwards := TLSBinding(keys.identity, testLeaf, bindingNow, bindingNow-1)
	_, tooLong := TLSBinding(keys.identity, testLeaf, bindingNow, bindingNow+7*dayMs+1)
	_, negative := TLSBinding(keys.identity, testLeaf, -1, bindingNow)
	_, tooLate := TLSBinding(keys.identity, testLeaf, 1<<53, 1<<53+dayMs)
	_, statusTooLong := StatusStatement(keys.identity, binding, bindingNow, bindingNow+hourMs+1)
	_, statusIssuer := StatusStatement(keys.connect, binding, bindingNow, bindingNow+hourMs)
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"a binding signed by a CONNECT key", connectIssuer, ErrNotAnIdentityKey},
		{"not_after before not_before", backwards, ErrValidityWindow},
		{"a binding valid for 7 days and a millisecond", tooLong, ErrValidityWindow},
		{"a negative not_before", negative, ErrValidityWindow},
		{"binding times at 2^53", tooLate, ErrValidityWindow},
		{"a statement valid for an hour and a millisecond", statusTooLong, ErrValidityWindow},
		{"a statement signed by a CONNECT key", statusIssuer, ErrNotAnIdentityKey},
	}
	for _, c := range cases {
		checkRefusal(t, c.name, c.err, c.want)
	}
}
