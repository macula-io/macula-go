package identity

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// BindingUse is what a binding binds to the identity key: the TLS key of a
// leaf certificate, or a CONNECT key.
type BindingUse string

const (
	// BindingTLS binds a station's TLS key, by the leaf certificate it
	// presents.
	BindingTLS BindingUse = "tls"
	// BindingConnect binds a CONNECT key.
	BindingConnect BindingUse = "connect"
)

const (
	labelBindingTLS     = "MACULA-PQ-BINDING-TLS-V1"
	labelBindingConnect = "MACULA-PQ-BINDING-CONNECT-V1"
	labelStatus         = "MACULA-PQ-STATUS-V1"
	maxBindingMs        = 7 * 24 * 60 * 60 * 1000
	maxStatusMs         = 60 * 60 * 1000
	toleranceMs         = 5 * 60 * 1000
	maxProtocolInt      = 1 << 53
)

var (
	bindingFieldNames = []string{"label", "node_id", "use", "subject_hash", "binding_id", "not_before", "not_after", "hash_alg", "sig_alg"}
	statusFieldNames  = []string{"label", "node_id", "binding_hash", "issued_at", "expires_at", "sig_alg"}
)

// The refusals of the binding and status checks, named as macula names them.
var (
	// ErrMalformedFrame is a signed structure of the wrong shape: not exactly
	// {tbs, signature}, or a tbs that the decoding rule refuses, with a key
	// its structure does not define, or a field of the wrong type, length or
	// range.
	ErrMalformedFrame = errors.New("identity: malformed signed structure")
	// ErrBindingSignatureInvalid is a binding whose signature does not verify
	// under its use's label.
	ErrBindingSignatureInvalid = errors.New("identity: the binding's signature does not verify")
	// ErrBindingWrongUse is a binding whose label or use is another use's.
	ErrBindingWrongUse = errors.New("identity: the binding is for another use")
	// ErrBindingKeyMismatch is a binding whose subject is not the leaf or
	// CONNECT key it came with.
	ErrBindingKeyMismatch = errors.New("identity: the binding binds another key")
	// ErrBindingExpired is a binding more than 5 minutes past its not_after.
	ErrBindingExpired = errors.New("identity: the binding has expired")
	// ErrBindingNotYetValid is a binding more than 5 minutes before its
	// not_before.
	ErrBindingNotYetValid = errors.New("identity: the binding is not valid yet")
	// ErrNodeIDMismatch is a binding or statement that names a node_id other
	// than the one derived from the identity key.
	ErrNodeIDMismatch = errors.New("identity: the structure names another node_id")
	// ErrStatusSignatureInvalid is a status statement whose signature does not
	// verify.
	ErrStatusSignatureInvalid = errors.New("identity: the status statement's signature does not verify")
	// ErrStatusBindingMismatch is a status statement for another binding.
	ErrStatusBindingMismatch = errors.New("identity: the status statement is for another binding")
	// ErrStatusExpired is a status statement more than 5 minutes past its
	// expiry.
	ErrStatusExpired = errors.New("identity: the status statement has expired")
	// ErrStatusFutureDated is a status statement issued more than 5 minutes
	// ahead.
	ErrStatusFutureDated = errors.New("identity: the status statement is dated in the future")
	// ErrValidityWindow is a binding or statement whose times a verifier would
	// refuse: negative, backwards, at 2^53 or later, or longer than 7 days for a
	// binding and an hour for a statement.
	ErrValidityWindow = errors.New("identity: a validity period outside what a verifier accepts")
)

// SignedTBS is a signed structure as it travels: tbs, the deterministic CBOR
// of its fields, and a signature over its label, a zero byte and tbs. A
// verifier checks the signature over the tbs bytes it received, and only then
// decodes them.
type SignedTBS struct {
	TBS       []byte
	Signature []byte
}

// BindingInfo is what a verified binding says.
type BindingInfo struct {
	Use      BindingUse
	NodeID   [32]byte
	NotAfter int64
}

// Value is s as the map {tbs, signature}.
func (s SignedTBS) Value() cbor.Value {
	return cbor.Map([]cbor.MapEntry{bytesEntry("tbs", s.TBS), bytesEntry("signature", s.Signature)})
}

// ParseSignedTBS is the signed structure in v, which must be a map of exactly
// tbs and signature, both byte strings, or ErrMalformedFrame.
func ParseSignedTBS(v cbor.Value) (SignedTBS, error) {
	entries, isMap := v.AsMap()
	tbs, tbsOK := fieldBytes(v, "tbs")
	signature, signatureOK := fieldBytes(v, "signature")
	if !isMap || len(entries) != 2 || !tbsOK || !signatureOK {
		return SignedTBS{}, ErrMalformedFrame
	}
	return SignedTBS{TBS: tbs, Signature: signature}, nil
}

// TLSBinding binds the TLS key of the leaf certificate a listener presents to
// identityKey, by the SHA-384 of the leaf's DER, from notBefore to notAfter in
// milliseconds.
func TLSBinding(identityKey *NodeKey, leafDER []byte, notBefore, notAfter int64) (SignedTBS, error) {
	return issueBinding(identityKey, BindingTLS, labelBindingTLS, sha512.Sum384(leafDER), notBefore, notAfter)
}

// ConnectBinding binds a CONNECT key to identityKey, by the SHA-384 of the key
// as carried, from notBefore to notAfter in milliseconds.
func ConnectBinding(identityKey *NodeKey, connectKey []byte, notBefore, notAfter int64) (SignedTBS, error) {
	return issueBinding(identityKey, BindingConnect, labelBindingConnect, sha512.Sum384(connectKey), notBefore, notAfter)
}

func issueBinding(identityKey *NodeKey, use BindingUse, label string, subjectHash [48]byte, notBefore, notAfter int64) (SignedTBS, error) {
	nodeID, err := identityKey.NodeID()
	if err != nil {
		return SignedTBS{}, err
	}
	if !withinWindow(notBefore, notAfter, maxBindingMs) {
		return SignedTBS{}, fmt.Errorf("%w: a binding from %d to %d", ErrValidityWindow, notBefore, notAfter)
	}
	bindingID := make([]byte, 16)
	if _, err := rand.Read(bindingID); err != nil {
		return SignedTBS{}, fmt.Errorf("identity: binding id: %w", err)
	}
	tbs := cbor.Encode(cbor.Map([]cbor.MapEntry{
		textEntry("label", label),
		bytesEntry("node_id", nodeID[:]),
		textEntry("use", string(use)),
		bytesEntry("subject_hash", subjectHash[:]),
		bytesEntry("binding_id", bindingID),
		intEntry("not_before", notBefore),
		intEntry("not_after", notAfter),
		textEntry("hash_alg", "SHA-384"),
		textEntry("sig_alg", sigAlg(identityKey.profile)),
	}))
	return signTBS(identityKey, label, tbs)
}

// StatusStatement keeps binding in force from issuedAt to expiresAt in
// milliseconds, at most an hour, signed by identityKey.
func StatusStatement(identityKey *NodeKey, binding SignedTBS, issuedAt, expiresAt int64) (SignedTBS, error) {
	nodeID, err := identityKey.NodeID()
	if err != nil {
		return SignedTBS{}, err
	}
	if !withinWindow(issuedAt, expiresAt, maxStatusMs) {
		return SignedTBS{}, fmt.Errorf("%w: a statement from %d to %d", ErrValidityWindow, issuedAt, expiresAt)
	}
	bindingHash := sha512.Sum384(binding.TBS)
	tbs := cbor.Encode(cbor.Map([]cbor.MapEntry{
		textEntry("label", labelStatus),
		bytesEntry("node_id", nodeID[:]),
		bytesEntry("binding_hash", bindingHash[:]),
		intEntry("issued_at", issuedAt),
		intEntry("expires_at", expiresAt),
		textEntry("sig_alg", sigAlg(identityKey.profile)),
	}))
	return signTBS(identityKey, labelStatus, tbs)
}

// VerifyTLSBinding checks binding against the identity key as carried, under
// profile p, and the leaf certificate this connection presented, at nowMs with
// 5 minutes of tolerance.
func VerifyTLSBinding(binding SignedTBS, identityKey []byte, p profile.Profile, leafDER []byte, nowMs int64) (BindingInfo, error) {
	return verifyBinding(binding, identityKey, p, BindingTLS, labelBindingTLS, sha512.Sum384(leafDER), nowMs)
}

// VerifyConnectBinding checks binding against the identity key as carried,
// under profile p, and the CONNECT key as carried, at nowMs with 5 minutes of
// tolerance.
func VerifyConnectBinding(binding SignedTBS, identityKey []byte, p profile.Profile, connectKey []byte, nowMs int64) (BindingInfo, error) {
	return verifyBinding(binding, identityKey, p, BindingConnect, labelBindingConnect, sha512.Sum384(connectKey), nowMs)
}

// bindingTBS is a binding's fields, once they are well formed.
type bindingTBS struct {
	label       string
	use         string
	nodeID      [32]byte
	subjectHash [48]byte
	notBefore   int64
	notAfter    int64
}

// verifyBinding checks the signature over the tbs bytes as received first, then
// decodes them, then checks them in macula's order: shape, use, node_id,
// subject, not_before, not_after.
func verifyBinding(b SignedTBS, identityKey []byte, p profile.Profile, use BindingUse, label string, subjectHash [48]byte, nowMs int64) (BindingInfo, error) {
	if !Verify(labelled(label, b.TBS), b.Signature, identityKey, p) {
		return BindingInfo{}, ErrBindingSignatureInvalid
	}
	fields, decoded := decodeTBS(b.TBS, bindingFieldNames)
	parsed, wellFormed := wellFormedBinding(fields, p)
	switch {
	case !decoded || !wellFormed:
		return BindingInfo{}, ErrMalformedFrame
	case parsed.label != label || parsed.use != string(use):
		return BindingInfo{}, ErrBindingWrongUse
	case parsed.nodeID != NodeIDOf(identityKey, p):
		return BindingInfo{}, ErrNodeIDMismatch
	case parsed.subjectHash != subjectHash:
		return BindingInfo{}, ErrBindingKeyMismatch
	case nowMs+toleranceMs < parsed.notBefore:
		return BindingInfo{}, ErrBindingNotYetValid
	case nowMs-toleranceMs > parsed.notAfter:
		return BindingInfo{}, ErrBindingExpired
	}
	return BindingInfo{Use: use, NodeID: parsed.nodeID, NotAfter: parsed.notAfter}, nil
}

func wellFormedBinding(f map[string]cbor.Value, p profile.Profile) (bindingTBS, bool) {
	label, labelOK := f["label"].AsText()
	use, useOK := f["use"].AsText()
	nodeID, nodeIDOK := fieldArray32(f["node_id"])
	subjectHash, subjectOK := fieldArray48(f["subject_hash"])
	bindingID, bindingIDOK := f["binding_id"].AsBytes()
	notBefore, notBeforeOK := protocolInt(f["not_before"])
	notAfter, notAfterOK := protocolInt(f["not_after"])
	hashAlg, hashAlgOK := f["hash_alg"].AsText()
	signatureAlg, sigAlgOK := f["sig_alg"].AsText()
	wellFormed := labelOK && useOK && nodeIDOK && subjectOK && bindingIDOK && len(bindingID) == 16 &&
		notBeforeOK && notAfterOK && withinWindow(notBefore, notAfter, maxBindingMs) &&
		hashAlgOK && hashAlg == "SHA-384" && sigAlgOK && signatureAlg == sigAlg(p)
	return bindingTBS{label: label, use: use, nodeID: nodeID, subjectHash: subjectHash, notBefore: notBefore, notAfter: notAfter}, wellFormed
}

// statusTBS is a status statement's fields, once they are well formed.
type statusTBS struct {
	nodeID      [32]byte
	bindingHash [48]byte
	issuedAt    int64
	expiresAt   int64
}

// VerifyStatus checks a status statement for the binding it came with, against
// the identity key as carried, under profile p, at nowMs with 5 minutes of
// tolerance, and returns when the statement expires.
func VerifyStatus(statement, binding SignedTBS, identityKey []byte, p profile.Profile, nowMs int64) (int64, error) {
	if !Verify(labelled(labelStatus, statement.TBS), statement.Signature, identityKey, p) {
		return 0, ErrStatusSignatureInvalid
	}
	fields, decoded := decodeTBS(statement.TBS, statusFieldNames)
	parsed, wellFormed := wellFormedStatus(fields, p)
	switch {
	case !decoded || !wellFormed:
		return 0, ErrMalformedFrame
	case parsed.nodeID != NodeIDOf(identityKey, p):
		return 0, ErrNodeIDMismatch
	case parsed.bindingHash != sha512.Sum384(binding.TBS):
		return 0, ErrStatusBindingMismatch
	case parsed.issuedAt > nowMs+toleranceMs:
		return 0, ErrStatusFutureDated
	case nowMs-toleranceMs > parsed.expiresAt:
		return 0, ErrStatusExpired
	}
	return parsed.expiresAt, nil
}

func wellFormedStatus(f map[string]cbor.Value, p profile.Profile) (statusTBS, bool) {
	label, labelOK := f["label"].AsText()
	nodeID, nodeIDOK := fieldArray32(f["node_id"])
	bindingHash, bindingHashOK := fieldArray48(f["binding_hash"])
	issuedAt, issuedAtOK := protocolInt(f["issued_at"])
	expiresAt, expiresAtOK := protocolInt(f["expires_at"])
	signatureAlg, sigAlgOK := f["sig_alg"].AsText()
	wellFormed := labelOK && label == labelStatus && nodeIDOK && bindingHashOK && issuedAtOK && expiresAtOK &&
		withinWindow(issuedAt, expiresAt, maxStatusMs) && sigAlgOK && signatureAlg == sigAlg(p)
	return statusTBS{nodeID: nodeID, bindingHash: bindingHash, issuedAt: issuedAt, expiresAt: expiresAt}, wellFormed
}

// decodeTBS is tbs decoded under the decoding rule, when it is a map whose keys
// are exactly names, all text.
func decodeTBS(tbs []byte, names []string) (map[string]cbor.Value, bool) {
	v, err := cbor.Decode(tbs)
	if err != nil {
		return nil, false
	}
	entries, isMap := v.AsMap()
	if !isMap || len(entries) != len(names) {
		return nil, false
	}
	fields := make(map[string]cbor.Value, len(entries))
	for _, e := range entries {
		name, isText := e.Key.AsText()
		if !isText {
			return nil, false
		}
		fields[name] = e.Val
	}
	for _, name := range names {
		if _, present := fields[name]; !present {
			return nil, false
		}
	}
	return fields, true
}

// withinWindow reports whether from and to are a validity period a verifier
// accepts: from at least 0, to no earlier than from and below 2^53, and at most
// max apart.
func withinWindow(from, to, max int64) bool {
	return from >= 0 && from <= to && to < maxProtocolInt && to-from <= max
}

// protocolInt is an integer field's value.
func protocolInt(v cbor.Value) (int64, bool) {
	if v.Kind() != cbor.KindUInt && v.Kind() != cbor.KindNegInt {
		return 0, false
	}
	return v.AsInt64()
}

func fieldArray32(v cbor.Value) ([32]byte, bool) {
	var out [32]byte
	b, ok := v.AsBytes()
	return out, ok && len(b) == len(out) && copy(out[:], b) == len(out)
}

func fieldArray48(v cbor.Value) ([48]byte, bool) {
	var out [48]byte
	b, ok := v.AsBytes()
	return out, ok && len(b) == len(out) && copy(out[:], b) == len(out)
}

// fieldBytes is the byte string under name in the map v.
func fieldBytes(v cbor.Value, name string) ([]byte, bool) {
	field, present := v.Get(name)
	if !present {
		return nil, false
	}
	return field.AsBytes()
}

// sigAlg is profile p's signature algorithm, as signed structures name it.
func sigAlg(p profile.Profile) string {
	definition, _ := p.Definition()
	return definition.SigAlg
}

// signTBS signs tbs under label with key.
func signTBS(key *NodeKey, label string, tbs []byte) (SignedTBS, error) {
	signature, err := key.Sign(labelled(label, tbs))
	if err != nil {
		return SignedTBS{}, err
	}
	return SignedTBS{TBS: tbs, Signature: signature}, nil
}

// labelled is label, a zero byte and tbs: the message a binding or a status
// statement signs.
func labelled(label string, tbs []byte) []byte {
	out := make([]byte, 0, len(label)+1+len(tbs))
	out = append(out, label...)
	out = append(out, 0)
	return append(out, tbs...)
}

func textEntry(name, value string) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Text(value)}
}

func bytesEntry(name string, value []byte) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Bytes(value)}
}

func intEntry(name string, value int64) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Int(value)}
}
