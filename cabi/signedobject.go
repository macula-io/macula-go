package main

// #include <stdint.h>
// #include <stddef.h>
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

// A signed object that carries its signer's key, {key, tbs, signature}, as
// macula_signed_object verifies it: what a binding checks a signature it was
// handed with (a corpus entry's, say) without reimplementing the rule.

// errUnverified is a signed object that did not verify, with the refusal
// macula_signed_object names. Anything else (a library that cannot verify
// post-quantum signatures at all, say) is no verdict on the object: failed.
func errUnverified(err error) *abiError {
	var reason string
	switch {
	case errors.Is(err, identity.ErrObjectSignatureInvalid):
		reason = "signature_invalid"
	case errors.Is(err, identity.ErrObjectAlgMismatch):
		reason = "alg_mismatch"
	case errors.Is(err, identity.ErrObjectMalformed):
		reason = "malformed"
	default:
		return classify(nil, err)
	}
	return &abiError{kind: kindUnverified, message: err.Error(), fields: map[string]any{"reason": reason}}
}

// verifySignedObject is the signed object in object's CBOR bytes, verified
// under label and the profile named, as JSON: the signer's node_id as hex,
// like every id the ABI returns, its key as carried and the tbs bytes as
// received as {"$bytes"}, and the fields they decode to.
func verifySignedObject(label string, object []byte, profileName string) (string, error) {
	if label == "" {
		return "", invalidArgument("the label is empty")
	}
	p, err := parseProfile(profileName)
	if err != nil {
		return "", err
	}
	v, err := cbor.Decode(object)
	if err != nil {
		return "", errUnverified(fmt.Errorf("%w: %w", identity.ErrObjectMalformed, err))
	}
	verified, err := identity.VerifyObject(label, v, p)
	if err != nil {
		return "", errUnverified(err)
	}
	nodeID := identity.NodeIDOf(verified.Key, p)
	text, err := json.Marshal(map[string]any{
		"node_id": hex.EncodeToString(nodeID[:]),
		"key":     payloadToJSON(cbor.Bytes(verified.Key)),
		"tbs":     payloadToJSON(cbor.Bytes(verified.TBS)),
		"fields":  payloadToJSON(verified.Fields),
	})
	if err != nil {
		return "", newError(kindFailed, "a verified object that does not encode: %v", err)
	}
	return string(text), nil
}

//export macula_signed_object_verify
func macula_signed_object_verify(label *C.char, object *C.uint8_t, objectLen C.size_t, profileName *C.char,
	errOut **C.char) *C.char {
	verified, err := verifySignedObject(goString(label), goBytes(object, objectLen), goString(profileName))
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	return cString(verified)
}
