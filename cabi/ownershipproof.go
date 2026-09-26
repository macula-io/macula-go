package main

// #include <stdint.h>
// #include <stddef.h>
import "C"

import (
	"errors"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/ownershipproof"
)

// An ownership proof (v2, mcl-om#7): the asserted_by block by which a node
// authorises every other field of a payload it sends (ownershipproof).

// ownershipProofPayload is payload_json with key's asserted_by block, as JSON.
func ownershipProofPayload(key *identity.NodeKey, realm [32]byte, procedure, payloadJSON string) (string, error) {
	if procedure == "" {
		return "", invalidArgument("the procedure is empty")
	}
	payload, err := payloadFromJSON(payloadJSON)
	if err != nil {
		return "", err
	}
	signed, err := ownershipproof.Attach(payload, key, realm, procedure)
	if errors.Is(err, ownershipproof.ErrNotAMap) {
		return "", invalidArgument("an ownership-proven payload is a JSON object")
	}
	if err != nil {
		return "", err
	}
	return string(payloadToJSON(signed)), nil
}

//export macula_key_ownership_proof
func macula_key_ownership_proof(h C.uintptr_t, realm32 *C.uint8_t, procedure, payloadJSON *C.char, errOut **C.char) *C.char {
	key := keyOf(h, errOut)
	if key == nil {
		return nil
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	payload, err := ownershipProofPayload(key, realm, goString(procedure), goString(payloadJSON))
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	return cString(payload)
}

//export macula_ownership_proof_message
func macula_ownership_proof_message(identity32, realm32 *C.uint8_t, procedure *C.char, timestampMs C.int64_t,
	nonce16 *C.uint8_t, fieldsJSON *C.char, outLen *C.size_t, errOut **C.char) *C.uint8_t {
	*outLen = 0
	id, ok := id32(identity32)
	if !ok {
		setErr(errOut, invalidArgument("the identity is NULL"))
		return nil
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	nonce, ok := fixed(nonce16, ownershipproof.NonceSize)
	if !ok {
		setErr(errOut, invalidArgument("the nonce is NULL"))
		return nil
	}
	if timestampMs < 0 {
		setErr(errOut, invalidArgument("a negative timestamp"))
		return nil
	}
	fields, err := payloadFromJSON(goString(fieldsJSON))
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	if _, isMap := fields.AsMap(); !isMap {
		setErr(errOut, invalidArgument("the fields are a JSON object"))
		return nil
	}
	message := ownershipproof.Message(id, realm, goString(procedure), uint64(timestampMs),
		[ownershipproof.NonceSize]byte(nonce), fields)
	return cBytes(message, outLen)
}
