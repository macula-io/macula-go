package main

// #include <stdint.h>
// #include <stddef.h>
import "C"

import (
	"encoding/json"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/devicerequest"
	"github.com/macula-io/macula-go/identity"
)

// A device request proof (realm proof v2, macula-realm#29): the device's key
// signs exactly the request it makes of a realm (devicerequest).

// The two forms a request is signed in, macula.h's MACULA_REQUEST_*.
const (
	requestHTTP = 0
	requestMesh = 1
)

// signedRequest is request_json in its signed form under rule: an HTTP body
// under the realm's JSON rule, or a mesh payload as it goes on the wire
// (this ABI's own mapping), its "proof" left out either way.
func signedRequest(requestJSON string, rule int32) (cbor.Value, error) {
	switch rule {
	case requestHTTP:
		request, err := devicerequest.JSONRequest([]byte(requestJSON))
		if err != nil {
			return cbor.Value{}, invalidArgument("%v", err)
		}
		return request, nil
	case requestMesh:
		payload, err := payloadFromJSON(requestJSON)
		if err != nil {
			return cbor.Value{}, err
		}
		entries, ok := payload.AsMap()
		if !ok {
			return cbor.Value{}, invalidArgument("a mesh request is a JSON object")
		}
		kept := make([]cbor.MapEntry, 0, len(entries))
		for _, e := range entries {
			if key, _ := e.Key.AsText(); key != "proof" {
				kept = append(kept, e)
			}
		}
		return cbor.Map(kept), nil
	}
	return cbor.Value{}, invalidArgument("a request rule is 0 (HTTP) or 1 (mesh), not %d", rule)
}

// deviceRequestProof is key's v2 proof for request_json under rule, as JSON.
func deviceRequestProof(key *identity.NodeKey, realm [32]byte, procedure, requestJSON string, rule int32) (string, error) {
	if procedure == "" {
		return "", invalidArgument("the procedure is empty")
	}
	request, err := signedRequest(requestJSON, rule)
	if err != nil {
		return "", err
	}
	proof, err := devicerequest.Sign(key, realm, procedure, request)
	if err != nil {
		return "", err
	}
	text, err := json.Marshal(proof)
	if err != nil {
		return "", err
	}
	return string(text), nil
}

//export macula_key_device_request_proof
func macula_key_device_request_proof(h C.uintptr_t, realm32 *C.uint8_t, procedure, requestJSON *C.char, rule C.int32_t,
	errOut **C.char) *C.char {
	key := keyOf(h, errOut)
	if key == nil {
		return nil
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	proof, err := deviceRequestProof(key, realm, goString(procedure), goString(requestJSON), int32(rule))
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	return cString(proof)
}

//export macula_device_request_message
func macula_device_request_message(publicKey *C.uint8_t, publicKeyLen C.size_t, realm32 *C.uint8_t, procedure *C.char,
	timestampMs C.int64_t, nonce16 *C.uint8_t, requestJSON *C.char, rule C.int32_t, outLen *C.size_t,
	errOut **C.char) *C.uint8_t {
	*outLen = 0
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	nonce, ok := fixed(nonce16, devicerequest.NonceSize)
	if !ok {
		setErr(errOut, invalidArgument("the nonce is NULL"))
		return nil
	}
	if timestampMs < 0 {
		setErr(errOut, invalidArgument("a negative timestamp"))
		return nil
	}
	request, err := signedRequest(goString(requestJSON), int32(rule))
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	if publicKeyLen == 0 {
		setErr(errOut, invalidArgument("the public key is empty"))
		return nil
	}
	message := devicerequest.Message(goBytes(publicKey, publicKeyLen), realm, goString(procedure), uint64(timestampMs),
		[devicerequest.NonceSize]byte(nonce), request)
	return cBytes(message, outLen)
}
