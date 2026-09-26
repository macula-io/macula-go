// Package devicerequest signs a device's request to a realm (proof v2,
// macula-realm#29): creating a join session over HTTP, or asking for a
// membership UCAN over the mesh. The proof binds the device's key to exactly
// this request, in this realm, once: every field the human admitter reads
// (device_info) and every term the realm grants (ttl_seconds) is signed, with
// a nonce the realm refuses to see twice.
//
// The signed bytes are macula-realm's MaculaRealm.Identity.DeviceRequestProof
// message/6, byte for byte: deterministic CBOR of a map of eight text-keyed
// entries. testdata holds the realm's own vector for it.
package devicerequest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

const (
	// Tag names what the signature is for, so it signs nothing else.
	Tag = "macula.realm.device_request"
	// Version is the proof's version, 2; the realm refuses a v1 proof.
	Version = 2
	// ProcedureJoinSession is the procedure of an HTTP join session.
	ProcedureJoinSession = "macula_realm.join_session"
	// ProcedureMembershipUCAN is the procedure of a membership UCAN asked
	// for over the mesh.
	ProcedureMembershipUCAN = "macula_realm.membership_ucan"
	// NonceSize is the nonce's length in bytes.
	NonceSize = 16
	// maxSafeInteger is 2^53 - 1, the largest integer every JSON reader
	// holds exactly; the realm refuses a larger one.
	maxSafeInteger = 1<<53 - 1
)

var (
	// ErrBooleanNotAllowed is a request with a boolean in it: the realm's
	// CBOR has no boolean (400 boolean_not_allowed).
	ErrBooleanNotAllowed = errors.New("devicerequest: a boolean is not allowed; send 0 or 1")
	// ErrNumberOutOfRange is an integer beyond 2^53 - 1 in magnitude (400
	// number_out_of_range).
	ErrNumberOutOfRange = errors.New("devicerequest: a number beyond 2^53 - 1")
	// ErrNotAJSONObject is a body that is not one JSON object (400
	// not_a_json_object).
	ErrNotAJSONObject = errors.New("devicerequest: the request is not one JSON object")
)

// Proof is the proof as it goes on the wire, beside the request's own
// public_key (the carried key, base64).
type Proof struct {
	V         int    `json:"v"`
	Timestamp uint64 `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// Message is the exact bytes a device signs: the carried public key, the
// realm id, the procedure, the timestamp in milliseconds, the nonce and the
// request, under the tag and version.
func Message(publicKey []byte, realm [32]byte, procedure string, timestampMs uint64, nonce [NonceSize]byte,
	request cbor.Value) []byte {
	return cbor.Encode(cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("tag"), Val: cbor.Text(Tag)},
		{Key: cbor.Text("v"), Val: cbor.Uint64(Version)},
		{Key: cbor.Text("public_key"), Val: cbor.Bytes(publicKey)},
		{Key: cbor.Text("realm"), Val: cbor.Bytes(realm[:])},
		{Key: cbor.Text("procedure"), Val: cbor.Text(procedure)},
		{Key: cbor.Text("timestamp"), Val: cbor.Uint64(timestampMs)},
		{Key: cbor.Text("nonce"), Val: cbor.Bytes(nonce[:])},
		{Key: cbor.Text("request"), Val: request},
	}))
}

// Sign signs request for procedure in realm with key, now and with a fresh
// nonce. request is the request in its signed form: JSONRequest's for an
// HTTP body; for a mesh payload, the payload as it goes on the wire without
// its proof.
func Sign(key *identity.NodeKey, realm [32]byte, procedure string, request cbor.Value) (Proof, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Proof{}, err
	}
	return signAt(key, realm, procedure, request, uint64(time.Now().UnixMilli()), nonce)
}

func signAt(key *identity.NodeKey, realm [32]byte, procedure string, request cbor.Value, timestampMs uint64,
	nonce [NonceSize]byte) (Proof, error) {
	signature, err := key.Sign(Message(key.PublicKey(), realm, procedure, timestampMs, nonce, request))
	if err != nil {
		return Proof{}, err
	}
	return Proof{V: Version, Timestamp: timestampMs, Nonce: hex.EncodeToString(nonce[:]),
		Signature: hex.EncodeToString(signature)}, nil
}

// JSONRequest is the signed form of an HTTP request body, one JSON object,
// under the realm's rule: its "proof" is dropped; a string is text; an
// integral number is an integer (1 and 1.0 alike); any other number is a
// float; an object is a map with text keys and an array a list; null is null.
// A boolean, or an integer beyond 2^53 - 1, is refused.
func JSONRequest(body []byte) (cbor.Value, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return cbor.Value{}, ErrNotAJSONObject
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return cbor.Value{}, ErrNotAJSONObject
	}
	delete(object, "proof")
	return jsonValue(object)
}

func jsonValue(v any) (cbor.Value, error) {
	switch t := v.(type) {
	case nil:
		return cbor.Null(), nil
	case bool:
		return cbor.Value{}, ErrBooleanNotAllowed
	case string:
		return cbor.Text(t), nil
	case json.Number:
		return jsonNumber(t)
	case []any:
		items := make([]cbor.Value, len(t))
		for i, item := range t {
			value, err := jsonValue(item)
			if err != nil {
				return cbor.Value{}, err
			}
			items[i] = value
		}
		return cbor.List(items), nil
	case map[string]any:
		entries := make([]cbor.MapEntry, 0, len(t))
		for k, item := range t {
			value, err := jsonValue(item)
			if err != nil {
				return cbor.Value{}, err
			}
			entries = append(entries, cbor.MapEntry{Key: cbor.Text(k), Val: value})
		}
		return cbor.Map(entries), nil
	}
	return cbor.Value{}, fmt.Errorf("devicerequest: a JSON value of type %T", v)
}

// jsonNumber is a JSON number as the realm reads it: the number Jason gives
// (an integer for integer syntax, a float otherwise), then an integral float
// as the integer it equals.
func jsonNumber(n json.Number) (cbor.Value, error) {
	text := n.String()
	if !strings.ContainsAny(text, ".eE") {
		i, err := strconv.ParseInt(text, 10, 64)
		if err != nil || i > maxSafeInteger || i < -maxSafeInteger {
			return cbor.Value{}, ErrNumberOutOfRange
		}
		return cbor.Int(i), nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) {
		return cbor.Value{}, ErrNumberOutOfRange
	}
	if f != math.Trunc(f) {
		return cbor.Float(f), nil
	}
	if math.Abs(f) > maxSafeInteger {
		return cbor.Value{}, ErrNumberOutOfRange
	}
	return cbor.Int(int64(f)), nil
}
