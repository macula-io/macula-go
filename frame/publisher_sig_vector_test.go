package frame

import (
	"encoding/hex"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

// Reference vector generated directly from the Erlang implementation
// (macula-io/macula, src/peering/macula_frame.erl:sign_publisher/2),
// live in a rebar3 shell against the same fixed identity
// reference_vector_test.go already uses for the per-hop SigDomain
// vector. This is the FIRST publisher_sig implementation in any repo
// (macula-go, macula-rust, macula-dotnet all lacked it as
// of 2026-08-29) -- there is no prior port to cross-check against, so
// this vector is checked straight against the Erlang source of truth.
const (
	pubSigVectorTopic     = "acme/svc.do"
	pubSigVectorSeq       = uint64(42)
	pubSigVectorPayload   = "hello"
	pubSigVectorSignature = "C11BEB676A590FD1BA86F0B77E377B4582AA461DB1283F64E57224E920A7BD0A2C7D36271B795FFC3CB4F2C7BB8925B034431AA6425E25B2AEEFAC026883BB0C"
)

func TestPublisherSigMatchesTheErlangReference(t *testing.T) {
	privSeed := hexBytes(t, vectorPriv)
	pubBytes := hexBytes(t, vectorPub)
	id, err := identity.FromSeed(privSeed)
	if err != nil {
		t.Fatalf("identity.FromSeed: %v", err)
	}

	realm := make([]byte, 32) // all-zero mesh realm, matching the vector

	spec := NewPublishSpec(pubSigVectorTopic, realm, pubBytes, pubSigVectorSeq,
		cbor.Bytes([]byte(pubSigVectorPayload)), vectorSentAtMs)
	unsigned := Publish(spec)
	signed := SignPublisher(unsigned, id)

	sigVal, ok := signed.Get("publisher_sig")
	if !ok {
		t.Fatal("signed frame has no publisher_sig field")
	}
	sigBytes, _ := sigVal.AsBytes()
	got := hex.EncodeToString(sigBytes)
	if !equalFoldHex(got, pubSigVectorSignature) {
		t.Errorf("publisher_sig diverged from the Erlang reference -- canonical field\n"+
			"set, encoding, or the event-pub signing domain must differ.\n got  %s\n want %s",
			got, pubSigVectorSignature)
	}

	if err := VerifyPublisher(signed); err != nil {
		t.Errorf("VerifyPublisher on our own freshly-signed frame: %v", err)
	}

	// Tamper check, mirroring the Erlang vector generation's own
	// sanity check: changing payload after signing must invalidate it.
	tampered := withFieldOnValue(signed, "payload", cbor.Bytes([]byte("world")))
	if err := VerifyPublisher(tampered); err == nil {
		t.Error("VerifyPublisher accepted a frame with a tampered payload")
	}

	// Absence must be a verification failure, not "trusted" -- see
	// VerifyPublisher's own doc comment.
	if err := VerifyPublisher(unsigned); err != ErrMissingPublisherSig {
		t.Errorf("VerifyPublisher on an unsigned frame: got %v, want %v", err, ErrMissingPublisherSig)
	}
}
