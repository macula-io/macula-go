package stationlink

import (
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/seal"
)

// A sealed stream frame opens only under the stream's own key id, as
// macula_stream's opened/5 binds it: one naming another key is not opened,
// though its ciphertext would open.
func TestASealedStreamFrameOpensOnlyUnderItsKeyID(t *testing.T) {
	keys := &callSeal{keyID: [seal.KeyIDSize]byte{7}, kC2P: [32]byte{1}, kP2C: [32]byte{2},
		request: seal.Request{RequestID: [16]byte{3}}}
	provider, caller := newStreamSeal(keys, false), newStreamSeal(keys, true)
	sealed, err := provider.sealed(frame.StreamDataFields{Seq: 1, Encoding: frame.Raw, Body: cbor.Bytes([]byte("chunk"))}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := sealed.(frame.StreamDataFields).Sealed
	received := func(keyID [seal.KeyIDSize]byte) frame.VerifiedStreamFrame {
		return frame.VerifiedStreamFrame{FrameType: "stream_data", Seq: 1, Encoding: frame.Raw,
			Sealed: &frame.Sealed{KeyID: keyID, Nonce: s.Nonce, Ct: s.Ct}}
	}
	if got, err := caller.opened(received(keys.keyID)); err != nil {
		t.Fatalf("under its own key id: %v", err)
	} else if b, _ := got.Body.AsBytes(); string(b) != "chunk" {
		t.Fatalf("opened %q", b)
	}
	if _, err := caller.opened(received([seal.KeyIDSize]byte{8})); !errors.Is(err, errNotOpened) {
		t.Errorf("under another key id: %v, want errNotOpened", err)
	}
}
