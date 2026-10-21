package stationlink

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/handshake"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/internal/wire10vectors"
	"github.com/macula-io/macula-go/profile"
)

// The wire 1.0 envelope vectors (macula priv/vectors/wire_1_0/envelope.json,
// macula#99): what a link does with each frame after HELLO, on the control
// stream or a dedicated stream, and with a length header alone.

// envelopeVerdict is what the link does with one received frame, in the
// vectors' terms.
func envelopeVerdict(t *testing.T, c wire10vectors.Case) (outcome, reason string, quicCode int64) {
	t.Helper()
	if c.Text("length_header") != "" {
		header, err := c.Hex("length_header")
		if err != nil {
			t.Fatal(err)
		}
		_, err = frameReader{r: bytes.NewReader(header)}.read(MaxFrameBytes)
		if errors.Is(err, ErrFrameTooLarge) {
			return "refuse", "frame_too_large", 0
		}
		return "accept", "", 0
	}
	payload, err := c.Hex("frame")
	if err != nil {
		t.Fatal(err)
	}
	if c.Text("position") == "dedicated_stream" {
		v, err := cbor.Decode(payload)
		if err == nil && unknownOnStream(v) {
			return "abort_stream", "", int64(quicCodeUnknownFrameType)
		}
		return "accept", "", 0
	}
	envelope, known, err := readControl(payload)
	if err == nil && known && envelope.FrameType == "status" {
		_, err = handshake.ReadStatus(cbor.Encode(envelope.Frame), statusPeer(t, c))
	}
	switch {
	case errors.Is(err, frame.ErrExtensionUnsupported):
		return "refuse", "extension_unsupported", 0
	case err != nil:
		return "refuse", "malformed_frame", 0
	case !known:
		return "ignore", "", 0
	}
	return "accept", "", 0
}

// statusPeer is the sender a STATUS case names (input.status_peer): its
// identity key, by role in keys.json, and its TLS binding, as a link holds
// them after HELLO; the link reads a STATUS as statusRenewed does.
func statusPeer(t *testing.T, c wire10vectors.Case) handshake.Peer {
	t.Helper()
	sender, _ := c.Input["status_peer"].(map[string]any)
	binding, _ := sender["binding"].(map[string]any)
	keys, err := wire10vectors.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	role, _ := sender["identity"].(string)
	key, err := keys.Key(c.Profile, role)
	if err != nil {
		t.Fatal(err)
	}
	hexOf := func(name string) []byte {
		s, _ := binding[name].(string)
		b, err := hex.DecodeString(s)
		if err != nil || s == "" {
			t.Fatalf("status_peer.binding.%s: %q, %v", name, s, err)
		}
		return b
	}
	return handshake.Peer{Profile: profile.Profile(c.Profile), IdentityKey: key,
		Binding: identity.SignedTBS{TBS: hexOf("tbs"), Signature: hexOf("signature")}, NowMs: c.Int("now_ms")}
}

func TestTheWireOneEnvelopeVectors(t *testing.T) {
	f, err := wire10vectors.Load("envelope")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			assertAnEnvelopeVector(t, c)
		})
	}
}

// assertAnEnvelopeVector applies one vector: the link's verdict on the frame,
// the QUIC code it names, and the counter it must move.
func assertAnEnvelopeVector(t *testing.T, c wire10vectors.Case) {
	t.Helper()
	before := frame.WireCounters()
	outcome, reason, code := envelopeVerdict(t, c)
	after := frame.WireCounters()
	if outcome != c.Outcome() || reason != c.Reason() {
		t.Errorf("verdict (%s, %s), want (%s, %s)", outcome, reason, c.Outcome(), c.Reason())
	}
	if want := c.ExpectInt("quic_code"); want != 0 && code != want {
		t.Errorf("QUIC code %d, want %d", code, want)
	}
	assertCounterMoved(t, c.ExpectText("count"), before, after)
}

// assertCounterMoved checks the counter the vector names moved between the two
// readings; a vector naming none needs no counter to move.
func assertCounterMoved(t *testing.T, counter string, before, after frame.WireCounts) {
	t.Helper()
	switch counter {
	case "wire_unknown_frame_type":
		if after.UnknownFrameType == before.UnknownFrameType {
			t.Errorf("wire_unknown_frame_type did not count")
		}
	case "wire_ext_ignored":
		if sum(after.ExtIgnored) == sum(before.ExtIgnored) {
			t.Errorf("wire_ext_ignored did not count")
		}
	case "wire_ext_refused":
		if sum(after.ExtRefused) == sum(before.ExtRefused) {
			t.Errorf("wire_ext_refused did not count")
		}
	}
}

func sum(m map[string]uint64) (n uint64) {
	for _, v := range m {
		n += v
	}
	return n
}
