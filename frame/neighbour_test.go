package frame

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// erlangNeighbour is testdata/erlang_neighbour.json: the control frames a
// client link sends, built by macula 12.1.0's macula_frame and neighbour-signed
// in pq_hybrid (unsigned in pq_pure), by scripts/interop/erlang_neighbour.escript.
type erlangNeighbour struct {
	Entries []struct {
		Profile    string `json:"profile"`
		PeerKey    string `json:"peer_key"`
		Connection string `json:"connection"`
		Frames     []struct {
			FrameType string `json:"frame_type"`
			Seq       uint64 `json:"seq"`
			Bytes     string `json:"bytes"`
		} `json:"frames"`
	} `json:"entries"`
}

func nbHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func decodedWhole(t *testing.T, b []byte) cbor.Value {
	t.Helper()
	d, err := Decode(b)
	if err != nil || !d.Complete || d.Consumed != len(b) {
		t.Fatalf("Decode: (%+v, %v)", d, err)
	}
	return d.Frame
}

func frameTypeOf(v cbor.Value) string {
	entries, _ := v.AsMap()
	for _, e := range entries {
		if k, _ := e.Key.AsText(); k == "frame_type" {
			s, _ := e.Val.AsText()
			return s
		}
	}
	return ""
}

// The control frames macula signed open here, each as its own type, at its
// connection and seq; at the next seq, or on another connection, each is
// refused. A pq_pure frame, which carries no neighbour, comes back as it is.
func TestControlFramesMaculaSentAreRead(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "erlang_neighbour.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var fixture erlangNeighbour
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if len(fixture.Entries) != 2 {
		t.Fatalf("%d profiles, want pq_hybrid and pq_pure", len(fixture.Entries))
	}
	for _, e := range fixture.Entries {
		p := profile.Profile(e.Profile)
		var connection [48]byte
		copy(connection[:], nbHex(t, e.Connection))
		for _, f := range e.Frames {
			t.Run(e.Profile+" "+f.FrameType, func(t *testing.T) {
				wire := decodedWhole(t, nbHex(t, f.Bytes))
				peer := NeighbourPeer{Profile: p, PeerKey: nbHex(t, e.PeerKey), Connection: connection, Seq: f.Seq}
				opened, err := VerifyNeighbour(wire, peer)
				if err != nil {
					t.Fatalf("VerifyNeighbour: %v", err)
				}
				if got := frameTypeOf(opened); got != f.FrameType {
					t.Errorf("opened as %q, want %q", got, f.FrameType)
				}
				if p != profile.PQHybrid {
					return
				}
				next := peer
				next.Seq++
				if _, err := VerifyNeighbour(wire, next); !errors.Is(err, ErrMalformedFrame) {
					t.Errorf("at the next seq: %v, want ErrMalformedFrame", err)
				}
				other := peer
				other.Connection[0] ^= 1
				if _, err := VerifyNeighbour(wire, other); !errors.Is(err, ErrMalformedFrame) {
					t.Errorf("on another connection: %v, want ErrMalformedFrame", err)
				}
			})
		}
	}
}

// The frames macula-go builds and signs open again, and each control frame
// type is neighbour-signed in pq_hybrid alone.
func TestControlFramesRoundTrip(t *testing.T) {
	realm, subscriber := [32]byte{3}, [32]byte{1}
	topic := []byte("io.macula/mcl-news/news/wire/news_item_reported_v1")
	build := map[string]func() (cbor.Value, error){
		"advertise":   func() (cbor.Value, error) { return AdvertiseFrame([]byte("a signed record")), nil },
		"unadvertise": func() (cbor.Value, error) { return UnadvertiseFrame([]byte("a signed withdrawal")), nil },
		"subscribe":   func() (cbor.Value, error) { return SubscribeFrame(topic, realm, subscriber) },
		"unsubscribe": func() (cbor.Value, error) { return UnsubscribeFrame(topic, realm, subscriber) },
		"goodbye":     func() (cbor.Value, error) { return GoodbyeFrame("normal", []byte("closing")) },
	}
	for _, p := range []profile.Profile{profile.PQHybrid, profile.PQPure} {
		key := must[*identity.NodeKey](t)(identity.GenerateKey(identity.PurposeIdentity, p))
		connection := [48]byte{9}
		seq := uint64(0)
		for frameType, make := range build {
			t.Run(string(p)+" "+frameType, func(t *testing.T) {
				if NeighbourSigned(p, frameType) != (p == profile.PQHybrid) {
					t.Errorf("NeighbourSigned(%s, %s) = %t", p, frameType, NeighbourSigned(p, frameType))
				}
				frame := must[cbor.Value](t)(make())
				signed := must[cbor.Value](t)(SignNeighbour(frame, key, NeighbourLink{Connection: connection, Seq: seq}))
				wire := onWire(t, signed)
				opened, err := VerifyNeighbour(wire, NeighbourPeer{Profile: p, PeerKey: key.PublicKey(), Connection: connection, Seq: seq})
				if err != nil {
					t.Fatalf("VerifyNeighbour: %v", err)
				}
				if frameTypeOf(opened) != frameType {
					t.Errorf("opened as %q", frameTypeOf(opened))
				}
			})
			seq++
		}
	}
}

// A SUBSCRIBE's and an UNSUBSCRIBE's topic is UTF-8 bytes of at most 512, as a
// station's receive rule reads it: both builders refuse a longer topic and one
// that is not UTF-8.
func TestASubscribeTopicIsUTF8OfAtMost512Bytes(t *testing.T) {
	realm, subscriber := [32]byte{1}, [32]byte{2}
	builds := map[string]func([]byte, [32]byte, [32]byte) (cbor.Value, error){
		"SUBSCRIBE": SubscribeFrame, "UNSUBSCRIBE": UnsubscribeFrame,
	}
	long := strings.Repeat("t", 512)
	for name, build := range builds {
		if _, err := build([]byte(long), realm, subscriber); err != nil {
			t.Errorf("%s with a 512-byte topic: %v, want it built", name, err)
		}
		_, err := build([]byte(long+"t"), realm, subscriber)
		wantRefusal(t, name+" with a 513-byte topic", err, ErrTextTooLong)
		_, err = build([]byte("\xff"), realm, subscriber)
		wantRefusal(t, name+" with a topic that is not UTF-8", err, ErrInvalidText)
	}
}
