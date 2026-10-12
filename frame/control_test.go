package frame

import (
	"errors"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// The control frames a client link builds read back through their tables
// (ReadControl), and a frame with a field its table does not name, without a
// field it requires, or carrying a neighbour signature, is malformed.
func TestControlFramesReadBackThroughTheirTables(t *testing.T) {
	subscribe, err := SubscribeFrame([]byte("t"), [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	unsubscribe, err := UnsubscribeFrame([]byte("t"), [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	goodbye, err := GoodbyeFrame("normal", []byte("moving to beam01"))
	if err != nil {
		t.Fatal(err)
	}
	bare, err := GoodbyeFrame("normal", nil)
	if err != nil {
		t.Fatal(err)
	}
	built := map[string]cbor.Value{
		"advertise": AdvertiseFrame([]byte{1}), "unadvertise": UnadvertiseFrame([]byte{2}),
		"subscribe": subscribe, "unsubscribe": unsubscribe, "goodbye with a detail": goodbye, "goodbye": bare,
	}
	for name, v := range built {
		decoded, err := Decode(must[[]byte](t)(Encode(v)))
		if err != nil || !decoded.Complete {
			t.Fatalf("%s: Decode: %v", name, err)
		}
		if _, err := ReadControl(decoded.Frame); err != nil {
			t.Errorf("%s: ReadControl = %v, want it read", name, err)
		}
	}
	entries, _ := bare.AsMap()
	for name, v := range map[string]cbor.Value{
		"a field no GOODBYE has":    cbor.Map(append(entries, textEntry("colour", "blue"))),
		"a neighbour signature":     cbor.Map(append(entries, valueEntry("neighbour", cbor.Map(nil)))),
		"a GOODBYE without reason":  frameWithout(bare, "reason"),
		"a 257-byte reason":         frameWith(bare, "reason", cbor.Text(strings.Repeat("r", 257))),
		"a SUBSCRIBE without realm": frameWithout(subscribe, "realm"),
		"a type with no table":      frameWith(bare, "frame_type", cbor.Text("example_future_frame")),
	} {
		if _, err := ReadControl(v); !errors.Is(err, ErrMalformedFrame) {
			t.Errorf("%s: %v, want ErrMalformedFrame", name, err)
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
