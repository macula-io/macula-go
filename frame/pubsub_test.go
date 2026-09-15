package frame

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// A SUBSCRIBE carries exactly the fields a macula 11.0.0 station reads in one:
// the envelope, realm, topic, subscriber and options, with no filter, which a
// station refuses as a field its type does not have. An UNSUBSCRIBE carries the
// envelope, realm, topic and subscriber.
func TestASubscribeCarriesNoFilter(t *testing.T) {
	realm, subscriber := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	subscribe := must[cbor.Value](t)(Subscribe(NewSubscribeSpec("news/today", realm, subscriber)))
	want := []string{"call_id", "capabilities", "frame_id", "frame_type", "options", "realm", "sent_at_ms", "source_route", "subscriber", "topic", "version"}
	if got := sortedKeys(subscribe); !slices.Equal(got, want) {
		t.Errorf("a SUBSCRIBE's fields: %v, want %v", got, want)
	}
	unsubscribe := must[cbor.Value](t)(Unsubscribe(NewUnsubscribeSpec("news/today", realm, subscriber)))
	want = []string{"call_id", "capabilities", "frame_id", "frame_type", "realm", "sent_at_ms", "source_route", "subscriber", "topic", "version"}
	if got := sortedKeys(unsubscribe); !slices.Equal(got, want) {
		t.Errorf("an UNSUBSCRIBE's fields: %v, want %v", got, want)
	}
}

// A SUBSCRIBE's and an UNSUBSCRIBE's topic is UTF-8 bytes of at most 512, as a
// station's receive rule reads it: both builders refuse a longer topic and one
// that is not UTF-8.
func TestASubscribeTopicIsUTF8OfAtMost512Bytes(t *testing.T) {
	realm, subscriber := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	builds := map[string]func(topic string) error{
		"SUBSCRIBE": func(topic string) error {
			_, err := Subscribe(NewSubscribeSpec(topic, realm, subscriber))
			return err
		},
		"UNSUBSCRIBE": func(topic string) error {
			_, err := Unsubscribe(NewUnsubscribeSpec(topic, realm, subscriber))
			return err
		},
	}
	long := strings.Repeat("t", 512)
	for name, build := range builds {
		if err := build(long); err != nil {
			t.Errorf("%s with a 512-byte topic: %v, want it built", name, err)
		}
		wantRefusal(t, name+" with a 513-byte topic", build(long+"t"), ErrTextTooLong)
		wantRefusal(t, name+" with a topic that is not UTF-8", build("\xff"), ErrInvalidText)
	}
}
