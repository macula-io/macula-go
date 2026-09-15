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

// A SUBSCRIBE and an UNSUBSCRIBE name a realm and a subscriber of 32 bytes each,
// as a station's field table reads them: both builders refuse either of another
// size, before they read the topic.
func TestASubscribeNamesARealmAndASubscriberOf32Bytes(t *testing.T) {
	key, short := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{1}, 31)
	builds := map[string]func(realm, subscriber []byte, topic string) error{
		"SUBSCRIBE": func(realm, subscriber []byte, topic string) error {
			_, err := Subscribe(NewSubscribeSpec(topic, realm, subscriber))
			return err
		},
		"UNSUBSCRIBE": func(realm, subscriber []byte, topic string) error {
			_, err := Unsubscribe(NewUnsubscribeSpec(topic, realm, subscriber))
			return err
		},
	}
	for name, build := range builds {
		if err := build(key, key, "news"); err != nil {
			t.Errorf("%s with a 32-byte realm and subscriber: %v, want it built", name, err)
		}
		wantRefusal(t, name+" with a 31-byte realm", build(short, key, "news"), ErrOutOfRange)
		wantRefusal(t, name+" with a 31-byte subscriber", build(key, short, "news"), ErrOutOfRange)
		wantRefusal(t, name+" with no realm", build(nil, key, "news"), ErrOutOfRange)
		wantRefusal(t, name+" with a 31-byte realm and a 513-byte topic", build(short, key, strings.Repeat("t", 513)), ErrOutOfRange)
	}
}

// A PUBLISH names a realm of 32 bytes and a topic a station reads, as a
// publication's field table reads them: Publish refuses a realm of another size,
// before it reads the topic, and a topic over 512 bytes or not UTF-8.
func TestAPublishNamesARealmOf32BytesAndATopicAStationReads(t *testing.T) {
	realm, publisher := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	build := func(realm []byte, topic string) error {
		_, err := Publish(NewPublishSpec(topic, realm, publisher, 1, cbor.Uint64(1), 0))
		return err
	}
	if err := build(realm, strings.Repeat("t", 512)); err != nil {
		t.Errorf("a PUBLISH with a 32-byte realm and a 512-byte topic: %v, want it built", err)
	}
	wantRefusal(t, "a PUBLISH with a 31-byte realm", build(realm[:31], "news"), ErrOutOfRange)
	wantRefusal(t, "a PUBLISH with no realm", build(nil, "news"), ErrOutOfRange)
	wantRefusal(t, "a PUBLISH with a 513-byte topic", build(realm, strings.Repeat("t", 513)), ErrTextTooLong)
	wantRefusal(t, "a PUBLISH with a topic that is not UTF-8", build(realm, "\xff"), ErrInvalidText)
	wantRefusal(t, "a PUBLISH with a 31-byte realm and a 513-byte topic", build(realm[:31], strings.Repeat("t", 513)), ErrOutOfRange)
}
