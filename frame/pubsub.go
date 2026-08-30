package frame

import "github.com/macula-io/macula-go/cbor"

// PublishSpec holds the fields for a PUBLISH frame.
type PublishSpec struct {
	Topic         string
	Realm         []byte
	Publisher     []byte
	Seq           uint64
	Payload       cbor.Value
	PublishedAtMs int64
	TTLMs         *uint64
}

func NewPublishSpec(topic string, realm, publisher []byte, seq uint64, payload cbor.Value, publishedAtMs int64) PublishSpec {
	return PublishSpec{Topic: topic, Realm: realm, Publisher: publisher, Seq: seq, Payload: payload, PublishedAtMs: publishedAtMs}
}

func publishValue(spec PublishSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("publish", 0, frameID, sentAtMs)
	fields = withField(fields, "realm", cbor.Bytes(spec.Realm))
	// topic := binary() -- bytes, not text.
	fields = withField(fields, "topic", cbor.Bytes([]byte(spec.Topic)))
	fields = withField(fields, "publisher", cbor.Bytes(spec.Publisher))
	fields = withField(fields, "seq", cbor.Uint64(spec.Seq))
	fields = withField(fields, "payload", spec.Payload)
	fields = withField(fields, "published_at_ms", cbor.Int(spec.PublishedAtMs))
	ttl := cbor.Null()
	if spec.TTLMs != nil {
		ttl = cbor.Uint64(*spec.TTLMs)
	}
	fields = withField(fields, "ttl_ms", ttl)
	return cbor.Map(fields)
}

// Publish builds a PUBLISH frame with a fresh frame_id/sent_at_ms. Does
// not set publisher_sig (the separate end-to-end publisher signature,
// §4/§6.8) -- not implemented yet.
func Publish(spec PublishSpec) cbor.Value { return publishValue(spec, freshFrameID(), currentMillis()) }

// SubscribeSpec holds the fields for a SUBSCRIBE frame.
type SubscribeSpec struct {
	Topic      string
	Realm      []byte
	Subscriber []byte
}

func NewSubscribeSpec(topic string, realm, subscriber []byte) SubscribeSpec {
	return SubscribeSpec{Topic: topic, Realm: realm, Subscriber: subscriber}
}

func subscribeValue(spec SubscribeSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("subscribe", 0, frameID, sentAtMs)
	fields = withField(fields, "realm", cbor.Bytes(spec.Realm))
	fields = withField(fields, "topic", cbor.Bytes([]byte(spec.Topic)))
	fields = withField(fields, "subscriber", cbor.Bytes(spec.Subscriber))
	fields = withField(fields, "filter", cbor.Null())
	fields = withField(fields, "options", cbor.Map(nil))
	return cbor.Map(fields)
}

// Subscribe builds a SUBSCRIBE frame with a fresh frame_id/sent_at_ms.
// No filter, no options -- the plainest possible subscription.
func Subscribe(spec SubscribeSpec) cbor.Value {
	return subscribeValue(spec, freshFrameID(), currentMillis())
}

// UnsubscribeSpec holds the fields for an UNSUBSCRIBE frame.
type UnsubscribeSpec struct {
	Topic      string
	Realm      []byte
	Subscriber []byte
}

func NewUnsubscribeSpec(topic string, realm, subscriber []byte) UnsubscribeSpec {
	return UnsubscribeSpec{Topic: topic, Realm: realm, Subscriber: subscriber}
}

func unsubscribeValue(spec UnsubscribeSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("unsubscribe", 0, frameID, sentAtMs)
	fields = withField(fields, "realm", cbor.Bytes(spec.Realm))
	fields = withField(fields, "topic", cbor.Bytes([]byte(spec.Topic)))
	fields = withField(fields, "subscriber", cbor.Bytes(spec.Subscriber))
	return cbor.Map(fields)
}

// Unsubscribe builds an UNSUBSCRIBE frame with a fresh frame_id/sent_at_ms.
func Unsubscribe(spec UnsubscribeSpec) cbor.Value {
	return unsubscribeValue(spec, freshFrameID(), currentMillis())
}

// EventInfo is what a subscriber actually receives -- the parsed
// fields of an EVENT frame.
type EventInfo struct {
	Topic        string
	Realm        []byte
	Publisher    []byte
	Seq          uint64
	Payload      cbor.Value
	DeliveredVia string
}

// ErrNotAnEventFrame is returned by ParseEvent when frame_type isn't
// "event".
var ErrNotAnEventFrame = errNotAnEventFrame{}

type errNotAnEventFrame struct{}

func (errNotAnEventFrame) Error() string { return "frame_type is not \"event\"" }

// ParseEvent parses a decoded frame as an EVENT.
func ParseEvent(v cbor.Value) (EventInfo, error) {
	ft, ok := v.Get("frame_type")
	if !ok {
		return EventInfo{}, ErrNotAnEventFrame
	}
	if t, ok := ft.AsText(); !ok || t != "event" {
		return EventInfo{}, ErrNotAnEventFrame
	}

	// topic := binary() on the wire -- bytes, not text.
	topicVal, ok := v.Get("topic")
	if !ok {
		return EventInfo{}, &ParseHelloError{Field: "topic", Err: ErrMissingField}
	}
	topicBytes, ok := topicVal.AsBytes()
	if !ok {
		return EventInfo{}, &ParseHelloError{Field: "topic", Err: ErrWrongFieldType}
	}

	realm, err := getBytes32(v, "realm")
	if err != nil {
		return EventInfo{}, err
	}
	publisher, err := getBytes32(v, "publisher")
	if err != nil {
		return EventInfo{}, err
	}
	seq, err := getUint(v, "seq")
	if err != nil {
		return EventInfo{}, err
	}
	payload, ok := v.Get("payload")
	if !ok {
		return EventInfo{}, &ParseHelloError{Field: "payload", Err: ErrMissingField}
	}
	deliveredViaVal, ok := v.Get("delivered_via")
	if !ok {
		return EventInfo{}, &ParseHelloError{Field: "delivered_via", Err: ErrMissingField}
	}
	deliveredVia, ok := deliveredViaVal.AsText()
	if !ok {
		return EventInfo{}, &ParseHelloError{Field: "delivered_via", Err: ErrWrongFieldType}
	}

	return EventInfo{
		Topic: string(topicBytes), Realm: realm, Publisher: publisher,
		Seq: seq, Payload: payload, DeliveredVia: deliveredVia,
	}, nil
}
