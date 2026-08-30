package connection

import (
	"crypto/rand"
	"sync/atomic"
	"time"

	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
)

const (
	publishStartedTopic   = "pubsub.publish_started_v1"
	publishCompletedTopic = "pubsub.publish_completed_v1"
)

// PublishOutcome is delivered to a RunPublisher callback once its publish
// attempt resolves — either it completed (Err nil), it failed (Err set), or
// it was cancelled before the underlying Publish ran (Cancelled true).
type PublishOutcome struct {
	Err       error
	Cancelled bool
}

// RunPublisher is the supervised counterpart to the bare Publish
// primitive, matching macula_publisher.erl in spirit: it runs spec's
// publish in a background goroutine, delivers the outcome to onDone
// instead of blocking the caller, and publishes
// pubsub.publish_started_v1/pubsub.publish_completed_v1 mesh facts around
// it (same topics, same outcome shape: completed/cancelled/failed) using
// spec's own realm — exactly what macula_publisher.erl's internal
// publish/5 helper does.
//
// Unlike Erlang's version, Go's bare Publish is already a synchronous,
// near-instant frame send (no network round-trip to await — PUBLISH has no
// ack on this wire), so there is no meaningful window in which "cancel" can
// abort an in-flight wire write. The returned cancel function only prevents
// the publish from running at all if called before the background
// goroutine starts it; once started, cancel is a no-op and the real
// outcome (success or failure) is what gets delivered, matching Erlang's
// own behavior in practice (killing the worker process does not un-send a
// frame it already sent).
//
// onDone is called from a different goroutine than the caller's — do not
// assume it runs synchronously with RunPublisher's return.
func (s *Session) RunPublisher(spec frame.PublishSpec, id identity.KeyPair, announce bool, onDone func(PublishOutcome)) (cancel func()) {
	var cancelled atomic.Bool
	publishID := randomPublishID()

	announceFact(s, announce, spec.Realm, id, publishStartedTopic,
		cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("publish_id"), Val: cbor.Bytes(publishID)},
			{Key: cbor.Text("topic"), Val: cbor.Bytes([]byte(spec.Topic))},
		}))

	go func() {
		if cancelled.Load() {
			announceCompleted(s, announce, spec.Realm, id, publishID, PublishOutcome{Cancelled: true})
			onDone(PublishOutcome{Cancelled: true})
			return
		}
		err := s.Publish(spec, id)
		outcome := PublishOutcome{Err: err}
		announceCompleted(s, announce, spec.Realm, id, publishID, outcome)
		onDone(outcome)
	}()

	return func() { cancelled.Store(true) }
}

func randomPublishID() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never returns a short read or error per its own doc
	return b
}

func announceFact(s *Session, announce bool, realm []byte, id identity.KeyPair, topic string, payload cbor.Value) {
	if !announce {
		return
	}
	spec := frame.NewPublishSpec(topic, realm, id.NodeID(), factSeq(), payload, time.Now().UnixMilli())
	_ = s.Publish(spec, id)
}

func announceCompleted(s *Session, announce bool, realm []byte, id identity.KeyPair, publishID []byte, outcome PublishOutcome) {
	fields := []cbor.MapEntry{{Key: cbor.Text("publish_id"), Val: cbor.Bytes(publishID)}}
	switch {
	case outcome.Cancelled:
		fields = append(fields, cbor.MapEntry{Key: cbor.Text("outcome"), Val: cbor.Text("cancelled")})
	case outcome.Err != nil:
		fields = append(fields,
			cbor.MapEntry{Key: cbor.Text("outcome"), Val: cbor.Text("failed")},
			cbor.MapEntry{Key: cbor.Text("reason"), Val: cbor.Text(outcome.Err.Error())})
	default:
		fields = append(fields, cbor.MapEntry{Key: cbor.Text("outcome"), Val: cbor.Text("completed")})
	}
	announceFact(s, announce, realm, id, publishCompletedTopic, cbor.Map(fields))
}

// factSeq is a monotonically increasing counter for the started/completed
// meta-facts' own seq field — these are telemetry about a publish
// operation, not the business event itself, so there is no per-topic
// sequence to coordinate with; a process-wide monotonic counter is enough
// to avoid handing every meta-fact the same seq value.
var factSeqCounter atomic.Uint64

func factSeq() uint64 { return factSeqCounter.Add(1) }
