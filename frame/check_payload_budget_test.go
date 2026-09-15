package frame

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

// itemCount is how many CBOR items v holds, itself included: every list
// element, map key and map value counts once, as the decoding rule's element
// budget counts them.
func itemCount(v cbor.Value) int {
	n := 1
	if items, ok := v.AsList(); ok {
		for _, item := range items {
			n += itemCount(item)
		}
	}
	if entries, ok := v.AsMap(); ok {
		for _, e := range entries {
			n += itemCount(e.Key) + itemCount(e.Val)
		}
	}
	return n
}

// zerosList is a list of n zeros, which is n+1 items.
func zerosList(n int) cbor.Value {
	items := make([]cbor.Value, n)
	for i := range items {
		items[i] = cbor.Uint64(0)
	}
	return cbor.List(items)
}

// A payload of MaxPayloadElements items is sendable and one more item is not,
// and a payload at the limit, inside a frame's map, stays within the decoding
// rule's element budget.
func TestCheckPayloadKeepsAPayloadWithinTheElementBudget(t *testing.T) {
	atLimit := zerosList(MaxPayloadElements - 1)
	if n := itemCount(atLimit); n != MaxPayloadElements {
		t.Fatalf("the payload at the limit holds %d items, want %d", n, MaxPayloadElements)
	}
	if err := CheckPayload(atLimit); err != nil {
		t.Errorf("a payload of %d items: %v, want it sendable", MaxPayloadElements, err)
	}
	if err := CheckPayload(zerosList(MaxPayloadElements)); err == nil {
		t.Errorf("a payload of %d items was accepted, want it refused", MaxPayloadElements+1)
	}
	if _, err := cbor.Decode(cbor.Encode(inFrameMap(atLimit))); err != nil {
		t.Errorf("a frame's map around the payload at the limit: %v, want it within the budget", err)
	}
}

// Every frame this package builds with a payload, body or args, signed as it is
// sent, holds no more than FrameReservedElements items besides its payload, so
// a payload CheckPayload accepts never pushes its frame past the budget.
func TestEveryFrameWithAPayloadHoldsItsOwnItemsWithinTheReserve(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	id16, id32 := make([]byte, 16), make([]byte, 32)
	payload := cbor.Null()
	const at = int64(1789000000000)
	frames := map[string]cbor.Value{
		"CALL":         Sign(Call(NewCallSpec(id16, "a.procedure", id32, payload, at, id.NodeID())), id),
		"RESULT":       Sign(Result(NewResultSpec(id16, payload, id.NodeID())), id),
		"PUBLISH":      SignPublisher(Sign(Publish(NewPublishSpec("a.topic", id32, id.NodeID(), 1, payload, at)), id), id),
		"STREAM_OPEN":  Sign(StreamOpen(NewStreamOpenSpec(id16, "a.procedure", id32, ServerStream, payload, at, id.NodeID())), id),
		"STREAM_DATA":  Sign(StreamData(NewStreamDataSpec(id16, 1, Msgpack, payload, id.NodeID())), id),
		"STREAM_REPLY": Sign(StreamReply(NewStreamReplySpec(id16, payload, id.NodeID())), id),
	}
	for name, f := range frames {
		if own := itemCount(f) - itemCount(payload); own > FrameReservedElements {
			t.Errorf("%s holds %d items besides its payload, more than the %d reserved", name, own, FrameReservedElements)
		}
	}
}
