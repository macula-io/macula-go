package frame

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
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

// Every frame this package signs with a payload or body, as it is sent, holds
// no more than FrameReservedElements items besides its payload, so a payload
// CheckPayload accepts never pushes its frame past the budget.
func TestEveryFrameWithAPayloadHoldsItsOwnItemsWithinTheReserve(t *testing.T) {
	key, err := identity.GenerateKey(identity.PurposeIdentity, profile.PQHybrid)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	payload := cbor.Null()
	const at = uint64(1789000000000)
	mode := ServerStream
	spec := RequestSpec{Realm: [32]byte{1}, Procedure: "org/a.procedure", Target: key.KeyID(), Deadline: at, Payload: payload}
	call, err := SignCall(spec, key)
	if err != nil {
		t.Fatalf("SignCall: %v", err)
	}
	spec.Mode = &mode
	open, err := SignStreamOpen(spec, key)
	if err != nil {
		t.Fatalf("SignStreamOpen: %v", err)
	}
	request, err := VerifyRequest(call, profile.PQHybrid)
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	opened, err := VerifyRequest(open, profile.PQHybrid)
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	result, err := SignResult(request, payload, nil, key)
	if err != nil {
		t.Fatalf("SignResult: %v", err)
	}
	publish, err := SignPublish(PublicationSpec{Realm: [32]byte{1}, Topic: "a.topic", Seq: 1, PublishedAt: at, Payload: payload}, key)
	if err != nil {
		t.Fatalf("SignPublish: %v", err)
	}
	data, err := SignProviderStream(StreamDataFields{Seq: 0, Encoding: Msgpack, Body: payload}, opened, key)
	if err != nil {
		t.Fatalf("STREAM_DATA: %v", err)
	}
	reply, err := SignProviderStream(StreamReplyFields{Seq: 0, Payload: payload}, opened, key)
	if err != nil {
		t.Fatalf("STREAM_REPLY: %v", err)
	}
	frames := map[string]cbor.Value{"CALL": call, "RESULT": result, "PUBLISH": publish, "STREAM_OPEN": open,
		"STREAM_DATA": data, "STREAM_REPLY": reply}
	for name, f := range frames {
		if own := itemCount(f) - itemCount(payload); own > FrameReservedElements {
			t.Errorf("%s holds %d items besides its payload, more than the %d reserved", name, own, FrameReservedElements)
		}
	}
}
