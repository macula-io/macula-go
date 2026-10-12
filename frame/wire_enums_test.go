package frame

import (
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// Wire 1.0's unknown enum values (macula docs/design/WIRE_1_0.md section 3.4,
// macula#99): one never closes a link. In a per-hop slot it reads as the field's
// fallback and is counted; inside a signed tbs it refuses that object, by name.

func TestAKnownPerHopEnumValueReadsAsItself(t *testing.T) {
	before := WireCounters().EnumFallback["delivered_via"]
	if got := ReadPerHopEnum("delivered_via", "plumtree", "direct", "plumtree", "direct"); got != "plumtree" {
		t.Errorf("ReadPerHopEnum = %q, want plumtree", got)
	}
	if got := WireCounters().EnumFallback["delivered_via"]; got != before {
		t.Errorf("wire_enum_fallback{delivered_via} moved to %d for a known value", got)
	}
}

func TestAnUnknownPerHopEnumValueReadsAsItsFallbackAndIsCounted(t *testing.T) {
	before := WireCounters().EnumFallback["priority"]
	if got := ReadPerHopEnum("priority", "urgent", "low", "high", "low"); got != "low" {
		t.Errorf("ReadPerHopEnum = %q, want the fallback low", got)
	}
	if got := WireCounters().EnumFallback["priority"]; got != before+1 {
		t.Errorf("wire_enum_fallback{priority} = %d, want %d", got, before+1)
	}
}

// An EVENT's delivered_via is per-hop: an unknown value reads as direct, and
// the publication it carries still verifies.
func TestAnEventDeliveredAnUnknownWayIsReadAsDirect(t *testing.T) {
	keys := requestKeysFor(t)
	publish := must[cbor.Value](t)(SignPublish(publishSpecAt(testNow), keys.caller))
	event := carrying(t, publish, frameTypeEvent, "delivered_via", cbor.Text("gossip_v2"))
	if _, err := verifyAt(t, event, testNow); err != nil {
		t.Fatalf("an EVENT delivered by gossip_v2: %v, want its publication verified", err)
	}
	before := WireCounters().EnumFallback["delivered_via"]
	if got := DeliveredVia(event); got != "direct" {
		t.Errorf("DeliveredVia = %q, want the fallback direct", got)
	}
	if got := WireCounters().EnumFallback["delivered_via"]; got != before+1 {
		t.Errorf("wire_enum_fallback{delivered_via} = %d, want %d", got, before+1)
	}
	if got := DeliveredVia(carrying(t, publish, frameTypeEvent, "delivered_via", cbor.Text("plumtree"))); got != "plumtree" {
		t.Errorf("DeliveredVia = %q, want plumtree", got)
	}
}

func wantEnumUnknown(t *testing.T, name string, err error, field string) {
	t.Helper()
	var unknown *EnumUnknownError
	if !errors.As(err, &unknown) || unknown.Field != field || !errors.Is(err, ErrEnumUnknown) {
		t.Errorf("%s: %v, want enum_unknown naming %s", name, err, field)
	}
}

// A STREAM_OPEN's mode is inside the request tbs: an unknown one refuses the
// request, enum_unknown naming mode.
func TestAStreamOpenOfAnUnknownModeIsRefusedNamingMode(t *testing.T) {
	keys := requestKeysFor(t)
	fields := withEntry(withEntry(requestTBS(keys), "frame_type", cbor.Text(frameTypeStreamOpen)), "mode", cbor.Text("duplex_v2"))
	wantEnumUnknown(t, "a STREAM_OPEN in mode duplex_v2", verifyCraftedRequest(t, frameTypeStreamOpen, fields, keys.caller), "mode")
}

func TestAStreamFrameOfAnUnknownEncodingOrRoleIsRefusedByName(t *testing.T) {
	keys := requestKeysFor(t)
	open := streamOpenOf(t, keys, Bidi, idOf(7))
	signer := keys.provider.KeyID()
	data := streamTBSOf(open, frameTypeStreamData, signer, 0, textEntry("encoding", "cbor_v2"), bytesEntry("body", []byte("x")))
	_, _, err := verifyProvider(t, crafted(frameTypeStreamData, "stream", signedWith(t, streamLabel, data, keys.provider)), streamStateOf(t, open))
	wantEnumUnknown(t, "a STREAM_DATA of encoding cbor_v2", err, "encoding")
	end := streamTBSOf(open, frameTypeStreamEnd, signer, 0, textEntry("role", "half_v2"))
	_, _, err = verifyProvider(t, crafted(frameTypeStreamEnd, "stream", signedWith(t, streamLabel, end, keys.provider)), streamStateOf(t, open))
	wantEnumUnknown(t, "a STREAM_END of role half_v2", err, "role")
}

func TestARelayErrorOfAnUnknownCodeIsRefusedNamingCode(t *testing.T) {
	keys := requestKeysFor(t)
	request := verifiedCall(t, keys)
	fields := withEntry(relayTBS(request, keys.station), "code", cbor.Text("route_withdrawn_v2"))
	relay := crafted(frameTypeError, "relay_error", signedWith(t, relayErrorLabel, fields, keys.station))
	_, err := VerifyRelayError(onWire(t, relay), request, profile.PQPure, keys.station.KeyID())
	wantEnumUnknown(t, "a relay error of code route_withdrawn_v2", err, "code")
}
