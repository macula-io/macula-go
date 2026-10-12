package frame

import (
	"errors"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// Wire 1.0's frame envelope (macula docs/design/WIRE_1_0.md section 3, macula#99).

func envelopeOf(frameType string, extra ...cbor.MapEntry) cbor.Value {
	return cbor.Map(append([]cbor.MapEntry{
		{Key: cbor.Text("version"), Val: cbor.Int(5)},
		{Key: cbor.Text("frame_type"), Val: cbor.Text(frameType)},
	}, extra...))
}

func extEntry(entries ...cbor.MapEntry) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text("ext"), Val: cbor.Map(entries)}
}

func extension(name string, critical int64, value cbor.Value) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("critical"), Val: cbor.Int(critical)},
		{Key: cbor.Text("value"), Val: value},
	})}
}

func keysOf(t *testing.T, frame cbor.Value) map[string]cbor.Value {
	t.Helper()
	entries, isMap := frame.AsMap()
	if !isMap {
		t.Fatalf("frame is not a map: %+v", frame)
	}
	keys := make(map[string]cbor.Value, len(entries))
	for _, e := range entries {
		name, _ := e.Key.AsText()
		keys[name] = e.Val
	}
	return keys
}

// Every frame a client builds carries version 5, no per-frame capabilities,
// and no optional envelope field it has no value for (one frame, one encoding).
func TestABuiltFrameCarriesVersionFiveAndOnlyTheFieldsItHas(t *testing.T) {
	goodbye, err := GoodbyeFrame("leaving", nil)
	if err != nil {
		t.Fatal(err)
	}
	subscribe, err := SubscribeFrame([]byte("t"), [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	for name, built := range map[string]cbor.Value{
		"advertise": AdvertiseFrame([]byte{1}),
		"goodbye":   goodbye,
		"subscribe": subscribe,
		"liveness":  LivenessPingFrame([16]byte{3}),
	} {
		keys := keysOf(t, built)
		if v, _ := keys["version"].AsInt64(); v != 5 {
			t.Errorf("%s: version %+v, want 5", name, keys["version"])
		}
		if _, has := keys["capabilities"]; has {
			t.Errorf("%s: carries the dropped capabilities header", name)
		}
		for _, optional := range []string{"realm", "call_id", "source_route"} {
			if v, has := keys[optional]; has && v.Kind() == cbor.KindNull {
				t.Errorf("%s: sends %s as null instead of leaving it out", name, optional)
			}
		}
	}
	if realm, _ := keysOf(t, subscribe)["realm"].AsBytes(); len(realm) != 32 {
		t.Errorf("subscribe: realm %x, want the 32-byte realm", realm)
	}
}

func TestAWellFormedEnvelopeIsReadWithItsFrameType(t *testing.T) {
	got, err := ReadEnvelope(envelopeOf("event"))
	if err != nil || got.FrameType != "event" {
		t.Fatalf("ReadEnvelope = %+v, %v; want event, nil", got, err)
	}
}

func TestAnEnvelopeOutsideTheWireOneRulesIsMalformed(t *testing.T) {
	long := strings.Repeat("x", 65)
	cases := map[string]cbor.Value{
		"version 2":            cbor.Map([]cbor.MapEntry{{Key: cbor.Text("version"), Val: cbor.Int(2)}, {Key: cbor.Text("frame_type"), Val: cbor.Text("event")}}),
		"version 4":            cbor.Map([]cbor.MapEntry{{Key: cbor.Text("version"), Val: cbor.Int(4)}, {Key: cbor.Text("frame_type"), Val: cbor.Text("event")}}),
		"no version":           cbor.Map([]cbor.MapEntry{{Key: cbor.Text("frame_type"), Val: cbor.Text("event")}}),
		"no frame_type":        cbor.Map([]cbor.MapEntry{{Key: cbor.Text("version"), Val: cbor.Int(5)}}),
		"empty frame_type":     envelopeOf(""),
		"65-byte frame_type":   envelopeOf(long),
		"frame_type not text":  cbor.Map([]cbor.MapEntry{{Key: cbor.Text("version"), Val: cbor.Int(5)}, {Key: cbor.Text("frame_type"), Val: cbor.Bytes([]byte("event"))}}),
		"capabilities header":  envelopeOf("event", cbor.MapEntry{Key: cbor.Text("capabilities"), Val: cbor.Int(0)}),
		"null realm":           envelopeOf("event", cbor.MapEntry{Key: cbor.Text("realm"), Val: cbor.Null()}),
		"31-byte realm":        envelopeOf("event", cbor.MapEntry{Key: cbor.Text("realm"), Val: cbor.Bytes(make([]byte, 31))}),
		"15-byte call_id":      envelopeOf("event", cbor.MapEntry{Key: cbor.Text("call_id"), Val: cbor.Bytes(make([]byte, 15))}),
		"15-byte frame_id":     envelopeOf("event", cbor.MapEntry{Key: cbor.Text("frame_id"), Val: cbor.Bytes(make([]byte, 15))}),
		"source_route as text": envelopeOf("event", cbor.MapEntry{Key: cbor.Text("source_route"), Val: cbor.Text("x")}),
		"empty ext":            envelopeOf("event", extEntry()),
		"ext not a map":        envelopeOf("event", cbor.MapEntry{Key: cbor.Text("ext"), Val: cbor.List(nil)}),
		"ext name uppercase":   envelopeOf("event", extEntry(extension("Trace", 0, cbor.Int(1)))),
		"ext name empty":       envelopeOf("event", extEntry(extension("", 0, cbor.Int(1)))),
		"ext name 65 bytes":    envelopeOf("event", extEntry(extension(long, 0, cbor.Int(1)))),
		"ext critical 2":       envelopeOf("event", extEntry(extension("trace", 2, cbor.Int(1)))),
		"ext entry extra key": envelopeOf("event", extEntry(cbor.MapEntry{Key: cbor.Text("trace"), Val: cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("critical"), Val: cbor.Int(0)}, {Key: cbor.Text("value"), Val: cbor.Int(1)}, {Key: cbor.Text("x"), Val: cbor.Int(1)},
		})})),
		"ext entry no value": envelopeOf("event", extEntry(cbor.MapEntry{Key: cbor.Text("trace"), Val: cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("critical"), Val: cbor.Int(0)},
		})})),
	}
	seventeen := make([]cbor.MapEntry, 17)
	for i := range seventeen {
		seventeen[i] = extension("e"+strings.Repeat("x", i), 0, cbor.Int(1))
	}
	cases["17 extensions"] = envelopeOf("event", extEntry(seventeen...))
	for name, v := range cases {
		if got, err := ReadEnvelope(v); !errors.Is(err, ErrMalformedFrame) {
			t.Errorf("%s: ReadEnvelope = %+v, %v; want ErrMalformedFrame", name, got, err)
		}
	}
}

// Sixteen extensions sit exactly at the bound (a bound case: it may tighten
// under LTS, never loosen).
func TestSixteenNonCriticalExtensionsAreIgnoredAndCounted(t *testing.T) {
	sixteen := make([]cbor.MapEntry, 16)
	for i := range sixteen {
		sixteen[i] = extension("e"+strings.Repeat("x", i), 0, cbor.Int(1))
	}
	before := WireCounters().ExtIgnored["e"]
	if _, err := ReadEnvelope(envelopeOf("event", extEntry(sixteen...))); err != nil {
		t.Fatalf("ReadEnvelope = %v, want the frame read", err)
	}
	if got := WireCounters().ExtIgnored["e"]; got != before+1 {
		t.Errorf("wire_ext_ignored{e} = %d, want %d", got, before+1)
	}
}

func TestAnUnknownCriticalExtensionRefusesTheFrame(t *testing.T) {
	v := envelopeOf("event", extEntry(extension("no_such.extension", 1, cbor.Int(1))))
	if _, err := ReadEnvelope(v); !errors.Is(err, ErrExtensionUnsupported) {
		t.Fatalf("ReadEnvelope = %v, want ErrExtensionUnsupported", err)
	}
}

// An ignored extension is read past: the envelope comes back without ext, so
// the frame type's own table never sees it. The counter's label is the name,
// which the envelope rule bounds to 64 bytes.
func TestAnUnknownNonCriticalExtensionIsIgnoredAndCountedByName(t *testing.T) {
	name := "trace.id"
	before := WireCounters().ExtIgnored[name]
	got, err := ReadEnvelope(envelopeOf("event", extEntry(extension(name, 0, cbor.Bytes([]byte{9})))))
	if err != nil {
		t.Fatalf("ReadEnvelope = %v, want the frame read", err)
	}
	if _, has := keysOf(t, got.Frame)["ext"]; has {
		t.Errorf("the read frame still carries ext")
	}
	if after := WireCounters().ExtIgnored[name]; after != before+1 {
		t.Errorf("wire_ext_ignored{%s} = %d, want %d", name, after, before+1)
	}
}

func TestAnUnknownFrameTypeIsCountedWithoutALabel(t *testing.T) {
	before := WireCounters().UnknownFrameType
	CountUnknownFrameType()
	if got := WireCounters().UnknownFrameType; got != before+1 {
		t.Errorf("wire_unknown_frame_type = %d, want %d", got, before+1)
	}
}
