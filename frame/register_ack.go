package frame

import (
	"fmt"
	"slices"

	"github.com/macula-io/macula-go/cbor"
)

// REGISTER_ACK (macula docs/design/WIRE_1_0.md section 3.5, macula#12) is the
// station's answer to an ADVERTISE, UNADVERTISE, SUBSCRIBE or UNSUBSCRIBE, on
// the control stream, unsigned. Its kind and reason are per-hop enums: an ack
// of a kind this library does not know is ignored, and a reason it does not
// know reads as refused, each counted as wire_enum_fallback.

// RegisterAck is a REGISTER_ACK as read: the frame it answers (Kind), the
// realm and name (the procedure or topic), the record version an advertise
// kind names or the subscriber a subscribe kind names, and whether the station
// accepted, with its Reason when it did not.
type RegisterAck struct {
	Kind          string
	Realm         [32]byte
	Name          string
	RecordVersion [16]byte
	Subscriber    [32]byte
	Accepted      bool
	Reason        string
}

// The kinds and refusal reasons section 3.5 names; refused is the generic
// reason, and what an unknown one reads as.
var (
	registerAckKinds   = []string{"advertise", "unadvertise", "subscribe", "unsubscribe"}
	registerAckReasons = []string{"too_many_providers", "advertiser_quota", "name_too_long", "record_refused",
		"not_authorized", "too_many_realms", "refused"}
)

// maxRegisterAckNameBytes bounds a REGISTER_ACK's name, a procedure or topic.
const maxRegisterAckNameBytes = 512

// ReadRegisterAck reads a REGISTER_ACK whose envelope is already read
// (ReadEnvelope). An ack of a kind this library does not know is ignored and
// counted: known is false and err nil. Otherwise it holds exactly the envelope
// keys, kind, realm (32 bytes), name (1 to 512 bytes of text), accepted (0 or
// 1), and reason (text) exactly when accepted is 0, and the record_version (16
// bytes) of an advertise or unadvertise or the subscriber (32 bytes) of a
// subscribe or unsubscribe, never both and never the other kind's: anything
// else is ErrMalformedFrame.
func ReadRegisterAck(v cbor.Value) (ack RegisterAck, known bool, err error) {
	kindValue, _ := v.Get("kind")
	kind, isText := kindValue.AsText()
	if !isText {
		return RegisterAck{}, false, ErrMalformedFrame
	}
	if !slices.Contains(registerAckKinds, kind) {
		countEnumFallback("kind")
		return RegisterAck{}, false, nil
	}
	advertise := kind == "advertise" || kind == "unadvertise"
	table := map[string]fieldRule{
		"version":    protocolVersion,
		"frame_type": textIn("register_ack"),
		"frame_id":   envelopeRules["frame_id"],
		"sent_at_ms": envelopeRules["sent_at_ms"],
		"kind":       textIn(kind),
		"realm":      bytesOf(32),
		"name":       nonEmptyTextWithin(maxRegisterAckNameBytes),
		"accepted":   zeroOrOne,
		"reason":     anyText,
	}
	required := []string{"version", "frame_type", "kind", "realm", "name", "accepted"}
	if advertise {
		table["record_version"] = bytesOf(16)
		required = append(required, "record_version")
	} else {
		table["subscriber"] = bytesOf(32)
		required = append(required, "subscriber")
	}
	fields, ok := readFields(v, table)
	if !ok || !hasFields(fields, required...) {
		return RegisterAck{}, false, ErrMalformedFrame
	}
	accepted, _ := fields["accepted"].AsInt64()
	reason, hasReason := fields["reason"]
	if hasReason == (accepted == 1) {
		return RegisterAck{}, false, ErrMalformedFrame
	}
	ack = RegisterAck{Kind: kind, Name: textOf(fields["name"]), Accepted: accepted == 1}
	copy(ack.Realm[:], bytesOf32(fields["realm"]))
	if advertise {
		version, _ := fields["record_version"].AsBytes()
		copy(ack.RecordVersion[:], version)
	} else {
		copy(ack.Subscriber[:], bytesOf32(fields["subscriber"]))
	}
	if hasReason {
		ack.Reason = ReadPerHopEnum("reason", textOf(reason), "refused", registerAckReasons...)
	}
	return ack, true, nil
}

func bytesOf32(v cbor.Value) []byte {
	b, _ := v.AsBytes()
	return b
}

func anyText(v cbor.Value) bool {
	_, isText := v.AsText()
	return isText
}

func nonEmptyTextWithin(max int) fieldRule {
	return func(v cbor.Value) bool {
		s, isText := v.AsText()
		return isText && len(s) > 0 && len(s) <= max
	}
}

// RegisterAckFrame is a station's REGISTER_ACK answering ack.Kind (WIRE_1_0.md
// section 3.5): the record version for an advertise kind, the subscriber for a
// subscribe kind, and the reason exactly when it refuses. A kind or a reason
// section 3.5 does not name, or a name that is empty or over 512 bytes, is
// ErrMalformedFrame, since no reader would take it.
func RegisterAckFrame(ack RegisterAck) (cbor.Value, error) {
	switch {
	case !slices.Contains(registerAckKinds, ack.Kind):
		return cbor.Value{}, fmt.Errorf("%w: a REGISTER_ACK of kind %q", ErrMalformedFrame, ack.Kind)
	case ack.Name == "" || len(ack.Name) > maxRegisterAckNameBytes:
		return cbor.Value{}, fmt.Errorf("%w: a REGISTER_ACK name of %d bytes", ErrMalformedFrame, len(ack.Name))
	case ack.Accepted != (ack.Reason == ""):
		return cbor.Value{}, fmt.Errorf("%w: a REGISTER_ACK has a reason exactly when it refuses", ErrMalformedFrame)
	case !ack.Accepted && !slices.Contains(registerAckReasons, ack.Reason):
		return cbor.Value{}, fmt.Errorf("%w: a REGISTER_ACK reason %q", ErrMalformedFrame, ack.Reason)
	}
	accepted := 0
	if ack.Accepted {
		accepted = 1
	}
	fields := append(base("register_ack", freshFrameID(), currentMillis()),
		textEntry("kind", ack.Kind), bytesEntry("realm", ack.Realm[:]), textEntry("name", ack.Name),
		valueEntry("accepted", cbor.Int(int64(accepted))))
	if ack.Kind == "advertise" || ack.Kind == "unadvertise" {
		fields = append(fields, bytesEntry("record_version", ack.RecordVersion[:]))
	} else {
		fields = append(fields, bytesEntry("subscriber", ack.Subscriber[:]))
	}
	if !ack.Accepted {
		fields = append(fields, textEntry("reason", ack.Reason))
	}
	return cbor.Map(fields), nil
}
