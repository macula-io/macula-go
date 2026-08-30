package frame

import "github.com/macula-io/macula-go/cbor"

// AdvertiseSpec holds the fields for an ADVERTISE frame — see
// plans/PLAN_WIRE_PROTOCOL.md §6.9.
type AdvertiseSpec struct {
	Realm      []byte
	Procedure  string
	Advertiser []byte
}

func NewAdvertiseSpec(realm []byte, procedure string, advertiser []byte) AdvertiseSpec {
	return AdvertiseSpec{Realm: realm, Procedure: procedure, Advertiser: advertiser}
}

// advertiseValue leaves source_route untouched (Null) -- confirmed
// directly against the reference, not assumed from CALL/STREAM_OPEN's
// pattern (which DO override it). realm IS overridden here, unlike
// RESULT/STREAM_DATA/etc.
func advertiseValue(spec AdvertiseSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("advertise", 0, frameID, sentAtMs)
	fields = withField(fields, "realm", cbor.Bytes(spec.Realm))
	fields = withField(fields, "procedure", cbor.Bytes([]byte(spec.Procedure)))
	fields = withField(fields, "advertiser", cbor.Bytes(spec.Advertiser))
	// options has no known use case yet -- always the reference's own
	// default, an empty map.
	fields = withField(fields, "options", cbor.Map(nil))
	return cbor.Map(fields)
}

// Advertise builds an ADVERTISE frame with a fresh frame_id/sent_at_ms.
func Advertise(spec AdvertiseSpec) cbor.Value {
	return advertiseValue(spec, freshFrameID(), currentMillis())
}

// UnadvertiseSpec holds the fields for an UNADVERTISE frame.
type UnadvertiseSpec struct {
	Realm      []byte
	Procedure  string
	Advertiser []byte
}

func NewUnadvertiseSpec(realm []byte, procedure string, advertiser []byte) UnadvertiseSpec {
	return UnadvertiseSpec{Realm: realm, Procedure: procedure, Advertiser: advertiser}
}

func unadvertiseValue(spec UnadvertiseSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("unadvertise", 0, frameID, sentAtMs)
	fields = withField(fields, "realm", cbor.Bytes(spec.Realm))
	fields = withField(fields, "procedure", cbor.Bytes([]byte(spec.Procedure)))
	fields = withField(fields, "advertiser", cbor.Bytes(spec.Advertiser))
	return cbor.Map(fields)
}

// Unadvertise builds an UNADVERTISE frame with a fresh frame_id/sent_at_ms.
func Unadvertise(spec UnadvertiseSpec) cbor.Value {
	return unadvertiseValue(spec, freshFrameID(), currentMillis())
}
