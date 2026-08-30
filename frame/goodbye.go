package frame

import "github.com/macula-io/macula-go/cbor"

func goodbyeValue(reason string, detail *string, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("goodbye", 0, frameID, sentAtMs)
	// reason is an Erlang atom() -> text (major 3). detail is
	// binary() | undefined -> a raw byte string (major 2), NOT text.
	fields = append(fields, cbor.MapEntry{Key: cbor.Text("reason"), Val: cbor.Text(reason)})
	detailVal := cbor.Null()
	if detail != nil {
		detailVal = cbor.Bytes([]byte(*detail))
	}
	fields = append(fields, cbor.MapEntry{Key: cbor.Text("detail"), Val: detailVal})
	return cbor.Map(fields)
}

// Goodbye builds a GOODBYE frame. reason is a short machine-readable
// code (e.g. "normal"); detail is an optional human-readable string.
func Goodbye(reason string, detail *string) cbor.Value {
	return goodbyeValue(reason, detail, freshFrameID(), currentMillis())
}
