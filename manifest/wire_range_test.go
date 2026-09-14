package manifest

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// past32Bits is n plus 2^32, a number a uint32 or a 32-bit int reads as n.
func past32Bits(n int) cbor.Value {
	return cbor.Uint64(uint64(n) + 1<<32)
}

// withEntry is entries as a map, with field's value set to value.
func withEntry(entries []cbor.MapEntry, field string, value cbor.Value) cbor.Value {
	out := make([]cbor.MapEntry, len(entries))
	for i, e := range entries {
		out[i] = entryWith(e, field, value)
	}
	return cbor.Map(out)
}

// entryWith is e with its value set to value when its key is field.
func entryWith(e cbor.MapEntry, field string, value cbor.Value) cbor.MapEntry {
	if key, _ := e.Key.AsText(); key == field {
		e.Val = value
	}
	return e
}

// withChunkEntry is wire, a manifest's wire map entries, with field of its
// chunk i set to value.
func withChunkEntry(wire []cbor.MapEntry, i int, field string, value cbor.Value) cbor.Value {
	chunksVal, _ := cbor.Map(wire).Get("chunks")
	chunks, _ := chunksVal.AsList()
	changed := append([]cbor.Value(nil), chunks...)
	chunk, _ := changed[i].AsMap()
	changed[i] = withEntry(chunk, field, value)
	return withEntry(wire, "chunks", cbor.List(changed))
}

// FromWire refuses a number too large for the field it fills instead of
// letting it wrap: a version past 32 bits, and a chunk size, chunk count, or
// chunk index, offset or size past the range of an int. Each number here is
// the manifest's own plus 2^32, which a uint32 or a 32-bit int reads as the
// manifest's own, so on a 32-bit platform only that check refuses it.
func TestFromWireRefusesANumberTooLargeForItsField(t *testing.T) {
	m := threeChunks()
	wire, _ := ToWire(m).AsMap()
	if _, err := FromWire(cbor.Map(wire)); err != nil {
		t.Fatalf("FromWire of the manifest as created: %v", err)
	}
	last := m.Chunks[len(m.Chunks)-1]
	cases := map[string]cbor.Value{
		"version":        withEntry(wire, "version", past32Bits(int(m.Version))),
		"chunk_size":     withEntry(wire, "chunk_size", past32Bits(m.ChunkSize)),
		"chunk_count":    withEntry(wire, "chunk_count", past32Bits(m.ChunkCount)),
		"a chunk index":  withChunkEntry(wire, last.Index, "index", past32Bits(last.Index)),
		"a chunk offset": withChunkEntry(wire, last.Index, "offset", past32Bits(last.Offset)),
		"a chunk size":   withChunkEntry(wire, last.Index, "size", past32Bits(last.Size)),
	}
	for name, value := range cases {
		if _, err := FromWire(value); err == nil {
			t.Errorf("%s plus 2^32: FromWire accepted the manifest", name)
		}
	}
}
