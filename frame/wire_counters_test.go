package frame

import (
	"fmt"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// An unknown critical extension is refused naming every unknown critical name
// the ext map carries, and CountExtRefused counts each once (WIRE_1_0.md
// section 3.2). Both extension counters keep at most 64 names, the rest under
// other (section 8).
func TestEachRefusedExtensionNameCountsOnceUnderAtMost64Names(t *testing.T) {
	critical := func(names ...string) cbor.Value {
		entries := make([]cbor.MapEntry, len(names))
		for i, name := range names {
			entries[i] = cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Map([]cbor.MapEntry{
				{Key: cbor.Text("critical"), Val: cbor.Int(1)}, {Key: cbor.Text("value"), Val: cbor.Int(0)}})}
		}
		return cbor.Map(entries)
	}
	before := WireCounters().ExtRefused
	err := ActOnExt(critical("counted.a", "counted.b"))
	CountExtRefused(err)
	after := WireCounters().ExtRefused
	for _, name := range []string{"counted.a", "counted.b"} {
		if after[name] != before[name]+1 {
			t.Errorf("wire_ext_refused{%s} = %d, want %d", name, after[name], before[name]+1)
		}
	}
	for i := 0; i < 80; i++ {
		CountExtRefused(ActOnExt(critical(fmt.Sprintf("flood.n%d", i))))
	}
	if got := WireCounters().ExtRefused; len(got) > maxCountedNames+1 || got["other"] == 0 {
		t.Errorf("%d names counted, other %d: want at most %d names and the rest under other", len(got), got["other"], maxCountedNames)
	}
}
