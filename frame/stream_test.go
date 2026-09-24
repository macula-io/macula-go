package frame

import "testing"

// Each stream mode, encoding and role reads back from its wire name.
func TestStreamModeEncodingRoleNameRoundTrip(t *testing.T) {
	for _, m := range []StreamMode{ServerStream, ClientStream, Bidi} {
		got, ok := streamModeFromName(m.Name())
		if !ok || got != m {
			t.Errorf("StreamMode %v round trip failed via name %q", m, m.Name())
		}
	}
	for _, e := range []StreamEncoding{Raw, Msgpack} {
		got, ok := streamEncodingFromName(e.Name())
		if !ok || got != e {
			t.Errorf("StreamEncoding %v round trip failed via name %q", e, e.Name())
		}
	}
	for _, r := range []StreamRole{Send, Both} {
		got, ok := streamRoleFromName(r.Name())
		if !ok || got != r {
			t.Errorf("StreamRole %v round trip failed via name %q", r, r.Name())
		}
	}
}
