package stationlink

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/frame"
)

// A Stream holds its open in an unexported field, which fmt would print by
// reflection without the open's own Format.
func TestAStreamPrintsNoCredential(t *testing.T) {
	grant := []byte("eyJhbGciOiJFZERTQSJ9.secret-grant")
	s := &Stream{open: frame.VerifiedRequest{Procedure: "acme/do", Token: grant, Proofs: [][]byte{[]byte("secret-proof")}}, caller: true}
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("x", "stream", s)
	outs := []string{b.String()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		outs = append(outs, fmt.Sprintf(verb, s), fmt.Sprintf(verb, struct{ S *Stream }{s}))
	}
	for _, out := range outs {
		if strings.Contains(out, "secret-") || strings.Contains(out, "0x65, 0x79") || !strings.Contains(out, "<grant, 33 bytes>") {
			t.Errorf("a stream printed its credential or hid its open: %s", out)
		}
	}
	if got := fmt.Sprint((*Stream)(nil)); got != "<nil>" {
		t.Errorf("a nil stream: %s", got)
	}
}
