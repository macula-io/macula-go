package redact_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/group"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/stationlink"
)

var (
	grant = []byte("eyJhbGciOiJFZERTQSJ9.secret-grant")
	proof = []byte("eyJhbGciOiJFZERTQSJ9.secret-proof")
)

// leaks reports whether out shows a credential's bytes in any form fmt
// writes them: as text, in hex, as decimal or as Go syntax.
func leaks(out string) bool {
	for _, b := range [][]byte{grant, proof} {
		goSyntax := strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", b), "[]byte{"), "}")
		if strings.Contains(out, "secret-") || strings.Contains(out, fmt.Sprintf("%x", b)) ||
			strings.Contains(out, strings.Trim(fmt.Sprint(b), "[]")) || strings.Contains(out, goSyntax) {
			return true
		}
	}
	return false
}

func TestNoCredentialCarrierPrintsItsCredential(t *testing.T) {
	proofs := [][]byte{proof}
	carriers := map[string]any{
		"frame.RequestSpec":      frame.RequestSpec{Procedure: "acme/do", Token: grant, Proofs: proofs},
		"frame.VerifiedRequest":  frame.VerifiedRequest{Procedure: "acme/do", Token: grant, Proofs: proofs},
		"pool.Call":              pool.Call{Procedure: "acme/do", Token: grant, Proofs: proofs},
		"pool.StreamCall":        pool.StreamCall{Procedure: "acme/do", Token: grant, Proofs: proofs},
		"pool.Group":             pool.Group{Prefix: "io.macula/acme/chat", UCAN: grant},
		"stationlink.Call":       stationlink.Call{Procedure: "acme/do", Token: grant, Proofs: proofs},
		"stationlink.StreamCall": stationlink.StreamCall{Procedure: "acme/do", Token: grant, Proofs: proofs},
		"stationlink.Request":    stationlink.Request{Procedure: "acme/do", Token: grant, Proofs: proofs},
		"group.Pull":             group.Pull{Procedure: "acme/group_keys_v1", Token: grant},
		"group.JoinOptions":      group.JoinOptions{UCAN: grant},
	}
	for name, c := range carriers {
		ptr := reflect.New(reflect.TypeOf(c))
		ptr.Elem().Set(reflect.ValueOf(c))
		for _, v := range []any{c, ptr.Interface(), struct{ Inner any }{c}} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
				out := fmt.Sprintf(verb, v)
				if leaks(out) {
					t.Errorf("%s with %s printed its credential: %s", name, verb, out)
				}
			}
		}
		if out := fmt.Sprintf("%+v", c); !strings.Contains(out, fmt.Sprintf("<grant, %d bytes>", len(grant))) {
			t.Errorf("%s does not name its grant: %s", name, out)
		}
		for _, v := range []any{c, ptr.Interface()} {
			if out := jsonLog(v); leaks(out) || !strings.Contains(out, "<grant, ") {
				t.Errorf("%s through slog's JSON handler: %s", name, out)
			}
		}
	}
}

// jsonLog logs v through slog's JSON handler, which marshals a value
// rather than formatting it, and returns the line.
func jsonLog(v any) string {
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("x", "v", v)
	return b.String()
}

func TestAStreamStatePrintsNoCredential(t *testing.T) {
	mode := frame.ServerStream
	state, err := frame.OpenStream(frame.VerifiedRequest{FrameType: "stream_open", Mode: &mode, Token: grant, Proofs: [][]byte{proof}})
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, state); leaks(out) || !strings.Contains(out, "<grant, ") {
			t.Errorf("%s: %s", verb, out)
		}
	}
	if out := jsonLog(state); leaks(out) {
		t.Errorf("slog JSON: %s", out)
	}
}
