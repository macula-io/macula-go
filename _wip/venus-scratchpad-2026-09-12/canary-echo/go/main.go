// Canary caller for io.macula.echo using macula-go v0.7.1: the caller half
// of examples/quickstart (one fresh identity, no advertise, no serve).
// Prepared for the hecate-echo on macula 10.24.0 canary; run only when
// Saturnus calls the baseline. Two calls, no loops.
//
// Match rule (Saturnus): "match" is a content match that ignores text versus
// bytes and map key order. Go can see both, so "exact_match" is also
// reported: the reply's CBOR encoding byte-identical to what was sent. An
// encoding change then shows as exact_match flipping while match stays true.
//
// Usage: MACULA_CANARY_RUN=<run id> canary-echo-go <station-host> [port]
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

const (
	procedure  = "io.macula.echo"
	sdk        = "macula-go"
	sdkVersion = "v0.7.1"
)

type record struct {
	SDK         string  `json:"sdk"`
	SDKVersion  string  `json:"sdk_version"`
	Run         string  `json:"run"`
	Station     string  `json:"station"`
	UTC         string  `json:"utc"`
	Call        string  `json:"call"`
	Match       bool    `json:"match"`
	ExactMatch  bool    `json:"exact_match"`
	DurationMs  int64   `json:"duration_ms"`
	IsError     bool    `json:"is_error"`
	Code        *uint8  `json:"code,omitempty"`
	Name        string  `json:"name,omitempty"`
	Detail      *string `json:"detail,omitempty"`
	ReportedBy  string  `json:"reported_by,omitempty"`
	RespondedBy string  `json:"responded_by,omitempty"`
	ReplyKind   string  `json:"reply_kind,omitempty"`
	Reply       string  `json:"reply,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// runID is the run id Saturnus names, from MACULA_CANARY_RUN.
var runID string

func emit(r record) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

func base(station, call string) record {
	return record{SDK: sdk, SDKVersion: sdkVersion, Run: runID, Station: station, UTC: time.Now().UTC().Format(time.RFC3339Nano), Call: call}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: canary-echo-go <station-host> [port]")
		os.Exit(2)
	}
	host := os.Args[1]
	port := uint16(4433)
	if len(os.Args) > 2 {
		p, err := strconv.Atoi(os.Args[2])
		if err != nil || p <= 0 || p > 65535 {
			fmt.Fprintln(os.Stderr, "bad port:", os.Args[2])
			os.Exit(2)
		}
		port = uint16(p)
	}
	runID = os.Getenv("MACULA_CANARY_RUN")
	if runID == "" {
		fmt.Fprintln(os.Stderr, "MACULA_CANARY_RUN (the run id Saturnus names) is required")
		os.Exit(2)
	}
	station := fmt.Sprintf("%s:%d", host, port)
	realm := make([]byte, 32) // the all-zero realm

	id, err := identity.Generate()
	if err != nil {
		r := base(station, "identity")
		r.Error = err.Error()
		emit(r)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	connStart := time.Now()
	session, err := connection.Connect(ctx, host, port, transport.WebPKI{}, id)
	if err != nil {
		r := base(station, "connect")
		r.DurationMs = time.Since(connStart).Milliseconds()
		r.Error = err.Error()
		emit(r)
		os.Exit(1)
	}
	defer session.Close("normal", nil, id)

	ok := callAndRecord(session, id, station, realm, "hello", cbor.Text("hello"))
	sent := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("sdk"), Val: cbor.Text(sdk)},
		{Key: cbor.Text("sdk_version"), Val: cbor.Text(sdkVersion)},
		{Key: cbor.Text("run"), Val: cbor.Text(runID)},
	})
	ok = callAndRecord(session, id, station, realm, "map", sent) && ok
	if !ok {
		os.Exit(1)
	}
}

func callAndRecord(s *connection.Session, id identity.KeyPair, station string, realm []byte, call string, payload cbor.Value) bool {
	r := base(station, call)
	start := time.Now()
	resp, err := s.Call(procedure, realm, payload, time.Now().Add(5*time.Second).UnixMilli(), id, 5*time.Second)
	r.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		r.Error = err.Error()
		emit(r)
		return false
	}
	if resp.IsError {
		r.IsError = true
		code := resp.Code
		r.Code = &code
		r.Name = resp.Name
		r.Detail = resp.Detail
		r.ReportedBy = hex.EncodeToString(resp.ReportedBy)
		emit(r)
		return false
	}
	r.RespondedBy = hex.EncodeToString(resp.RespondedBy)
	r.ReplyKind = kindName(resp.Payload.Kind())
	r.Reply = resp.Payload.String()
	r.Match = contentOf(payload) == contentOf(resp.Payload)
	r.ExactMatch = bytes.Equal(cbor.Encode(payload), cbor.Encode(resp.Payload))
	emit(r)
	return r.Match
}

// contentOf renders v so that text and bytes with the same content compare
// equal and map entries compare regardless of order. Lengths are prefixed so
// no two different contents can render the same.
func contentOf(v cbor.Value) string {
	switch v.Kind() {
	case cbor.KindText:
		s, _ := v.AsText()
		return fmt.Sprintf("s%d:%s", len(s), s)
	case cbor.KindBytes:
		b, _ := v.AsBytes()
		return fmt.Sprintf("s%d:%s", len(b), b)
	case cbor.KindMap:
		entries, _ := v.AsMap()
		parts := make([]string, 0, len(entries))
		for _, e := range entries {
			k, val := contentOf(e.Key), contentOf(e.Val)
			parts = append(parts, fmt.Sprintf("%d:%s%d:%s", len(k), k, len(val), val))
		}
		sort.Strings(parts)
		return "m{" + strings.Join(parts, "") + "}"
	default:
		return "x:" + hex.EncodeToString(cbor.Encode(v))
	}
}

func kindName(k cbor.Kind) string {
	switch k {
	case cbor.KindText:
		return "text"
	case cbor.KindBytes:
		return "bytes"
	case cbor.KindMap:
		return "map"
	case cbor.KindList:
		return "list"
	case cbor.KindUInt, cbor.KindNegInt:
		return "int"
	case cbor.KindFloat:
		return "float"
	case cbor.KindNull:
		return "null"
	}
	return fmt.Sprintf("kind-%d", int(k))
}
