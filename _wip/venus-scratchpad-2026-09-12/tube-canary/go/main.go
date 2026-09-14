// Tube canary caller for hecate-tube (beam02, macula 10.18.0 to 10.24.0), using
// macula-go v0.7.1. Prepared for Saturnus's tube canary; run only on his "go".
//
// One run, one station, two identities:
//   - identity A holds the station session and makes tube.lookup_channel and
//     tube.lookup_video_clip as plain calls in io.macula, ids as CBOR bytes;
//   - identity B dials the provider directly for tube.watch_video_clip
//     (server_stream, clip id as CBOR bytes), read to the end, recording byte
//     count, chunk count, sha256 of the received bytes and duration.
//
// The known hazard hecate-tube#3 is retried once and marked: a lookup answered
// bad_request, or a stream aborted with code "cancelled" and bad_request in its
// message before any data (macula_streamer's form of handle_open's bad_request).
// A second occurrence is a failure. StationEndpointNotFound is its own outcome. Lookup content is digested without view_count, since every
// stream run records a view (see stripViewCounts).
//
// Usage: MACULA_CANARY_RUN=<run id> tube-canary-go <station-host> [port]
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/directdial"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/stream"
	"github.com/macula-io/macula-go/transport"
)

const (
	sdk        = "macula-go"
	sdkVersion = "v0.7.1"
	realmHex   = "abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1"
	channelID  = "channel-01a04717ace27d1fa41aed430d0ec70a"
	clipID     = "clip-01a0471969fd71c2930cc459a797e6ca"

	callTimeout  = 10 * time.Second
	dialTimeout  = 20 * time.Second
	chunkTimeout = 30 * time.Second
	streamCap    = 10 * time.Minute
)

var runID, station string

func emit(fields map[string]any) {
	fields["sdk"] = sdk
	fields["sdk_version"] = sdkVersion
	fields["run"] = runID
	fields["station"] = station
	if _, ok := fields["utc"]; !ok {
		fields["utc"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, _ := json.Marshal(fields)
	fmt.Println(string(b))
}

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: MACULA_CANARY_RUN=<run id> tube-canary-go <station-host> [port]")
		return 2
	}
	host := os.Args[1]
	port := uint16(4433)
	if len(os.Args) > 2 {
		p, err := strconv.Atoi(os.Args[2])
		if err != nil || p <= 0 || p > 65535 {
			fmt.Fprintln(os.Stderr, "bad port:", os.Args[2])
			return 2
		}
		port = uint16(p)
	}
	runID = os.Getenv("MACULA_CANARY_RUN")
	if runID == "" {
		fmt.Fprintln(os.Stderr, "MACULA_CANARY_RUN (the run id Saturnus names) is required")
		return 2
	}
	station = fmt.Sprintf("%s:%d", host, port)
	realm, _ := hex.DecodeString(realmHex)

	idA, errA := identity.Generate()
	idB, errB := identity.Generate()
	if err := errors.Join(errA, errB); err != nil {
		emit(map[string]any{"call": "identities", "outcome": "error", "error": err.Error()})
		return 1
	}
	emit(map[string]any{"call": "identities", "identity_a": fmt.Sprintf("%x", idA.NodeID()), "identity_b": fmt.Sprintf("%x", idB.NodeID())})

	ctx, cancel := context.WithTimeout(context.Background(), streamCap+2*time.Minute)
	defer cancel()
	connStart := time.Now()
	session, err := connection.Connect(ctx, host, port, transport.WebPKI{}, idA)
	if err != nil {
		emit(map[string]any{"call": "connect", "outcome": "error", "duration_ms": time.Since(connStart).Milliseconds(), "error": err.Error()})
		return 1
	}
	defer session.Close("normal", nil, idA)

	// MACULA_CANARY_ONLY=stream skips the lookups, for a stream-only re-run Saturnus asks for.
	ok := true
	if os.Getenv("MACULA_CANARY_ONLY") != "stream" {
		ok = lookup(session, idA, realm, "tube.lookup_channel", "channel_id", channelID)
		ok = lookup(session, idA, realm, "tube.lookup_video_clip", "clip_id", clipID) && ok
	}
	ok = watch(ctx, session, idB, realm) && ok
	if !ok {
		return 1
	}
	return 0
}

func lookup(s *connection.Session, id identity.KeyPair, realm []byte, procedure, key, value string) bool {
	payload := cbor.Map([]cbor.MapEntry{{Key: cbor.Text(key), Val: cbor.Bytes([]byte(value))}})
	for attempt := 1; attempt <= 2; attempt++ {
		r := map[string]any{"call": procedure, "attempt": attempt}
		start := time.Now()
		resp, err := s.Call(procedure, realm, payload, time.Now().Add(callTimeout).UnixMilli(), id, callTimeout)
		r["duration_ms"] = time.Since(start).Milliseconds()
		switch {
		case err != nil:
			r["outcome"] = "error"
			r["error"] = err.Error()
		case resp.IsError:
			r["outcome"] = "call_error"
			r["code"] = resp.Code
			r["name"] = resp.Name
			if resp.Detail != nil {
				r["detail"] = *resp.Detail
			}
			r["reported_by"] = fmt.Sprintf("%x", resp.ReportedBy)
		default:
			stripped, counts := stripViewCounts(resp.Payload)
			sum := sha256.Sum256(cbor.Encode(stripped))
			r["outcome"] = "ok"
			r["responded_by"] = fmt.Sprintf("%x", resp.RespondedBy)
			r["content_sha256"] = hex.EncodeToString(sum[:])
			r["view_counts"] = counts
			r["summary"] = summarize(resp.Payload)
		}
		retry := attempt == 1 && err == nil && resp.IsError && resp.Detail != nil && *resp.Detail == "bad_request"
		if retry {
			r["hazard"] = "hecate-tube#3: bad_request, retrying once"
		}
		emit(r)
		if !retry {
			return r["outcome"] == "ok"
		}
	}
	return false
}

func watch(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, realm []byte) bool {
	args := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("clip_id"), Val: cbor.Bytes([]byte(clipID))}})
	for attempt := 1; attempt <= 2; attempt++ {
		r := watchOnce(ctx, resolveVia, id, realm, args)
		r["attempt"] = attempt
		retry := attempt == 1 && isStreamHazard(r)
		if retry {
			r["hazard"] = "hecate-tube#3: cancelled with bad_request before any data, retrying once"
		}
		emit(r)
		if !retry {
			return r["outcome"] == "ok"
		}
	}
	return false
}

// isStreamHazard is the rule for hecate-tube#3 on a stream: handle_open answered
// bad_request, which macula_streamer sends as code "cancelled" with bad_request in
// the message, and no data had arrived.
func isStreamHazard(r map[string]any) bool {
	msg, _ := r["message"].(string)
	return r["outcome"] == "peer_aborted" && r["code"] == "cancelled" &&
		strings.Contains(msg, "bad_request") && r["chunks"] == 0
}

func watchOnce(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, realm []byte, args cbor.Value) map[string]any {
	r := map[string]any{"call": "tube.watch_video_clip", "mode": "server_stream", "path": "direct_dial"}
	start := time.Now()
	deadline := time.Now().Add(streamCap).UnixMilli()
	target, h, err := directdial.OpenStreamDirect(ctx, resolveVia, id, realm, "tube.watch_video_clip", frame.ServerStream, args, deadline, dialTimeout)
	if err != nil {
		r["duration_ms"] = time.Since(start).Milliseconds()
		r["error"] = err.Error()
		switch {
		case errors.Is(err, directdial.ErrStationEndpointNotFound):
			r["outcome"] = "station_endpoint_not_found"
		case errors.Is(err, directdial.ErrProcedureNotAdvertised):
			r["outcome"] = "procedure_not_advertised"
		default:
			r["outcome"] = "open_error"
		}
		return r
	}
	defer target.Close("normal", nil, id)
	r["serving_station"] = fmt.Sprintf("%x", target.Station.NodeID)

	hasher := sha256.New()
	var total int64
	chunks := 0
	for {
		if time.Since(start) > streamCap {
			r["outcome"] = "stream_cap_exceeded"
			break
		}
		item, err := h.Recv(chunkTimeout)
		if err != nil {
			var aborted *stream.ErrPeerAborted
			if errors.As(err, &aborted) {
				r["outcome"] = "peer_aborted"
				r["code"] = aborted.Code
				r["message"] = aborted.Message
			} else {
				r["outcome"] = "recv_error"
				r["error"] = err.Error()
			}
			break
		}
		if item.IsEOF {
			r["outcome"] = "ok"
			break
		}
		if item.Encoding != frame.Raw {
			r["outcome"] = "unexpected_encoding"
			r["encoding"] = int(item.Encoding)
			break
		}
		b, ok := item.Body.AsBytes()
		if !ok {
			r["outcome"] = "unexpected_body"
			r["body"] = item.Body.String()
			break
		}
		if chunks == 0 {
			r["first_chunk_ms"] = time.Since(start).Milliseconds()
		}
		hasher.Write(b)
		total += int64(len(b))
		chunks++
	}
	r["duration_ms"] = time.Since(start).Milliseconds()
	r["bytes"] = total
	r["chunks"] = chunks
	r["sha256"] = hex.EncodeToString(hasher.Sum(nil))
	return r
}

// stripViewCounts removes every map entry keyed "view_count", at any depth,
// and returns the removed values in traversal order. Each stream run records a
// view, so counts change between runs; they are reported, not matched.
func stripViewCounts(v cbor.Value) (cbor.Value, []int64) {
	counts := []int64{}
	return strip(v, &counts), counts
}

func strip(v cbor.Value, counts *[]int64) cbor.Value {
	if entries, ok := v.AsMap(); ok {
		out := make([]cbor.MapEntry, 0, len(entries))
		for _, e := range entries {
			if k, ok := e.Key.AsText(); ok && k == "view_count" {
				if n, ok := e.Val.AsInt64(); ok {
					*counts = append(*counts, n)
				}
				continue
			}
			out = append(out, cbor.MapEntry{Key: e.Key, Val: strip(e.Val, counts)})
		}
		return cbor.Map(out)
	}
	if items, ok := v.AsList(); ok {
		out := make([]cbor.Value, len(items))
		for i, item := range items {
			out[i] = strip(item, counts)
		}
		return cbor.List(out)
	}
	return v
}

func summarize(v cbor.Value) map[string]any {
	out := map[string]any{}
	if n, ok := v.Get("name"); ok {
		out["name"] = textOf(n)
	}
	if c, ok := v.Get("channel_id"); ok {
		out["channel_id"] = textOf(c)
	}
	if c, ok := v.Get("clips"); ok {
		if items, ok := c.AsList(); ok {
			out["clip_count"] = len(items)
		}
	}
	return out
}

func textOf(v cbor.Value) string {
	if s, ok := v.AsText(); ok {
		return s
	}
	if b, ok := v.AsBytes(); ok {
		return string(b)
	}
	return v.String()
}
