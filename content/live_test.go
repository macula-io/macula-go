//go:build live

// Integration tests against a real, live macula-station. NOT run by
// default `go test ./...` — gated behind the `live` build tag, same
// discipline as connection/live_test.go. Run explicitly:
//
//	go test -tags=live ./content/... -run TestLive -v
package content

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/macula-io/macula-go-sdk/connection"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/manifest"
	"github.com/macula-io/macula-go-sdk/transport"
)

const (
	liveStationHost = "station-de-frankfurt.macula.io"
	liveStationPort = 4433
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

func connectLive(t *testing.T) (*connection.Session, identity.KeyPair) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := connection.Connect(ctx, liveStationHost, liveStationPort, transport.WebPKI{}, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return session, id
}

// TestLiveSingleBlockPutGetRoundTrip: content small enough
// (<= manifest.DefaultChunkSize) to be addressed purely by content
// hash, no manifest involved. Every byte is randomized per run so
// there's no risk of colliding with content some other run already
// stored under the same MCID.
func TestLiveSingleBlockPutGetRoundTrip(t *testing.T) {
	session, id := connectLive(t)
	defer session.Close("normal", nil, id)

	data := randomBytes(t, 4096)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mcid, err := Put(ctx, session, data, "test-block", id)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if manifest.McidIsChunked(mcid) {
		t.Fatalf("4096 bytes is well under the chunking threshold, mcid reports chunked")
	}
	t.Logf("OBSERVED: stored single block under mcid=%x", mcid)

	fetched, err := Get(ctx, session, mcid, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(fetched) != string(data) {
		t.Fatalf("fetched bytes must match what was put, exactly")
	}
}

// TestLiveChunkedPutGetRoundTrip: content large enough to force
// manifest.Create's multi-chunk path, exercising _content.put_block
// (several times, sequentially), _content.put_manifest,
// _content.get_manifest, and _content.get_block (again several times)
// all against a real station, then verifies the reassembled bytes
// against the manifest's Merkle root.
func TestLiveChunkedPutGetRoundTrip(t *testing.T) {
	session, id := connectLive(t)
	defer session.Close("normal", nil, id)

	size := manifest.DefaultChunkSize*2 + 12_345
	data := randomBytes(t, size)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	mcid, err := Put(ctx, session, data, "test-chunked", id)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !manifest.McidIsChunked(mcid) {
		t.Fatalf("%d bytes is well over the chunking threshold, mcid does not report chunked", size)
	}
	t.Logf("OBSERVED: stored %d bytes as a manifest under mcid=%x", size, mcid)

	fetched, err := Get(ctx, session, mcid, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(fetched) != string(data) {
		t.Fatalf("reassembled bytes must match what was put, exactly")
	}
}

// TestLiveGetOfUnknownBlockReportsNotFound: a made-up MCID that (with
// overwhelming probability) nothing has ever stored — proves the
// wire-level not_found reply is reached and parsed correctly, not just
// the happy path.
func TestLiveGetOfUnknownBlockReportsNotFound(t *testing.T) {
	session, id := connectLive(t)
	defer session.Close("normal", nil, id)

	mcid := manifest.BlockMcid(randomBytes(t, 32))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := Get(ctx, session, mcid, id)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	t.Logf("OBSERVED: not_found reported correctly for an unknown mcid")
}
