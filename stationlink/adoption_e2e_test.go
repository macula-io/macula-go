package stationlink_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// The A0 shapes of DESIGN_E2E_SEALED_BY_DEFAULT.md section 8.1, end to end
// through a station: a caller that writes in the clear to a provider that
// requires sealing is refused sealed_required carrying the provider's KEM key,
// adopts that key, and gets its answer. The provider carries the key only with
// KEMKeyInRefusal, which is release A and off by default: that is the design's
// test-only provider, "a provider built to send the extension in the test
// only".

// A clear call to a keyed provider is refused sealed_required carrying the
// key, and the same call, sealed to it under a new request, answers. Every
// CALL names its target, so this is section 8.1's explicit target clear call.
// The provider's handler sees a sealed request, and the key comes back on the
// call's Adopted hook.
func TestAClearCallAdoptsTheKeyTheRefusalCarries(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) { assertAClearCallAdopts(t, p) })
	}
}

func assertAClearCallAdopts(t *testing.T, p profile.Profile) {
	t.Helper()
	w := newAdoptingWorld(t, p, "adopt call")
	sealed := make(chan bool, 1)
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/open", Confidential: stationlink.ConfidentialRequired,
		Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
			sealed <- r.Sealed
			return r.Payload, nil
		}})
	var adopted []byte
	// The provider refuses this clear call; the link seals it again under a new
	// request, which is the call that answers.
	got, err := w.caller.Call(t.Context(), stationlink.Call{Realm: w.realm.ID, Procedure: "mcl-vault/open",
		Target: w.provider.NodeID(), Payload: cbor.Text("the secret"), Timeout: 10 * time.Second, Clear: true,
		Adopted: func(kemKey []byte) { adopted = kemKey }})
	if text, _ := got.AsText(); err != nil || text != "the secret" {
		t.Fatalf("the adopted call: %q, %v", text, err)
	}
	if !<-sealed {
		t.Error("the provider's handler saw the call in the clear")
	}
	if !bytes.Equal(adopted, w.carried()) {
		t.Errorf("the call adopted %x, the provider holds %x", adopted, w.carried())
	}
}

// A clear bidi stream to a provider that waits for the caller's first chunk
// adopts the key its refusal carries and completes: what the caller wrote
// before the refusal is replayed sealed, in order, and the provider answers.
func TestAClearStreamAdoptsTheKeyTheRefusalCarries(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) { assertAClearStreamAdopts(t, p, frame.Bidi) })
	}
}

// A clear client stream to a provider that answers only after the caller's
// end, as count_bytes does, replays the chunks and the end the caller wrote
// and closed before the refusal, in order, under the sealed reopen: the
// provider reads to its end and answers.
func TestAClearClientStreamAdoptsTheKeyTheRefusalCarries(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) { assertAClearStreamAdopts(t, p, frame.ClientStream) })
	}
}

func assertAClearStreamAdopts(t *testing.T, p profile.Profile, mode frame.StreamMode) {
	t.Helper()
	w := newAdoptingWorld(t, p, "adopt "+mode.Name())
	read := make(chan string, 1)
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/count", Confidential: stationlink.ConfidentialRequired,
		Stream: &stationlink.StreamOffer{Mode: mode, Handler: countingHandler(read)}})
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID,
		Procedure: "mcl-vault/count", Target: w.provider.NodeID(), Mode: mode, Payload: cbor.Map(nil), Clear: true})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// Written and closed before the refusal arrives: the race the copy exists
	// for, so these writes' own errors are not failures here - what matters is
	// that the copy holds them and the replay delivers them.
	_ = stream.Send([]byte("one"))
	_ = stream.Send([]byte("two"))
	_ = stream.CloseSend()
	if got, want := takeRead(t, stream, read), "one,two"; got != want {
		t.Errorf("the provider read %q, want %q: the copy was not replayed", got, want)
	}
	event, err := recv(t, stream)
	if total, _ := event.Payload.AsInt64(); err != nil || event.Kind != stationlink.StreamReply || total != 6 {
		t.Errorf("the reply: %+v, %v", event, err)
	}
}

// A send that meets the refusal - the window adoption exists for - lands in the
// replay, never on the refused session, and the provider reads every chunk the
// owner wrote exactly once, in order, its end included. Repeated, so the writes
// meet the refusal at different points: one round may have them all in the
// copy, the next may have one waiting on the reopen.
func TestASendRacingTheRefusalIsReplayedOnce(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) { assertARacingSendIsDeliveredOnce(t, p) })
	}
}

// raceRounds and raceChunks size the race: enough writes in flight to reach the
// refusal on both sides of the copy.
const (
	raceRounds = 12
	raceChunks = 8
)

func assertARacingSendIsDeliveredOnce(t *testing.T, p profile.Profile) {
	t.Helper()
	w := newAdoptingWorld(t, p, "adopt race")
	read := make(chan string, raceRounds)
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/count", Confidential: stationlink.ConfidentialRequired,
		Stream: &stationlink.StreamOffer{Mode: frame.Bidi, Handler: countingHandler(read)}})
	for round := 0; round < raceRounds; round++ {
		stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID,
			Procedure: "mcl-vault/count", Target: w.provider.NodeID(), Mode: frame.Bidi,
			Payload: cbor.Map(nil), Clear: true})
		if err != nil {
			t.Fatalf("round %d: OpenStream: %v", round, err)
		}
		chunks := racingChunks(round)
		go writeAll(stream, chunks)
		if got, want := takeRead(t, stream, read), strings.Join(chunks, ","); got != want {
			t.Fatalf("round %d: the provider read %q, want %q", round, got, want)
		}
		assertRacingReply(t, round, stream, chunks)
	}
}

// racingChunks is one round's writes, named so a dropped, reordered or replayed
// chunk shows which one it was.
func racingChunks(round int) []string {
	chunks := make([]string, raceChunks)
	for i := range chunks {
		chunks[i] = fmt.Sprintf("r%d-c%d", round, i)
	}
	return chunks
}

// writeAll writes chunks and ends the caller's side, as an owner that does not
// wait for the refusal would: every write is the owner's, so every one is
// replayed exactly once whatever the session it met.
func writeAll(stream *stationlink.Stream, chunks []string) {
	for _, chunk := range chunks {
		_ = stream.Send([]byte(chunk))
	}
	_ = stream.CloseSend()
}

// assertRacingReply checks the provider answered with the total size of the
// chunks it read.
func assertRacingReply(t *testing.T, round int, stream *stationlink.Stream, chunks []string) {
	t.Helper()
	want := 0
	for _, chunk := range chunks {
		want += len(chunk)
	}
	event, err := recv(t, stream)
	if total, _ := event.Payload.AsInt64(); err != nil || event.Kind != stationlink.StreamReply || total != int64(want) {
		t.Errorf("round %d: the reply: %+v, %v", round, event, err)
	}
}

// takeRead is what the provider's handler read, or a failure if it never read,
// naming what the caller's stream was doing at that point.
func takeRead(t *testing.T, stream *stationlink.Stream, read <-chan string) string {
	t.Helper()
	select {
	case got := <-read:
		return got
	case <-time.After(30 * time.Second):
		t.Fatalf("the provider never finished reading the replayed chunks: the stream's error %v, ended %v",
			stream.Err(), streamEnded(stream))
		return ""
	}
}

// streamEnded reports whether the stream has been released.
func streamEnded(stream *stationlink.Stream) bool {
	select {
	case <-stream.Done():
		return true
	default:
		return false
	}
}

// countingHandler reads a stream's raw chunks until its end, reports them
// joined by a comma, and answers with their total size: the count_bytes shape,
// a provider that holds its answer until the caller has finished writing.
func countingHandler(read chan<- string) stationlink.StreamHandler {
	return func(ctx context.Context, s *stationlink.Stream) error {
		var chunks []string
		total := 0
		for {
			event, err := s.Recv(ctx)
			if err != nil {
				return err
			}
			if event.Kind == stationlink.StreamEnd {
				break
			}
			if body, ok := event.Body.AsBytes(); ok {
				chunks = append(chunks, string(body))
				total += len(body)
			}
		}
		read <- strings.Join(chunks, ",")
		return s.Reply(cbor.Uint64(uint64(total)))
	}
}

// adoptingWorld is a keyed provider that carries its key in a sealed_required
// refusal - release A, on only in the test - with a caller that may only reach
// it in the clear.
type adoptingWorld struct {
	realm    teststation.Realm
	provider *stationlink.Link
	caller   *stationlink.Link
	ring     *seal.Keyring
}

func newAdoptingWorld(t *testing.T, p profile.Profile, name string) adoptingWorld {
	t.Helper()
	s := teststation.Start(t, p, name)
	realm := teststation.NewRealm(t, p, "sealed.test", "mcl-vault")
	ring, err := seal.NewKeyring(p, time.Now)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	provider := dialConfigured(t, s, p, name+" provider", func(cfg *stationlink.Config) {
		cfg.Keyring, cfg.KEMAdvertise, cfg.KEMKeyInRefusal = ring, true, true
	})
	realm.Admit(t, s, provider.NodeID())
	return adoptingWorld{realm: realm, provider: provider, caller: dialIn(t, s, p, name+" caller"), ring: ring}
}

// carried is the key the provider holds now, as a refusal carries it.
func (w adoptingWorld) carried() []byte { return w.ring.Current().PublicKey().Carried() }

func (w adoptingWorld) serve(t *testing.T, o stationlink.Offer) {
	t.Helper()
	o.Realm, o.RealmKey = w.realm.ID, w.realm.RealmKey()
	if _, err := w.provider.Serve(t.Context(), o); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}
