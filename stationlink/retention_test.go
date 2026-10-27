package stationlink

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
)

// A clear stream's retention and the adoption it exists for
// (DESIGN_E2E_SEALED_BY_DEFAULT.md section 3): only a seq-0 sealed_required
// carrying a key of the stream's profile adopts, and any other first frame
// drops the copy.

// carriedKeyOf is a KEM key of p as an advertisement and a refusal carry it.
func carriedKeyOf(t *testing.T, p profile.Profile) []byte {
	t.Helper()
	k, err := seal.GenerateKey(p)
	if err != nil {
		t.Fatalf("seal key: %v", err)
	}
	return k.PublicKey().Carried()
}

// streamErrorCarrying is a verified provider STREAM_ERROR at seq carrying the
// KEM key under seal.kem_key when key is not nil.
func streamErrorCarrying(code string, seq uint64, key []byte) frame.VerifiedStreamFrame {
	v := frame.VerifiedStreamFrame{FrameType: "stream_error", Seq: seq, Code: code}
	if key != nil {
		ext, _ := frame.ExtMap([]frame.Ext{{Name: frame.ExtSealKEMKey, Value: cbor.Bytes(key)}})
		v.Ext = ext
	}
	return v
}

func TestOnlyARefusalCarryingAKeyOfTheStreamsProfileAdopts(t *testing.T) {
	carried := carriedKeyOf(t, profile.PQPure)
	short := carried[:32]
	for _, tc := range []struct {
		name  string
		frame frame.VerifiedStreamFrame
		want  bool
	}{
		{"a seq-0 sealed_required with the key", streamErrorCarrying(codeSealedRequired, 0, carried), true},
		{"a refusal naming no key", streamErrorCarrying(codeSealedRequired, 0, nil), false},
		{"a refusal with a key of another length", streamErrorCarrying(codeSealedRequired, 0, short), false},
		{"a refusal at another seq", streamErrorCarrying(codeSealedRequired, 1, carried), false},
		{"another refusal carrying one", streamErrorCarrying(codeSealedRefused, 0, carried), false},
		{"a chunk", frame.VerifiedStreamFrame{FrameType: "stream_data", Seq: 0}, false},
	} {
		key, adopted := adoptionKey(profile.PQPure, tc.frame)
		if adopted != tc.want {
			t.Errorf("%s: adopted %v, want %v", tc.name, adopted, tc.want)
			continue
		}
		if adopted && string(key) != string(carried) {
			t.Errorf("%s: adopted key %x, want %x", tc.name, key, carried)
		}
	}
}

// The copy is capped at the stream's own bound: past it retention stops and the
// copy is dropped, so a later refusal surfaces unchanged.
func TestRetentionStopsAtItsBound(t *testing.T) {
	s := &Stream{link: &Link{profile: profile.PQPure}, retained: &retainedStream{}}
	s.retain(frame.StreamDataFields{Encoding: frame.Raw, Body: cbor.Bytes(make([]byte, 64))}, false, streamInbox-1)
	if s.retained == nil {
		t.Fatal("retention ended below its bound")
	}
	s.retain(frame.StreamDataFields{Encoding: frame.Raw, Body: cbor.Bytes(make([]byte, 64))}, false, 2)
	if s.retained != nil {
		t.Error("retention lived past its bound")
	}
	if acts, key := s.firstPeerFrame(streamErrorCarrying(codeSealedRequired, 0, carriedKeyOf(t, profile.PQPure))); acts != nil || key != nil {
		t.Error("a dropped copy was still replayed")
	}
}

// The first frame is where retention ends: an adoption takes the copy, and any
// other frame drops it.
func TestTheFirstFrameTakesOrDropsTheCopy(t *testing.T) {
	carried := carriedKeyOf(t, profile.PQPure)
	retaining := func() *Stream {
		return &Stream{link: &Link{profile: profile.PQPure}, retained: &retainedStream{}}
	}
	s := retaining()
	s.retain(frame.StreamDataFields{Encoding: frame.Raw, Body: cbor.Bytes([]byte("hello"))}, false, 32)
	s.retain(frame.StreamEndFields{Role: frame.Send}, true, 16)
	acts, key := s.firstPeerFrame(streamErrorCarrying(codeSealedRequired, 0, carried))
	if len(acts) != 2 || string(key) != string(carried) {
		t.Fatalf("the adoption took %d actions and key %x, want 2 and %x", len(acts), key, carried)
	}
	if !acts[1].last {
		t.Error("the copied STREAM_END did not stay the last action")
	}
	if s.retained != nil {
		t.Error("retention lived past the first frame")
	}

	s = retaining()
	s.retain(frame.StreamDataFields{Encoding: frame.Raw, Body: cbor.Bytes([]byte("hello"))}, false, 32)
	if acts, key := s.firstPeerFrame(frame.VerifiedStreamFrame{FrameType: "stream_data", Seq: 0}); acts != nil || key != nil {
		t.Error("a chunk from the provider adopted the stream")
	}
	if s.retained != nil {
		t.Error("the copy lived past a first frame that was no refusal")
	}
}
