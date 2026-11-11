package stationlink

import (
	"errors"
	"io"
	"sync"
	"testing"
)

// testStream is a control stream a test drives: it answers the write it is
// given with n bytes and err, and keeps what it was asked to write.
type testStream struct {
	mu      sync.Mutex
	written [][]byte
	n       int
	err     error
}

func (s *testStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.written = append(s.written, append([]byte(nil), p...))
	if s.err != nil {
		return s.n, s.err
	}
	return len(p), nil
}

func (s *testStream) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.written)
}

// heldLink is a link with a control stream a test drives and nothing else: no
// connection, so an ending is whatever the test records on it.
func heldLink(stream io.Writer) *Link {
	return &Link{writer: &frameWriter{w: stream}, unrouted: map[string]uint64{}, done: make(chan struct{})}
}

// signed is a publication this package can hold without signing one: the held
// set stores what a link sent, not what it means.
func signed(payload byte) SignedPublication {
	return SignedPublication{encoded: []byte{payload}, resendUntil: 1 << 62}
}

// A publication a link wrote is held until the station is known to have read
// it: what was written is what the pool takes if the link ends first.
func TestAPublicationIsHeldWhenItIsWritten(t *testing.T) {
	stream := &testStream{}
	link := heldLink(stream)
	if err := link.PublishSigned(signed(7)); err != nil {
		t.Fatalf("PublishSigned: %v", err)
	}
	held := link.TakeUnconfirmed()
	if len(held) != 1 || held[0].Size() != 1 || held[0].encoded[0] != 7 {
		t.Fatalf("held %d publications, want the one written", len(held))
	}
	if stream.count() != 1 {
		t.Errorf("%d frames written, want 1", stream.count())
	}
}

// A frame the stream did not take at all is not held and reports its error: the
// caller may send the same publication on another link, and nothing anywhere
// carries this one.
func TestAFrameThatWroteNothingIsNotHeld(t *testing.T) {
	writeErr := errors.New("stream: written nothing")
	link := heldLink(&testStream{n: 0, err: writeErr})
	err := link.PublishSigned(signed(1))
	if !errors.Is(err, writeErr) {
		t.Errorf("a write that wrote nothing: %v, want the write's error", err)
	}
	if held := link.TakeUnconfirmed(); len(held) != 0 {
		t.Errorf("held %d publications after a write that wrote nothing, want none", len(held))
	}
}

// A frame the stream took part of is on a broken stream: the station will not
// route it, the link ends, and the held copy is the one that counts. The caller
// is told nothing, because a caller that hears an error signs a new publication
// — a new seq and hash — and the subscriber would get it twice.
func TestAPartlyWrittenFrameIsHeldAndTheCallerHearsNothing(t *testing.T) {
	writeErr := errors.New("stream: written part")
	stream := &testStream{n: 3, err: writeErr}
	link := heldLink(stream)
	ended := make(chan error, 1)
	restore := endLink
	endLink = func(l *Link, err error) {
		if l != link {
			t.Errorf("endLink on another link")
		}
		ended <- err
	}
	t.Cleanup(func() { endLink = restore })
	if err := link.PublishSigned(signed(2)); err != nil {
		t.Errorf("a partly written frame: %v, want no error: the held copy carries it", err)
	}
	select {
	case err := <-ended:
		if !errors.Is(err, writeErr) {
			t.Errorf("the link ended with %v, want the write's error", err)
		}
	default:
		t.Error("a partly written frame did not end the link it broke")
	}
	if held := link.TakeUnconfirmed(); len(held) != 1 {
		t.Errorf("held %d publications after a partly written frame, want 1", len(held))
	}
}

// The window between recording a hold and writing the frame is one the link can
// end in: the pool takes what the link held, and the write then fails having
// written nothing. The publication is carried by the take, so the caller is told
// nothing — an error there would make it sign a new publication for one that is
// already on its way.
func TestAPublicationTakenBeforeItsWriteIsNotReported(t *testing.T) {
	stream := &testStream{}
	link := heldLink(stream)
	taken := make(chan []SignedPublication, 1)
	restore := AfterHeld
	AfterHeld = func() { taken <- link.TakeUnconfirmed() }
	t.Cleanup(func() { AfterHeld = restore })
	stream.err = io.ErrClosedPipe // the write the take leaves behind fails, having written nothing
	if err := link.PublishSigned(signed(3)); err != nil {
		t.Errorf("a publication the pool took before its write: %v, want no error", err)
	}
	held := <-taken
	if len(held) != 1 || held[0].encoded[0] != 3 {
		t.Fatalf("the take got %d publications, want the one whose write had not started", len(held))
	}
	if again := link.TakeUnconfirmed(); len(again) != 0 {
		t.Errorf("the set holds %d after it was taken, want none", len(again))
	}
}

// The held set is bounded by entries and by bytes, and counts what it lets go
// of: the oldest first, and the newest always gets in.
func TestTheHeldSetLetsGoOfTheOldestAndCountsIt(t *testing.T) {
	var u unconfirmed
	for i := range MaxUnconfirmed + 1 {
		ok, letGo := u.hold(uint64(i), signed(byte(i)), 1)
		if !ok {
			t.Fatal("a hold was refused with the set untaken")
		}
		want := uint64(0)
		if i == MaxUnconfirmed {
			want = 1
		}
		if letGo != want {
			t.Fatalf("hold %d let go of %d, want %d", i, letGo, want)
		}
	}
	if len(u.items) != MaxUnconfirmed {
		t.Fatalf("the set holds %d entries, want %d", len(u.items), MaxUnconfirmed)
	}
	if u.items[0].number != 1 {
		t.Errorf("the oldest held is frame %d, want 1: the first was let go of", u.items[0].number)
	}
	// Over the byte cap the oldest goes too, and the newest stays.
	var b unconfirmed
	half := MaxUnconfirmedBytes / 2
	if ok, _ := b.hold(1, signed(1), half); !ok {
		t.Fatal("the first hold was refused")
	}
	ok, letGo := b.hold(2, signed(2), half+1)
	if !ok || letGo != 1 || len(b.items) != 1 || b.items[0].number != 2 {
		t.Fatalf("over the byte cap: ok=%v letGo=%d items=%d, want the oldest let go of and the newest kept",
			ok, letGo, len(b.items))
	}
}

// The set never lets go of the last publication it holds, so one frame larger
// than the byte cap is held rather than dropped: with MaxUnconfirmedBytes at
// least a frame, a full set never exceeds the cap by more than one frame, and
// never at all.
func TestTheHeldSetKeepsTheNewestEvenOverTheByteCap(t *testing.T) {
	var u unconfirmed
	if ok, letGo := u.hold(1, signed(1), MaxUnconfirmedBytes+1); !ok || letGo != 0 || len(u.items) != 1 {
		t.Fatalf("one publication over the byte cap: ok=%v letGo=%d items=%d, want it held",
			ok, letGo, len(u.items))
	}
}

// Once the pool has taken what the link held, nothing is held again: nothing
// would take it, so a publication written then is refused and nothing of it
// goes out.
func TestTakingTheHeldSetRefusesALaterHold(t *testing.T) {
	var u unconfirmed
	if ok, _ := u.hold(1, signed(1), 1); !ok {
		t.Fatal("the first hold was refused")
	}
	if held := u.take(); len(held) != 1 {
		t.Fatalf("the take got %d, want 1", len(held))
	}
	if ok, _ := u.hold(2, signed(2), 1); ok {
		t.Error("a hold after the take was accepted: nothing would take it again")
	}
	if held := u.take(); len(held) != 0 {
		t.Errorf("a second take got %d, want none", len(held))
	}
}

// A hold is dropped only by the frame number it was recorded with: the write
// that wrote nothing removes its own hold, and a second removal finds nothing.
func TestAHoldIsDroppedOnlyByItsOwnFrameNumber(t *testing.T) {
	var u unconfirmed
	u.hold(1, signed(1), 1)
	u.hold(2, signed(2), 1)
	if !u.drop(1) {
		t.Fatal("drop of a held frame said it was not held")
	}
	if u.drop(1) {
		t.Error("a second drop of the same frame said it was held")
	}
	if len(u.items) != 1 || u.items[0].number != 2 || u.bytes != 1 {
		t.Errorf("the set holds %+v (%d bytes), want frame 2 alone", u.items, u.bytes)
	}
}

// A frame sent before the one the station answered was read by it, and is let
// go of; one sent after it is not.
func TestConfirmingAFrameLetsGoOfEveryOneBeforeIt(t *testing.T) {
	var u unconfirmed
	for i := range uint64(5) {
		u.hold(i, signed(byte(i)), 2)
	}
	u.confirmBefore(3)
	if len(u.items) != 2 || u.items[0].number != 3 || u.bytes != 4 {
		t.Fatalf("after confirming frame 3: %+v (%d bytes), want frames 3 and 4", u.items, u.bytes)
	}
	u.confirmBefore(99)
	if len(u.items) != 0 || u.bytes != 0 {
		t.Errorf("after confirming everything: %+v (%d bytes), want none", u.items, u.bytes)
	}
}
