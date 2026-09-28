package pool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
	"github.com/macula-io/macula-go/stationlink"
)

// A pool call's seal report (macula DESIGN_E2E_SEAL_REPORT §2, §5): CallReport
// returns the result with Sealed 1 and the id of the key the call was sealed
// to when the provider's advertisement named one, Sealed 0 and no key when it
// named none, and no report on an error.

// adKeyID is the KEM key id the provider's verified advertisement names, as
// the caller resolves it.
func adKeyID(t *testing.T, w sealedPools, procedure string) [8]byte {
	t.Helper()
	realmKey, err := w.caller.realmKeyFor(w.realm.ID, procedure)
	if err != nil {
		t.Fatal(err)
	}
	var found []candidate
	eventually(t, "the advertisement", func() bool {
		found, _ = w.caller.resolve(t.Context(), resolvedKey{realm: w.realm.ID, procedure: procedure}, realmKey)
		return len(found) == 1
	})
	return found[0].kemKeyID
}

func TestACallReportNamesTheKeyItWasSealedTo(t *testing.T) {
	w := newSealedPools(t, "report keyed", true)
	var sealed bool
	w.serve(t, Offer{Procedure: procedure}, &sealed)
	want := stationlink.Report{Sealed: 1, Provider: w.provider.NodeID(), SealKeyID: adKeyID(t, w, procedure)}
	got, report, err := w.caller.CallReport(t.Context(), Call{Realm: w.realm.ID, Procedure: procedure, Payload: cbor.Text("x")})
	if text, _ := got.AsText(); err != nil || text != "x" || report != want || !sealed {
		t.Errorf("a sealed call: %q, %+v, %v, want %+v", text, report, err, want)
	}
}

func TestACallReportOfAClearCallIsSealed0(t *testing.T) {
	w := newSealedPools(t, "report keyless", false)
	var sealed bool
	w.serve(t, Offer{Procedure: procedure}, &sealed)
	got, report, err := w.caller.CallReport(t.Context(), Call{Realm: w.realm.ID, Procedure: procedure, Payload: cbor.Text("x")})
	want := stationlink.Report{Sealed: 0, Provider: w.provider.NodeID()}
	if text, _ := got.AsText(); err != nil || text != "x" || report != want || sealed {
		t.Errorf("a clear call: %q, %+v, %v, want %+v", text, report, err, want)
	}
}

func TestAFailedCallHasNoReport(t *testing.T) {
	w := newSealedPools(t, "report error", true)
	w.serve(t, Offer{Procedure: procedure, Handler: func(context.Context, stationlink.Request) (cbor.Value, error) {
		return cbor.Value{}, errors.New("no")
	}}, nil)
	_, report, err := w.caller.CallReport(t.Context(), Call{Realm: w.realm.ID, Procedure: procedure, Payload: cbor.Text("x")})
	var provided *stationlink.ProviderError
	if !errors.As(err, &provided) || report != (stationlink.Report{}) {
		t.Errorf("a failed call: %+v, %v, want a provider error and no report", report, err)
	}
}

// A stream the pool opens reports as a stationlink stream does, once settled.
func TestAPoolStreamReportsOnceSettled(t *testing.T) {
	w := newSealedPools(t, "report stream", true)
	w.serve(t, Offer{Procedure: "mcl-echo/stream", Stream: &stationlink.StreamOffer{Mode: frame.ServerStream,
		Handler: func(_ context.Context, s *stationlink.Stream) error { return s.Reply(cbor.Text("streamed")) }}}, nil)
	want := stationlink.Report{Sealed: 1, Provider: w.provider.NodeID(), SealKeyID: adKeyID(t, w, "mcl-echo/stream")}
	stream, err := w.caller.OpenStream(t.Context(), StreamCall{Realm: w.realm.ID, Procedure: "mcl-echo/stream",
		Mode: frame.ServerStream, Payload: cbor.Map(nil)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := stream.Recv(ctx); err != nil {
		t.Fatal(err)
	}
	if report, err := stream.Report(); err != nil || report != want {
		t.Errorf("a pool stream: %+v, %v, want %+v", report, err, want)
	}
}

// reported builds the report from the call that produced the result: after a
// reseal callAt hands it the resealed call, so the report names the reseal's
// key, never the first; a clear call reports 0 and no key; an error none.
func TestReportedNamesTheKeyOfTheCallThatProducedTheResult(t *testing.T) {
	first, resealedTo := sealedKey(t), sealedKey(t)
	target := [32]byte{7}
	call := stationlink.Call{Target: target, SealTo: first}
	call.SealTo = resealedTo // what callAt does after sealed_refused
	if _, got, err := reported(cbor.Text("x"), call, nil); err != nil ||
		got != (stationlink.Report{Sealed: 1, Provider: target, SealKeyID: seal.KeyID(resealedTo)}) {
		t.Errorf("a resealed call: %+v, %v", got, err)
	}
	if _, got, _ := reported(cbor.Text("x"), stationlink.Call{Target: target, Clear: true}, nil); got != (stationlink.Report{Provider: target}) {
		t.Errorf("a clear call: %+v", got)
	}
	if _, got, err := reported(cbor.Value{}, call, errors.New("no")); err == nil || got != (stationlink.Report{}) {
		t.Errorf("an error: %+v, %v", got, err)
	}
}

func sealedKey(t *testing.T) []byte {
	t.Helper()
	k, err := seal.GenerateKey(profile.PQPure)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Carried()
}
