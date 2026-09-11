// Package directdial implements Macula's direct-dial resolve-and-call:
// resolving a signed procedure_advertisement DHT record and its serving
// station's own signed station_endpoint, then dialing that station in one
// hop — instead of depending on ordinary advertise-gossip having
// propagated a route between whichever two stations happen to be
// involved. Ported from macula-io/macula's macula_direct_dial.erl; see
// that module's doc for the full trust model this reproduces.
//
// Trust model (see macula_direct_dial.erl's module doc for the full
// reasoning): every candidate procedure_advertisement must carry a valid
// Ed25519 signature before its serving_station is trusted at all, and the
// resolved station_endpoint must be signed by the station itself. The
// actual QUIC dial trusts neither the TLS certificate (a production
// station's TLS is terminated by an unrelated PKI) nor nothing — trust is
// enforced at the application layer, by checking the freshly dialed
// session's own signature-verified HELLO identity against the exact
// pubkey the signed DHT chain resolved.
//
// Every advertisement that verifies is a candidate, in the order the DHT
// returns them. A candidate whose station endpoint can't be resolved, whose
// dial fails, or whose dialed identity doesn't match is passed over for the
// next one, but only before the request is sent: once a CALL or a stream's
// opening frame may have gone out, its outcome is returned as it is. A
// content fetch is verified against its MCID, so a failed fetch also moves on
// to the next provider. When no candidate qualifies, or every one failed
// before sending, resolution asks the DHT again. One deadline bounds all of
// it: the lookups, each candidate's endpoint lookup and dial (within a share
// of the time that remains), and the request.
//
// cert_chain-based org/realm authorization (Slice 7c Direction B,
// macula_record:verify_advertisement_cert_chain/3 on the Erlang side) is
// opt-in, through the *WithCertChain variants.
package directdial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/content"
	"github.com/macula-io/macula-go/dht"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/manifest"
	"github.com/macula-io/macula-go/stream"
	"github.com/macula-io/macula-go/transport"
)

// retryDelay spaces one pass over the DHT from the next, matching
// macula_direct_dial.erl's ?RESOLVE_RETRY_MS: a record just published on the
// provider's station has not necessarily replicated to the resolving station
// yet, so a miss is not treated as final.
const (
	retryDelay = 100 * time.Millisecond
	// defaultLookupTimeout bounds one DHT lookup when more time remains,
	// matching the dht package's own default.
	defaultLookupTimeout = 5 * time.Second
	// minCandidateShare is the least time one candidate gets for its endpoint
	// lookup and dial while that much of the deadline remains.
	minCandidateShare = time.Second
)

// DefaultResolveTimeout bounds Resolve, ResolveWithCertChain and
// ResolveStationEndpoint when their context carries no deadline.
const DefaultResolveTimeout = 10 * time.Second

// The DHT lookups, and the work done at one station (dial it, then send the
// request), are variables so tests can drive resolution without a network.
var (
	findRecords = dht.FindRecordsTimeout
	findRecord  = dht.FindRecordTimeout
	callAt      = dialAndCall
	openAt      = dialAndOpenStream
	fetchAt     = dialAndFetch
)

var (
	ErrProcedureNotAdvertised  = errors.New("directdial: procedure has no direct-dial advertisement in the DHT")
	ErrNoTrustedAdvertisement  = errors.New("directdial: every candidate advertisement failed signature verification")
	ErrStationEndpointNotFound = errors.New("directdial: resolved station published no reachable station_endpoint")
	// ErrNoAuthorizedAdvertisement means at least one candidate advertisement's
	// envelope signature verified (otherwise ErrNoTrustedAdvertisement would
	// apply), but none passed cert-chain authorization for the expected org
	// — see dht.VerifyAdvertisementCertChain for why (absent chain, wrong
	// org, untrusted chain, etc. — unwrap for the specific reason from the
	// LAST candidate tried).
	ErrNoAuthorizedAdvertisement = errors.New("directdial: no candidate advertisement is cert-chain-authorized for the expected org")
)

// Resolve finds procedure's currently-advertised serving station and its
// dialable host/port, retrying past DHT propagation lag. realm and
// procedure must match exactly what the provider passed to AdvertiseDirect
// (or the Erlang equivalent) — the discovery URI they derive must agree.
// session is used only to query the DHT; it does not need to be connected
// to the same station that will end up serving the call.
//
// The first candidate whose station endpoint resolves is returned. ctx
// bounds the whole resolution; without a deadline, DefaultResolveTimeout
// applies.
func Resolve(ctx context.Context, session *connection.Session, id identity.KeyPair, realm []byte, procedure string) (station []byte, host string, port uint16, err error) {
	ctx, cancel := withResolveDeadline(ctx)
	defer cancel()
	r, err := eachCandidate(ctx, advertisedStations(session, id, realm, procedure), reachableStation(session, id))
	return r.station, r.host, r.port, err
}

// trustedAdvertisements returns every record that verifies and reads as a
// procedure_advertisement, in the order given.
func trustedAdvertisements(recs []dht.Record) []dht.ProcedureAdvertisement {
	var advs []dht.ProcedureAdvertisement
	for _, rec := range recs {
		if dht.Verify(rec) != nil {
			continue
		}
		adv, err := dht.ReadProcedureAdvertisement(rec)
		if err != nil {
			continue
		}
		advs = append(advs, adv)
	}
	return advs
}

// ResolveWithCertChain is Resolve, plus Slice 7c Direction B managed-realm
// authorization: only an advertisement whose embedded cert chain validates
// to realmCAPEM and names expectedOrg is trusted. Opt-in — Resolve itself
// is unaffected and remains the right choice for unmanaged realms.
//
// lastErr surfaces the specific dht.VerifyAdvertisementCertChain failure
// from the LAST candidate tried when none qualify (wrapped under
// ErrNoAuthorizedAdvertisement via errors.Unwrap) — distinguishing "nobody
// advertised a cert chain at all" from "one did, but for the wrong org"
// matters operationally, so callers get the real reason, not just "no".
//
// ctx bounds the whole resolution, as for Resolve.
func ResolveWithCertChain(ctx context.Context, session *connection.Session, id identity.KeyPair, realm []byte, procedure string, realmCAPEM []byte, expectedOrg string) (station []byte, host string, port uint16, err error) {
	ctx, cancel := withResolveDeadline(ctx)
	defer cancel()
	r, err := eachCandidate(ctx, authorizedStations(session, id, realm, procedure, realmCAPEM, expectedOrg), reachableStation(session, id))
	return r.station, r.host, r.port, err
}

// authorizedAdvertisements is trustedAdvertisements plus the cert-chain
// check. lastErr is the most recent VerifyAdvertisementCertChain failure seen
// (nil if every candidate failed the plain signature check instead, in which
// case the caller reports ErrNoTrustedAdvertisement, matching Resolve's own
// distinction).
func authorizedAdvertisements(recs []dht.Record, realmCAPEM []byte, expectedOrg string) (advs []dht.ProcedureAdvertisement, lastErr error) {
	for _, rec := range recs {
		if err := dht.VerifyAdvertisementCertChain(realmCAPEM, rec, expectedOrg); err != nil {
			if !errors.Is(err, dht.ErrCertChainBadSignature) {
				lastErr = err
			}
			continue
		}
		adv, err := dht.ReadProcedureAdvertisement(rec)
		if err != nil {
			lastErr = err
			continue
		}
		advs = append(advs, adv)
	}
	return advs, lastErr
}

// CallWithCertChain is Call, resolved via ResolveWithCertChain instead of
// Resolve — see both for the full contract. Opt-in managed-realm
// authorization; Call itself is unaffected.
func CallWithCertChain(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, realm []byte, procedure string, realmCAPEM []byte, expectedOrg string, payload cbor.Value, timeout time.Duration) (frame.CallResponse, error) {
	return call(ctx, authorizedStations(resolveVia, id, realm, procedure, realmCAPEM, expectedOrg), resolveVia, id, realm, procedure, payload, timeout, nil)
}

// AdvertiseDirectWithCertChain is AdvertiseDirect, plus embedding a
// service-cert chain (leaf-first PEM: leaf ++ org CA) for Slice 7c
// Direction B authorization — see dht.NewProcedureAdvertisementWithCertChain
// and VerifyAdvertisementCertChain. Opt-in; AdvertiseDirect itself is
// unaffected.
func AdvertiseDirectWithCertChain(session *connection.Session, id identity.KeyPair, realm []byte, procedure string, ttl time.Duration, certChainPEM []byte) error {
	advertiseSpec := frame.NewAdvertiseSpec(realm, procedure, id.NodeID())
	if err := session.Advertise(advertiseSpec, id); err != nil {
		return fmt.Errorf("directdial: advertise: %w", err)
	}
	uri := dht.DiscoveryURI(realm, procedure)
	rec, err := dht.NewProcedureAdvertisementWithCertChain(id.NodeID(), uri, session.Station.NodeID, ttl, certChainPEM)
	if err != nil {
		return err
	}
	rec = dht.Sign(rec, id)
	return dht.PutRecord(session, id, rec)
}

// ResolveStationEndpoint resolves an arbitrary known station's dialable
// host/port from its own signed station_endpoint record — the same lookup
// Resolve performs internally after finding a procedure_advertisement, but
// exported for callers that already know WHICH station they want (content
// PUT-direct: macula_feeder:start_link_direct/5,6's own pattern, which
// names Station directly rather than resolving one via a
// procedure_advertisement — content has no "procedure" to advertise).
//
// Retries past a resolved-but-stale record, not just an absent one — the
// DHT can hand back a replica that hasn't been evicted yet even though the
// station's own current publish is live. Giving up on the first stale hit
// would make an otherwise healthy station unreachable via direct-dial
// until that one replica ages out.
//
// ctx bounds the lookup; without a deadline, DefaultResolveTimeout applies.
func ResolveStationEndpoint(ctx context.Context, session *connection.Session, id identity.KeyPair, station []byte) (out []byte, host string, port uint16, err error) {
	ctx, cancel := withResolveDeadline(ctx)
	defer cancel()
	host, port, err = stationEndpoint(ctx, session, id, station)
	if err != nil {
		return nil, "", 0, err
	}
	return station, host, port, nil
}

// Call resolves procedure's provider via direct-dial (through resolveVia,
// which is used only to query the DHT) and calls it there, in one hop, in
// a SEPARATE connection from resolveVia. The provider must have advertised
// via AdvertiseDirect (or the Erlang macula_response:advertise_direct/6,7)
// — a plain advertise publishes no discoverable record and Resolve will
// return ErrProcedureNotAdvertised.
//
// The dial itself uses transport.Insecure{} (no TLS verification) because
// trust is enforced at the application layer instead — see the package
// doc's "Trust model". After the dial, the freshly connected session's own
// signature-verified HELLO identity is checked against the exact pubkey
// the signed DHT chain resolved; a mismatch is a trust violation, so the
// CALL is never sent there and the next candidate is tried.
//
// timeout bounds resolution, each candidate's endpoint lookup and dial, and
// the CALL itself, which carries the resulting deadline.
func Call(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, realm []byte, procedure string, payload cbor.Value, timeout time.Duration) (frame.CallResponse, error) {
	return call(ctx, advertisedStations(resolveVia, id, realm, procedure), resolveVia, id, realm, procedure, payload, timeout, nil)
}

// CallWithUCAN is Call, presenting ucanToken to a provider gated with
// `{ucan_required, Issuer}` (see connection.Session.CallWithUCAN for the
// wire behavior). Every hecate-om capability is advertised via
// AdvertiseDirect, so this is the only way a UCAN-gated capability is
// reachable at all — plain Call cannot resolve or dial it, and Call
// (this package) cannot attach a token. Split from Call rather than
// adding an optional token there, matching connection.Session's own
// Call/CallWithUCAN split.
func CallWithUCAN(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, realm []byte, procedure string, payload cbor.Value, timeout time.Duration, ucanToken []byte) (frame.CallResponse, error) {
	if ucanToken == nil {
		ucanToken = []byte{}
	}
	return call(ctx, advertisedStations(resolveVia, id, realm, procedure), resolveVia, id, realm, procedure, payload, timeout, ucanToken)
}

// AdvertiseDirect publishes a signed procedure_advertisement naming
// session's own currently-connected station (session.Station.NodeID) as
// procedure's server, discoverable by any caller's Resolve/Call. Mirrors
// macula_response:advertise_direct/6,7 +
// macula_direct_dial:publish_advertisement/4,5 — unlike the Erlang
// reference's pool (many links, one chosen by connected_station/1), a Go
// Session is always exactly one connection, so there is no link-selection
// step: session's own verified HELLO identity IS the serving station.
//
// Unlike the Erlang SDK's supervised macula_response, this registers no
// handler of its own and does not keep anything alive across calls. A
// station's registration for a procedure does not survive the connection
// that sent it being replaced, so a long-lived server needs to call this
// again on its own schedule; see KeepAdvertisedDirect for that loop.
//
// Mirrors macula_response:advertise_direct/6,7, which calls plain
// advertise/6 FIRST and only then publishes the DHT record — both, not
// either. Without the plain Advertise, a caller that resolves this
// station via the DHT record and dials it directly reaches a station with
// no ordinary ADVERTISE registration to route the CALL to, so ServeOneCall
// never sees it. Found live 2026-08-30 porting this fix from
// macula-rust, which hit it first by verifying an actual RESULT came
// back through direct-dial instead of accepting a clean unknown_next_peer
// as sufficient (that only proves resolve+dial+trust-chain work, not that
// a live handler is reachable).
//
// Both steps run on the ONE session passed in, so this must not be called
// on a session whose receive loop belongs to ServeForever: the put_record
// CALL's RESULT frame is consumed by that loop and the put times out
// ("dht: put_record: connection: read stream: deadline exceeded" -- seen
// live 2026-09-03 from macula-cli's daemon, which did exactly that). A
// long-lived server that is already serving should Advertise on its
// serving session and publish the record (NewProcedureAdvertisement +
// Sign + PutRecord) on a separate calling session, the way macula-cli's
// daemon Register now does.
func AdvertiseDirect(session *connection.Session, id identity.KeyPair, realm []byte, procedure string, ttl time.Duration) error {
	advertiseSpec := frame.NewAdvertiseSpec(realm, procedure, id.NodeID())
	if err := session.Advertise(advertiseSpec, id); err != nil {
		return fmt.Errorf("directdial: advertise: %w", err)
	}
	uri := dht.DiscoveryURI(realm, procedure)
	rec, err := dht.NewProcedureAdvertisement(id.NodeID(), uri, session.Station.NodeID, ttl)
	if err != nil {
		return err
	}
	rec = dht.Sign(rec, id)
	return dht.PutRecord(session, id, rec)
}

// KeepAdvertisedDirect calls AdvertiseDirect immediately, then again every
// interval, until ctx is done. It is the "call this again on its own
// schedule" loop AdvertiseDirect's own doc says a long-lived server needs —
// Go has nothing equivalent to macula_response's `reuse_sup` to worry
// about here, because AdvertiseDirect (unlike Erlang's advertise/5, which
// spawns a real per-call OTP supervisor) is already a stateless, side-
// effect-free-on-repeat function: nothing is created per tick that could
// leak.
//
// interval should leave real margin before ttl expires — production
// practice in hecate-om's own capability re-advertise loop (the actual
// consumer of advertise_direct's reuse_sup option on the Erlang side) uses
// a 4x margin: a 30s republish interval against a 120s record TTL.
//
// A failed tick (network blip, connection genuinely dead, etc.) is
// reported via onError (nil is fine — the error is simply dropped) but
// does NOT stop the loop; it tries again at the next interval regardless,
// matching hecate-om's own log-and-continue practice around every DHT
// publish. This loop cannot detect or repair a dead SESSION on its own —
// if session's underlying connection has actually gone down, every tick
// will keep failing the same way until ctx is cancelled; reconnecting a
// dead session is a separate, larger concern this does not attempt to
// solve.
func KeepAdvertisedDirect(ctx context.Context, session *connection.Session, id identity.KeyPair, realm []byte, procedure string, ttl, interval time.Duration, onError func(error)) {
	tick := func() {
		if err := AdvertiseDirect(session, id, realm, procedure, ttl); err != nil && onError != nil {
			onError(err)
		}
	}
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}

// eachCandidate works through candidates until one settles the request or
// ctx is done; ctx must carry a deadline. find returns one pass's candidates,
// or an error when none qualifies. try works one candidate, bounded by share
// for its endpoint lookup and dial; next reports that nothing was sent, so
// another candidate may be tried. A pass in which none qualifies, or every
// candidate failed before sending, is followed by another after retryDelay.
// When ctx is done, the error names the last failure seen together with
// ctx's own.
func eachCandidate[C, T any](ctx context.Context, find func(context.Context) ([]C, error), try func(share context.Context, candidate C) (result T, next bool, err error)) (T, error) {
	var zero T
	var last error
	for ctx.Err() == nil {
		candidates, err := find(ctx)
		if err != nil {
			last = err
		}
		for i, candidate := range candidates {
			if ctx.Err() != nil {
				break
			}
			share, cancel := context.WithTimeout(ctx, candidateShare(ctx, len(candidates)-i))
			result, next, err := try(share, candidate)
			cancel()
			if !next {
				return result, err
			}
			last = err
		}
		pause(ctx, retryDelay)
	}
	return zero, settle(last, ctx.Err())
}

// candidateShare is the time one candidate gets for its endpoint lookup and
// dial: what remains of ctx's deadline split evenly over the candidates not
// yet tried, but no less than minCandidateShare while that much remains. A
// long list still leaves each candidate time to dial, and a candidate whose
// endpoint never resolves can't use up the time the others need.
func candidateShare(ctx context.Context, untried int) time.Duration {
	deadline, _ := ctx.Deadline()
	remaining := time.Until(deadline)
	return max(remaining/time.Duration(untried), min(minCandidateShare, remaining))
}

// lookupTimeout bounds one DHT lookup by what remains of ctx's deadline.
func lookupTimeout(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return defaultLookupTimeout
	}
	return min(defaultLookupTimeout, time.Until(deadline))
}

// pause waits for d, or until ctx is done.
func pause(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// settle joins the last failure seen with the context error that ended the
// work, so either can be matched with errors.Is.
func settle(last, done error) error {
	if last == nil {
		return done
	}
	return fmt.Errorf("%w: %w", last, done)
}

// withResolveDeadline gives ctx DefaultResolveTimeout when it carries no
// deadline of its own.
func withResolveDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, DefaultResolveTimeout)
}

// advertisedStations returns one pass over procedure's advertisements: every
// advertisement that verifies, in the order the DHT returned them.
func advertisedStations(session *connection.Session, id identity.KeyPair, realm []byte, procedure string) func(context.Context) ([]dht.ProcedureAdvertisement, error) {
	key := dht.ProcedureKey(dht.DiscoveryURI(realm, procedure))
	return func(ctx context.Context) ([]dht.ProcedureAdvertisement, error) {
		recs, err := findRecords(session, id, key, lookupTimeout(ctx))
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return nil, ErrProcedureNotAdvertised
		}
		advs := trustedAdvertisements(recs)
		if len(advs) == 0 {
			return nil, ErrNoTrustedAdvertisement
		}
		return advs, nil
	}
}

// authorizedStations is advertisedStations, keeping only the advertisements
// whose cert chain validates to realmCAPEM and names expectedOrg.
func authorizedStations(session *connection.Session, id identity.KeyPair, realm []byte, procedure string, realmCAPEM []byte, expectedOrg string) func(context.Context) ([]dht.ProcedureAdvertisement, error) {
	key := dht.ProcedureKey(dht.DiscoveryURI(realm, procedure))
	return func(ctx context.Context) ([]dht.ProcedureAdvertisement, error) {
		recs, err := findRecords(session, id, key, lookupTimeout(ctx))
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return nil, ErrProcedureNotAdvertised
		}
		advs, lastErr := authorizedAdvertisements(recs, realmCAPEM, expectedOrg)
		switch {
		case len(advs) > 0:
			return advs, nil
		case lastErr != nil:
			return nil, fmt.Errorf("%w: %v", ErrNoAuthorizedAdvertisement, lastErr)
		default:
			return nil, ErrNoTrustedAdvertisement
		}
	}
}

// reached is the station a resolution settled on, with its dialable host and
// port.
type reached struct {
	station []byte
	host    string
	port    uint16
}

// reachableStation settles a resolution on the first advertisement whose
// station endpoint resolves.
func reachableStation(session *connection.Session, id identity.KeyPair) func(context.Context, dht.ProcedureAdvertisement) (reached, bool, error) {
	return func(share context.Context, adv dht.ProcedureAdvertisement) (reached, bool, error) {
		host, port, err := stationEndpoint(share, session, id, adv.ServingStation)
		if err != nil {
			return reached{}, true, err
		}
		return reached{station: adv.ServingStation, host: host, port: port}, false, nil
	}
}

// stationEndpoint resolves station's dialable host and port from its own
// signed station_endpoint record, retrying past an absent or expired replica
// until ctx is done.
func stationEndpoint(ctx context.Context, session *connection.Session, id identity.KeyPair, station []byte) (string, uint16, error) {
	key := dht.StationEndpointKey(station)
	for ctx.Err() == nil {
		rec, err := findRecord(session, id, key, lookupTimeout(ctx))
		switch {
		case errors.Is(err, dht.ErrNotFound):
		case err != nil:
			return "", 0, err
		default:
			host, port, err := endpointOf(rec, station)
			if !errors.Is(err, dht.ErrExpired) {
				return host, port, err
			}
		}
		pause(ctx, retryDelay)
	}
	return "", 0, fmt.Errorf("%w: %w", ErrStationEndpointNotFound, ctx.Err())
}

// endpointOf reads a dialable host and port from rec, station's
// station_endpoint record. The record must be SIGNED BY station itself:
// checking the signer as well as the signature is what makes pinning the
// dial's expected identity meaningful.
func endpointOf(rec dht.Record, station []byte) (string, uint16, error) {
	if !bytesEqual(rec.Key, station) {
		return "", 0, fmt.Errorf("directdial: station_endpoint signer mismatch")
	}
	if err := dht.Verify(rec); err != nil {
		return "", 0, err
	}
	ep, err := dht.ReadStationEndpoint(rec)
	if err != nil {
		return "", 0, err
	}
	if len(ep.HostAdvertised) == 0 {
		return "", 0, fmt.Errorf("directdial: station_endpoint has no advertised host")
	}
	return ep.HostAdvertised[0], ep.QuicPort, nil
}

// call sends one CALL for procedure to the first candidate from find that
// takes it. timeout bounds resolution, each candidate's endpoint lookup and
// dial, and the CALL, which carries the resulting deadline.
func call(ctx context.Context, find func(context.Context) ([]dht.ProcedureAdvertisement, error), resolveVia *connection.Session, id identity.KeyPair, realm []byte, procedure string, payload cbor.Value, timeout time.Duration, ucanToken []byte) (frame.CallResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()
	resp, err := eachCandidate(ctx, find, func(share context.Context, adv dht.ProcedureAdvertisement) (frame.CallResponse, bool, error) {
		host, port, err := stationEndpoint(share, resolveVia, id, adv.ServingStation)
		if err != nil {
			return frame.CallResponse{}, true, err
		}
		resp, sent, err := callAt(share, deadline, host, port, adv.ServingStation, id, procedure, realm, payload, ucanToken)
		return resp, !sent, err
	})
	if err != nil {
		return resp, fmt.Errorf("directdial: %s: %w", procedure, err)
	}
	return resp, nil
}

// opened is a stream a candidate station accepted, with the session that
// carries it.
type opened struct {
	session *connection.Session
	handle  *stream.Handle
}

// openStream opens a stream for procedure at the first candidate from find
// that takes it. timeout bounds resolution and each candidate's endpoint
// lookup and dial; the stream itself runs under ctx and deadlineMs.
func openStream(ctx context.Context, find func(context.Context) ([]dht.ProcedureAdvertisement, error), resolveVia *connection.Session, id identity.KeyPair, realm []byte, procedure string, mode frame.StreamMode, args cbor.Value, deadlineMs int64, timeout time.Duration) (*connection.Session, *stream.Handle, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	o, err := eachCandidate(resolveCtx, find, func(share context.Context, adv dht.ProcedureAdvertisement) (opened, bool, error) {
		host, port, err := stationEndpoint(share, resolveVia, id, adv.ServingStation)
		if err != nil {
			return opened{}, true, err
		}
		session, handle, sent, err := openAt(share, ctx, host, port, adv.ServingStation, id, procedure, realm, mode, args, deadlineMs)
		return opened{session: session, handle: handle}, !sent, err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("directdial: %s: %w", procedure, err)
	}
	return o.session, o.handle, nil
}

// dialAndVerify dials host:port and checks the freshly connected session's
// own signature-verified HELLO identity against station — the shared
// second half of every direct-dial call shape (Call, CallWithCertChain, and
// now OpenStreamDirect/OpenStreamDirectWithCertChain), factored out once
// PutDirect/GetDirect needed the same dial-then-pin sequence against a
// station identity that ISN'T necessarily reached via Resolve.
func dialAndVerify(ctx context.Context, host string, port uint16, station []byte, id identity.KeyPair) (*connection.Session, error) {
	target, err := connection.Connect(ctx, host, port, transport.Insecure{}, id)
	if err != nil {
		return nil, fmt.Errorf("directdial: dial resolved station %x at %s:%d: %w", station, host, port, err)
	}
	if !bytesEqual(target.Station.NodeID, station) {
		_ = target.Close("normal", nil, id)
		return nil, fmt.Errorf(
			"directdial: trust violation — resolved station %x but the dialed peer proved identity %x",
			station, target.Station.NodeID)
	}
	return target, nil
}

// dialAndCall dials station at host and port within dialCtx, pins its
// identity, and sends one CALL there with deadline as its deadline, carrying
// ucanToken when it is not nil. sent reports whether the CALL went out;
// until then nothing reached the station.
func dialAndCall(dialCtx context.Context, deadline time.Time, host string, port uint16, station []byte, id identity.KeyPair, procedure string, realm []byte, payload cbor.Value, ucanToken []byte) (resp frame.CallResponse, sent bool, err error) {
	target, err := dialAndVerify(dialCtx, host, port, station, id)
	if err != nil {
		return frame.CallResponse{}, false, err
	}
	defer func() { _ = target.Close("normal", nil, id) }()
	if ucanToken == nil {
		resp, err = target.Call(procedure, realm, payload, deadline.UnixMilli(), id, time.Until(deadline))
		return resp, true, err
	}
	resp, err = target.CallWithUCAN(procedure, realm, payload, deadline.UnixMilli(), id, time.Until(deadline), ucanToken)
	return resp, true, err
}

// dialAndOpenStream dials station at host and port within dialCtx, pins its
// identity, and opens a stream there under streamCtx. sent reports whether
// the stream's opening frame may have gone out; until then nothing reached
// the station. The caller owns the returned session.
func dialAndOpenStream(dialCtx, streamCtx context.Context, host string, port uint16, station []byte, id identity.KeyPair, procedure string, realm []byte, mode frame.StreamMode, args cbor.Value, deadlineMs int64) (target *connection.Session, h *stream.Handle, sent bool, err error) {
	target, err = dialAndVerify(dialCtx, host, port, station, id)
	if err != nil {
		return nil, nil, false, err
	}
	h, err = stream.Open(streamCtx, target, procedure, realm, mode, args, deadlineMs, id)
	if err != nil {
		_ = target.Close("normal", nil, id)
		return nil, nil, true, fmt.Errorf("directdial: open stream: %w", err)
	}
	return target, h, true, nil
}

// dialAndFetch dials node at host and port within dialCtx, pins its
// identity, and fetches mcid there under fetchCtx. content.Get verifies what
// it receives against mcid.
func dialAndFetch(dialCtx, fetchCtx context.Context, host string, port uint16, node []byte, id identity.KeyPair, mcid manifest.Mcid) ([]byte, error) {
	target, err := dialAndVerify(dialCtx, host, port, node, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = target.Close("normal", nil, id) }()
	return content.Get(fetchCtx, target, mcid, id)
}

// OpenStreamDirect resolves procedure's provider via direct-dial (through
// resolveVia, which is used only to query the DHT) and opens a stream
// there, in one hop, in a SEPARATE connection from resolveVia — the
// streaming-RPC counterpart to Call. The provider must have advertised via
// AdvertiseDirect: streaming's provider side (macula_streamer.erl) shares
// the identical procedure_advertisement mechanism RPC uses (confirmed
// against macula_streamer.erl/macula_stream_sink.erl's own advertise_direct/
// start_link_direct — both are macula_response:advertise_direct/
// macula_direct_dial:call_stream under the hood, nothing stream-specific
// added), so no separate stream-shaped AdvertiseDirect exists or is needed.
//
// The caller owns the returned *connection.Session (and must Close it once
// the stream and any other work on it is done) alongside the *stream.Handle
// itself, since — unlike Call, which owns its dial for exactly one
// request/reply — a stream outlives the single function call that opens it.
//
// timeout bounds resolution and each candidate's endpoint lookup and dial;
// the stream itself runs under ctx and deadlineMs.
func OpenStreamDirect(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, realm []byte, procedure string, mode frame.StreamMode, args cbor.Value, deadlineMs int64, timeout time.Duration) (*connection.Session, *stream.Handle, error) {
	return openStream(ctx, advertisedStations(resolveVia, id, realm, procedure), resolveVia, id, realm, procedure, mode, args, deadlineMs, timeout)
}

// OpenStreamDirectWithCertChain is OpenStreamDirect, resolved via
// ResolveWithCertChain instead of Resolve — see both for the full
// contract. Opt-in managed-realm authorization; OpenStreamDirect itself is
// unaffected.
func OpenStreamDirectWithCertChain(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, realm []byte, procedure string, realmCAPEM []byte, expectedOrg string, mode frame.StreamMode, args cbor.Value, deadlineMs int64, timeout time.Duration) (*connection.Session, *stream.Handle, error) {
	return openStream(ctx, authorizedStations(resolveVia, id, realm, procedure, realmCAPEM, expectedOrg), resolveVia, id, realm, procedure, mode, args, deadlineMs, timeout)
}

// PutDirect stores data at a KNOWN station directly, in one hop, instead of
// going through whatever station resolveVia happens to be connected to.
// Mirrors macula_feeder:start_link_direct/5,6, which — unlike
// procedure/stream direct-dial — takes the target Station's pubkey
// directly rather than resolving one via a procedure_advertisement: content
// has no "procedure" to advertise, so there is nothing to Resolve here
// beyond the station's own station_endpoint (ResolveStationEndpoint).
// resolveVia is used only to query the DHT for station's station_endpoint;
// it does not need to already be connected to station.
//
// Caveat found live: if resolveVia happens to already be connected to
// station (the common case when the caller doesn't have a separate
// resolver session), PutDirect's own internal dial reuses id against the
// SAME station resolveVia is on — this fleet enforces one connection per
// identity and kicks whichever connects second, so resolveVia's own
// connection can be closed out from under the caller by this call. Use a
// different identity for resolveVia than for id if the caller needs
// resolveVia to keep working afterward against that same station.
//
// timeout bounds the station endpoint lookup and the dial; the put itself
// runs under ctx.
func PutDirect(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, station []byte, data []byte, name string, timeout time.Duration) (manifest.Mcid, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	host, port, err := stationEndpoint(dialCtx, resolveVia, id, station)
	if err != nil {
		return manifest.Mcid{}, fmt.Errorf("directdial: resolve station %x: %w", station, err)
	}
	target, err := dialAndVerify(dialCtx, host, port, station, id)
	if err != nil {
		return manifest.Mcid{}, err
	}
	defer func() { _ = target.Close("normal", nil, id) }()
	return content.Put(ctx, target, data, name, id)
}

// GetDirect fetches and verifies the content addressed by mcid from
// whichever station a signed content_announcement names as its host,
// dialing that station in one hop instead of relaying through resolveVia's
// own station. Mirrors macula_direct_dial:get_content/3.
//
// Architectural note this package's other direct-dial functions don't need:
// a content_announcement's endpoint is the FINAL dial target directly (see
// macula_record:read_content_announcement/1's `endpoint` field and
// macula:get_content_station/5's use of it as-is) — unlike
// procedure_advertisement, there is no station-relay indirection, so the
// announcer must genuinely BE independently dialable there. A plain
// outbound-only leaf (everything this SDK's own identity/session model
// supports) cannot legitimately publish one of these about itself — only
// something with its own listening identity (macula-station, or a
// dedicated content-serving relay) can. This SDK therefore does not expose
// a client-facing "AnnounceContentDirect": dht.NewContentAnnouncement stays
// a low-level primitive (mirroring macula_record.erl's own export) for
// that kind of infrastructure-tier code, not ordinary leaf use. GetDirect
// itself has no such limitation — resolving and fetching FROM an
// already-announced provider is a perfectly ordinary leaf operation.
//
// Every announcement that verifies is a candidate. A provider that can't be
// dialled, or whose fetch fails or doesn't verify against mcid, is passed
// over for the next. timeout bounds the whole fetch: lookups, dials and
// transfers.
func GetDirect(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, mcid manifest.Mcid, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	key := dht.ContentKey(mcid[:])
	find := func(ctx context.Context) ([]dht.ContentAnnouncement, error) {
		recs, err := findRecords(resolveVia, id, key, lookupTimeout(ctx))
		if err != nil {
			return nil, fmt.Errorf("directdial: find content providers: %w", err)
		}
		providers := trustedContentProviders(recs)
		if len(providers) == 0 {
			return nil, ErrContentNotAnnounced
		}
		return providers, nil
	}
	return eachCandidate(ctx, find, func(share context.Context, provider dht.ContentAnnouncement) ([]byte, bool, error) {
		host, port, err := parseSeedURL(provider.Endpoint)
		if err != nil {
			return nil, true, fmt.Errorf("directdial: content provider endpoint %q: %w", provider.Endpoint, err)
		}
		data, err := fetchAt(share, ctx, host, port, provider.AnnouncerNode, id, mcid)
		return data, err != nil, err
	})
}

// ErrContentNotAnnounced means mcid has no live, verifiable
// content_announcement in the DHT — either nobody announced it (common:
// single-block content put via _content.put_block alone is never
// announced, matching macula_content_transfer:put_single_block/3), or
// every candidate found failed signature/self-consistency verification.
var ErrContentNotAnnounced = errors.New("directdial: content has no verifiable announcement in the DHT")

// trustedContentProviders mirrors macula.erl's decode_provider/1: a record's
// OWN signature must verify, AND the payload's claimed announcer_node must
// equal the record's own envelope key — a record merely stored under the
// right key but self-signed by a different identity would otherwise still be
// trusted. It returns every provider that passes, in the order given.
func trustedContentProviders(recs []dht.Record) []dht.ContentAnnouncement {
	var providers []dht.ContentAnnouncement
	for _, rec := range recs {
		if dht.Verify(rec) != nil {
			continue
		}
		provider, err := dht.ReadContentAnnouncement(rec)
		if err != nil {
			continue
		}
		if !bytesEqual(provider.AnnouncerNode, rec.Key) {
			continue
		}
		providers = append(providers, provider)
	}
	return providers
}

// parseSeedURL splits a content_announcement's endpoint (a dialable seed
// URL, e.g. "https://host:4433" — macula_client:seed()'s own format) into
// the host/port pair connection.Connect wants. Distinct from
// station_endpoint's already-split host_advertised/quic_port fields —
// content_announcement embeds a single ready-to-dial URL instead.
func parseSeedURL(seed string) (host string, port uint16, err error) {
	u, err := url.Parse(seed)
	if err != nil {
		return "", 0, fmt.Errorf("parse: %w", err)
	}
	h := u.Hostname()
	if h == "" {
		// No scheme/authority at all -- try it as a bare host:port instead
		// of failing outright, matching this SDK's own tolerance elsewhere
		// for a station config given without a scheme.
		var portStr string
		if h, portStr, err = net.SplitHostPort(seed); err != nil {
			return "", 0, fmt.Errorf("not a URL or host:port: %s", seed)
		}
		p, perr := strconv.ParseUint(portStr, 10, 16)
		if perr != nil {
			return "", 0, fmt.Errorf("invalid port %q: %w", portStr, perr)
		}
		return h, uint16(p), nil
	}
	portStr := u.Port()
	if portStr == "" {
		return "", 0, fmt.Errorf("endpoint has no port: %s", seed)
	}
	p, perr := strconv.ParseUint(portStr, 10, 16)
	if perr != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portStr, perr)
	}
	return h, uint16(p), nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
