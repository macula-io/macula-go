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
// cert_chain-based org/realm authorization (Slice 7c Direction B,
// macula_record:verify_advertisement_cert_chain/3 on the Erlang side) is
// NOT ported here — it is opt-in even in the reference implementation,
// and blocked behind direct-dial itself existing at all in this SDK.
package directdial

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/connection"
	"github.com/macula-io/macula-go-sdk/dht"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/transport"
)

// resolveRetries/resolveRetryDelay match macula_direct_dial.erl's
// ?RESOLVE_RETRIES/?RESOLVE_RETRY_MS — a record just published on the
// provider's station has not necessarily replicated to the resolving
// station yet, so the first miss is not treated as failure.
const (
	resolveRetries    = 50
	resolveRetryDelay = 100 * time.Millisecond
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
func Resolve(session *connection.Session, id identity.KeyPair, realm []byte, procedure string) (station []byte, host string, port uint16, err error) {
	uri := dht.DiscoveryURI(realm, procedure)
	key := dht.ProcedureKey(uri)

	var recs []dht.Record
	for attempt := 0; attempt < resolveRetries; attempt++ {
		recs, err = dht.FindRecords(session, id, key)
		if err == nil && len(recs) > 0 {
			break
		}
		time.Sleep(resolveRetryDelay)
	}
	if len(recs) == 0 {
		return nil, "", 0, ErrProcedureNotAdvertised
	}

	adv, ok := firstTrustedAdvertisement(recs)
	if !ok {
		return nil, "", 0, ErrNoTrustedAdvertisement
	}

	return resolveStationEndpoint(session, id, adv.ServingStation)
}

func firstTrustedAdvertisement(recs []dht.Record) (dht.ProcedureAdvertisement, bool) {
	for _, rec := range recs {
		if dht.Verify(rec) != nil {
			continue
		}
		adv, err := dht.ReadProcedureAdvertisement(rec)
		if err != nil {
			continue
		}
		return adv, true
	}
	return dht.ProcedureAdvertisement{}, false
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
func ResolveWithCertChain(session *connection.Session, id identity.KeyPair, realm []byte, procedure string, realmCAPEM []byte, expectedOrg string) (station []byte, host string, port uint16, err error) {
	uri := dht.DiscoveryURI(realm, procedure)
	key := dht.ProcedureKey(uri)

	var recs []dht.Record
	for attempt := 0; attempt < resolveRetries; attempt++ {
		recs, err = dht.FindRecords(session, id, key)
		if err == nil && len(recs) > 0 {
			break
		}
		time.Sleep(resolveRetryDelay)
	}
	if len(recs) == 0 {
		return nil, "", 0, ErrProcedureNotAdvertised
	}

	adv, ok, lastErr := firstAuthorizedAdvertisement(recs, realmCAPEM, expectedOrg)
	if !ok {
		if lastErr != nil {
			return nil, "", 0, fmt.Errorf("%w: %v", ErrNoAuthorizedAdvertisement, lastErr)
		}
		return nil, "", 0, ErrNoTrustedAdvertisement
	}

	return resolveStationEndpoint(session, id, adv.ServingStation)
}

// firstAuthorizedAdvertisement is firstTrustedAdvertisement plus the
// cert-chain check. lastErr is the most recent VerifyAdvertisementCertChain
// failure seen (nil if every candidate failed the plain signature check
// instead, in which case the caller should report ErrNoTrustedAdvertisement,
// matching Resolve's own distinction).
func firstAuthorizedAdvertisement(recs []dht.Record, realmCAPEM []byte, expectedOrg string) (dht.ProcedureAdvertisement, bool, error) {
	var lastErr error
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
		return adv, true, nil
	}
	return dht.ProcedureAdvertisement{}, false, lastErr
}

// CallWithCertChain is Call, resolved via ResolveWithCertChain instead of
// Resolve — see both for the full contract. Opt-in managed-realm
// authorization; Call itself is unaffected.
func CallWithCertChain(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, realm []byte, procedure string, realmCAPEM []byte, expectedOrg string, payload cbor.Value, timeout time.Duration) (frame.CallResponse, error) {
	station, host, port, err := ResolveWithCertChain(resolveVia, id, realm, procedure, realmCAPEM, expectedOrg)
	if err != nil {
		return frame.CallResponse{}, fmt.Errorf("directdial: resolve %s: %w", procedure, err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target, err := connection.Connect(dialCtx, host, port, transport.Insecure{}, id)
	if err != nil {
		return frame.CallResponse{}, fmt.Errorf("directdial: dial resolved station %x at %s:%d: %w", station, host, port, err)
	}
	defer func() { _ = target.Close("normal", nil, id) }()

	if !bytesEqual(target.Station.NodeID, station) {
		return frame.CallResponse{}, fmt.Errorf(
			"directdial: trust violation — resolved station %x but the dialed peer proved identity %x",
			station, target.Station.NodeID)
	}

	return target.Call(procedure, realm, payload, time.Now().Add(timeout).UnixMilli(), id, timeout)
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

// resolveStationEndpoint retries past a resolved-but-stale record, not
// just an absent one — the DHT can hand back a replica that hasn't been
// evicted yet even though the station's own current publish is live.
// Giving up on the first stale hit would make an otherwise healthy
// station unreachable via direct-dial until that one replica ages out.
func resolveStationEndpoint(session *connection.Session, id identity.KeyPair, station []byte) (out []byte, host string, port uint16, err error) {
	key := dht.StationEndpointKey(station)
	for attempt := 0; attempt < resolveRetries; attempt++ {
		rec, ferr := dht.FindRecord(session, id, key)
		if ferr != nil {
			if errors.Is(ferr, dht.ErrNotFound) {
				time.Sleep(resolveRetryDelay)
				continue
			}
			return nil, "", 0, ferr
		}
		// The station_endpoint record for `station` must be SIGNED BY
		// `station` itself — checking the signature and that the signer
		// is exactly `station`, not just any valid signature, is what
		// makes pinning the dial's expected identity meaningful below.
		if !bytesEqual(rec.Key, station) {
			return nil, "", 0, fmt.Errorf("directdial: station_endpoint signer mismatch")
		}
		verr := dht.Verify(rec)
		if errors.Is(verr, dht.ErrExpired) {
			time.Sleep(resolveRetryDelay)
			continue
		}
		if verr != nil {
			return nil, "", 0, verr
		}
		ep, rerr := dht.ReadStationEndpoint(rec)
		if rerr != nil {
			return nil, "", 0, rerr
		}
		if len(ep.HostAdvertised) == 0 {
			return nil, "", 0, fmt.Errorf("directdial: station_endpoint has no advertised host")
		}
		return station, ep.HostAdvertised[0], ep.QuicPort, nil
	}
	return nil, "", 0, ErrStationEndpointNotFound
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
// the signed DHT chain resolved; a mismatch is a trust violation, not a
// retryable error, and the call is refused.
func Call(ctx context.Context, resolveVia *connection.Session, id identity.KeyPair, realm []byte, procedure string, payload cbor.Value, timeout time.Duration) (frame.CallResponse, error) {
	station, host, port, err := Resolve(resolveVia, id, realm, procedure)
	if err != nil {
		return frame.CallResponse{}, fmt.Errorf("directdial: resolve %s: %w", procedure, err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target, err := connection.Connect(dialCtx, host, port, transport.Insecure{}, id)
	if err != nil {
		return frame.CallResponse{}, fmt.Errorf("directdial: dial resolved station %x at %s:%d: %w", station, host, port, err)
	}
	defer func() { _ = target.Close("normal", nil, id) }()

	if !bytesEqual(target.Station.NodeID, station) {
		return frame.CallResponse{}, fmt.Errorf(
			"directdial: trust violation — resolved station %x but the dialed peer proved identity %x",
			station, target.Station.NodeID)
	}

	return target.Call(procedure, realm, payload, time.Now().Add(timeout).UnixMilli(), id, timeout)
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
// macula-rust-sdk, which hit it first by verifying an actual RESULT came
// back through direct-dial instead of accepting a clean unknown_next_peer
// as sufficient (that only proves resolve+dial+trust-chain work, not that
// a live handler is reachable).
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
