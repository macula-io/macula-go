package pool

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/dht"
	"github.com/macula-io/macula-go/transport"
)

// listStationsProcedure is hecate_stations.list_stations's mesh-callable
// procedure name. An EXACT match against this (never a prefix check) is
// what naturally excludes hecate-stations' own direct-dial-only
// advertisement (a genuinely different procedure name, not this one
// with a prefix stripped) -- matches macula-mcp's mesh_list_stations
// tool's own filtering (registerMeshListStations/decodeRecord in that
// repo: `procedure === LIST_STATIONS_PROCEDURE`).
const listStationsProcedure = "hecate_stations.list_stations"

// findRecordsByTypeProcedure mirrors dht package's own unexported
// findRecordsByTypeProc constant -- duplicated as a literal (not
// imported) because it's genuinely trivial, unlike the record-decoding
// logic this file DOES reuse via dht.RecordFromRPCValue.
const findRecordsByTypeProcedure = "_dht.find_records_by_type"

// discoveryPollInterval bounds how often discoverStations checks for a
// first healthy link before its first real attempt -- matches this
// package's own existing connectPollInterval (rpc.go), same idiom.
const discoveryPollInterval = 50 * time.Millisecond

// discoveryTimeout bounds both DHT calls a discovery attempt makes --
// matches dht package's own dhtTimeout; reconstructed here rather than
// imported since dht's own constant is unexported and this value is
// small/stable enough not to be worth plumbing an export for.
const discoveryTimeout = 5 * time.Second

// discoverStations is the background goroutine StationDiscoveryOpts
// spawns when enabled (see Connect). It waits for the pool's first
// healthy link -- there's no point asking the DHT anything before
// then, and every discovery call below routes through Pool.Call, which
// itself needs a healthy link -- then resolves and calls
// hecate_stations.list_stations once immediately, and repeats every
// RefreshInterval thereafter. A failed attempt (hecate_stations not
// currently advertised anywhere this pool's links can see, a timeout,
// a malformed reply) is silently retried next tick: there is no caller
// to report a background-loop error to, and the bootstrap Seeds this
// Pool was given already keep it fully usable regardless of whether
// discovery ever succeeds even once.
func (p *Pool) discoverStations() {
	if !p.waitForAnyHealthyLink() {
		return
	}
	for {
		p.discoverOnce()
		select {
		case <-time.After(p.opts.StationDiscovery.RefreshInterval):
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Pool) waitForAnyHealthyLink() bool {
	for {
		if len(p.connectedActors()) > 0 {
			return true
		}
		select {
		case <-time.After(discoveryPollInterval):
		case <-p.ctx.Done():
			return false
		}
	}
}

func (p *Pool) discoverOnce() {
	realm, ok := p.resolveListStationsRealm()
	if !ok {
		return
	}
	stations, ok := p.callListStations(realm)
	if !ok {
		return
	}
	p.addDiscoveredLinks(stations)
}

// resolveListStationsRealm finds which realm hecate_stations.list_stations
// is CURRENTLY advertised under, via a DHT find_records_by_type query --
// there is no way to know this without asking (it is never the default
// all-zero realm the query itself travels under), matching macula-mcp's
// mesh_list_stations tool's own two-call shape exactly: a DHT lookup,
// then the real call, using whatever realm the lookup found.
func (p *Pool) resolveListStationsRealm() ([]byte, bool) {
	ctx, cancel := context.WithTimeout(p.ctx, discoveryTimeout)
	defer cancel()
	args := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("type"), Val: cbor.Uint64(uint64(dht.TypeProcedureAdvertisement))},
	})
	resp, err := p.Call(ctx, make([]byte, 32), findRecordsByTypeProcedure, args, discoveryTimeout)
	if err != nil || resp.IsError {
		return nil, false
	}
	list, ok := resp.Payload.AsList()
	if !ok {
		return nil, false
	}
	for _, item := range list {
		rec, rerr := dht.RecordFromRPCValue(item)
		if rerr != nil || rec.Type != dht.TypeProcedureAdvertisement {
			continue
		}
		adv, aerr := dht.ReadProcedureAdvertisement(rec)
		if aerr != nil {
			continue
		}
		// ProcedureURI is hex(realm) + "/" + procedure (dht.DiscoveryURI's
		// own format) -- split on the FIRST "/" only, matching
		// macula-mcp's decodeRecord (uri.indexOf("/")) exactly, since the
		// procedure segment can itself legitimately contain further "/"s.
		slash := strings.IndexByte(adv.ProcedureURI, '/')
		if slash == -1 || adv.ProcedureURI[slash+1:] != listStationsProcedure {
			continue
		}
		realm, derr := hex.DecodeString(adv.ProcedureURI[:slash])
		if derr != nil || len(realm) != 32 {
			continue
		}
		return realm, true
	}
	return nil, false
}

// callListStations calls hecate_stations.list_stations under realm
// with no filters (every known station) and returns its raw
// "stations" list entries for addDiscoveredLinks to parse.
func (p *Pool) callListStations(realm []byte) ([]cbor.Value, bool) {
	ctx, cancel := context.WithTimeout(p.ctx, discoveryTimeout)
	defer cancel()
	resp, err := p.Call(ctx, realm, listStationsProcedure, cbor.Map(nil), discoveryTimeout)
	if err != nil || resp.IsError {
		return nil, false
	}
	stationsV, ok := resp.Payload.Get("stations")
	if !ok {
		return nil, false
	}
	list, ok := stationsV.AsList()
	if !ok {
		return nil, false
	}
	return list, true
}

// addDiscoveredLinks adds one link per station not already known,
// capped at StationDiscovery.MaxLinks (see its own doc for exactly
// what that bounds). Additive only, by construction: addLink is
// already a no-op for an already-known host:port, and there is
// deliberately no removal path here at all -- a station missing from
// this response does not tear down an existing link; see
// StationDiscoveryOpts' own doc for why.
//
// Two rejections beyond dialTargetFromStationRow's own, both found by
// adversarial review of a live discovery run, not reasoned about in
// the abstract:
//
//  1. A row whose node_id already matches a link this Pool holds
//     (bootstrap or previously discovered) is skipped, keyed by the
//     PEER'S OWN IDENTITY rather than by host:port spelling.
//     link.go's own addLink dedupes by exact host:port string only --
//     a bootstrap Seed spelled differently than hecate_stations'
//     node_record.hostname for the SAME station (different case, a
//     CNAME, an IP-literal seed) would otherwise pass that check and
//     add a SECOND connection to a station the pool already holds
//     under one shared identity, which the station's own per-identity
//     dedupe answers by kicking the older link -- the exact permanent
//     flap CallStation's own doc already names as a known, not-yet-
//     closed gap for its differently-shaped direct-dial case. Checking
//     by node id here closes it for discovery specifically, without
//     touching CallStation's own occurrence of the same gap. Residual
//     window, not closed by this: a link only has a PeerNodeID after
//     its FIRST successful handshake, so a bootstrap Seed still mid-
//     handshake (nothing pathological -- just a slower dial than the
//     first Seed that made discoverStations start) is invisible to
//     hasLinkForNodeID until it finishes; a discovery tick landing in
//     that exact window can still add a duplicate that flaps once the
//     slow Seed comes up. No clean pre-dial fix exists without already
//     knowing the Seed's identity ahead of time.
//  2. A row whose only dialable host is a bare IP literal (no
//     hostname, only host_advertised) is skipped when Trust is
//     transport.WebPKI -- see dialTargetFromStationRow's own doc for
//     why host_advertised is IP-only on the real fleet. Adding it
//     anyway would occupy a MaxLinks slot with a link that can NEVER
//     become healthy under WebPKI (TLS cert validation fails on every
//     single redial, forever, at RespawnDelay's fixed 1s cadence,
//     with nothing here to give up and free the slot) -- confirmed
//     live: this is exactly what silently ate one of five discovered
//     slots before this check existed. Insecure/Pinned trust modes may
//     genuinely support a bare IP, so this only rejects under WebPKI
//     specifically, not unconditionally.
func (p *Pool) addDiscoveredLinks(stations []cbor.Value) {
	isWebPKI := isWebPKITrust(p.opts.Trust)
	for _, st := range stations {
		if p.linkCount() >= p.opts.StationDiscovery.MaxLinks {
			return
		}
		host, port, ok := dialTargetFromStationRow(st)
		if !ok {
			continue
		}
		if isWebPKI && net.ParseIP(host) != nil {
			continue
		}
		if nodeID, ok := stationNodeID(st); ok && p.hasLinkForNodeID(nodeID) {
			continue
		}
		p.addLink(host, port, p.opts.Trust)
	}
}

// stationNodeID extracts a station row's node_id (32 raw bytes, same
// CBOR-bytes wire convention as every other identifier field in this
// response -- see dialTargetFromStationRow's own doc).
func stationNodeID(st cbor.Value) ([]byte, bool) {
	v, ok := st.Get("node_id")
	if !ok {
		return nil, false
	}
	b, ok := v.AsBytes()
	if !ok || len(b) != 32 {
		return nil, false
	}
	return b, true
}

// dialTargetFromStationRow extracts a dialable host:port from one
// hecate_stations.list_stations response row, preferring the
// node_record-derived hostname (a real DNS name, e.g.
// "station-de-frankfurt.macula.io") over host_advertised[0] (the
// station_endpoint-derived field directdial.ResolveStationEndpoint
// dials by).
//
// This is the OPPOSITE priority from ResolveStationEndpoint, and
// deliberately so, not an oversight: confirmed live against the real
// fleet (mesh_list_stations, 2026-09-05) that host_advertised there is
// ALWAYS a bare IPv6 literal, never a DNS name, on every single
// station row. directdial can dial that safely because
// directdial.dialAndVerify uses transport.Insecure{} and verifies
// trust by matching the resolved station's NODE ID instead -- it
// never depends on the peer's TLS certificate covering the address
// dialed. This package's addLink uses p.opts.Trust, which for any real
// deployment is transport.WebPKI{} (hostname + CA-chain validation) --
// dialing a bare IP under WebPKI fails immediately with "cannot
// validate certificate ... doesn't contain any IP SANs" (reproduced
// live: all 4 non-bootstrap stations in a real discovery run failed
// exactly this way before this ordering was fixed). hostname is what
// each station's own cert is actually issued for, so it's the correct
// preference here even though it's the LOWER-priority field for
// direct-dial's own, differently-trusted use case. A row with neither
// field at all (e.g. a bare daemon/station_endpoint entry with no
// node_record yet) is skipped, not guessed at.
//
// host_advertised entries (used only as a fallback here) arrive as
// CBOR byte strings, not text -- macula_record.erl's with_host_list/2
// puts each host in as a bare Erlang binary (confirmed against a real
// station's own published record, see dht.ReadStationEndpoint's
// identical handling) -- try bytes first, text as a fallback in case a
// future publisher wraps these properly. hostname itself arrives the
// same way (confirmed live), so gets the identical treatment.
func dialTargetFromStationRow(st cbor.Value) (host string, port uint16, ok bool) {
	portV, pok := st.Get("quic_port")
	if !pok {
		return "", 0, false
	}
	portI, pok := portV.AsInt64()
	if !pok || portI <= 0 || portI > 65535 {
		return "", 0, false
	}
	if hostnameV, hok := st.Get("hostname"); hok {
		if h, ok := asHostText(hostnameV); ok {
			return h, uint16(portI), true
		}
	}
	if hostsV, hok := st.Get("host_advertised"); hok {
		if list, lok := hostsV.AsList(); lok && len(list) > 0 {
			if h, ok := asHostText(list[0]); ok {
				return h, uint16(portI), true
			}
		}
	}
	return "", 0, false
}

// asHostText decodes a host field, trying bytes then text (see
// dialTargetFromStationRow's own doc on why). An empty string is
// rejected either way -- a present-but-empty field is not a usable
// dial target, and net.ParseIP("") returns nil, so an unrejected empty
// host would silently bypass addDiscoveredLinks' own bare-IP-under-
// WebPKI check further up the call chain.
func asHostText(v cbor.Value) (string, bool) {
	if b, ok := v.AsBytes(); ok && len(b) > 0 {
		return string(b), true
	}
	if s, ok := v.AsText(); ok && s != "" {
		return s, true
	}
	return "", false
}

// linkCount is the current total number of links this Pool holds
// (bootstrap + discovered), for StationDiscovery.MaxLinks enforcement.
func (p *Pool) linkCount() int {
	p.linksMu.RLock()
	defer p.linksMu.RUnlock()
	return len(p.links)
}

// hasLinkForNodeID reports whether any link this Pool currently holds
// (bootstrap or previously discovered, live or mid-backoff) has ever
// proved this exact peer node id -- see addDiscoveredLinks' own doc on
// why discovery dedupes by identity here, not just by host:port
// spelling the way addLink itself does.
func (p *Pool) hasLinkForNodeID(nodeID []byte) bool {
	p.linksMu.RLock()
	defer p.linksMu.RUnlock()
	for _, l := range p.links {
		if bytes.Equal(l.PeerNodeID(), nodeID) {
			return true
		}
	}
	return false
}

// isWebPKITrust reports whether trust is transport.WebPKI, checking
// both the value and pointer forms -- WebPKI has a value receiver
// (transport.Trust is satisfied by both transport.WebPKI{} and
// &transport.WebPKI{}, and every call site in this repo happens to use
// the value form, but nothing stops a caller from using the pointer
// form instead), and a bare type assertion against the value type
// alone would silently miss that and let a bare-IP-under-WebPKI link
// back in as if this check didn't exist at all.
func isWebPKITrust(t transport.Trust) bool {
	switch t.(type) {
	case transport.WebPKI, *transport.WebPKI:
		return true
	default:
		return false
	}
}
