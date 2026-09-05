package pool

import (
	"context"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/dht"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/transport"
)

// autoReplyDiscovery drives ONE fake bootstrap session through both
// calls a real discovery attempt makes, in order: first
// "_dht.find_records_by_type" (replied with a list containing adv),
// then listStationsProcedure (replied with a single station row
// pointing at discoveredHost:discoveredPort). Any other/later call on
// this session gets no reply -- not needed by these tests, and a
// silent hang here would show up as a test timeout, not a false pass.
func autoReplyDiscovery(s *fakeSession, adv dht.Record, discoveredHost string, discoveredPort int) {
	go func() {
		replied := 0
		for {
			select {
			case <-s.done:
				return
			default:
			}
			frames := s.Sent()
			if len(frames) <= replied {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			f := frames[len(frames)-1]
			replied = len(frames)
			callID, ok := frame.FrameCallID(f)
			if !ok {
				continue
			}
			procV, ok := f.Get("procedure")
			if !ok {
				continue
			}
			procRaw, ok := procV.AsBytes()
			if !ok {
				continue
			}
			switch string(procRaw) {
			case findRecordsByTypeProcedure:
				s.recv <- frame.Result(frame.NewResultSpec(callID, cbor.List([]cbor.Value{adv.ToRPCValue()}), fill32(0x01)))
			case listStationsProcedure:
				station := cbor.Map([]cbor.MapEntry{
					{Key: cbor.Text("quic_port"), Val: cbor.Int(int64(discoveredPort))},
					{Key: cbor.Text("host_advertised"), Val: cbor.List([]cbor.Value{cbor.Bytes([]byte(discoveredHost))})},
				})
				payload := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("stations"), Val: cbor.List([]cbor.Value{station})}})
				s.recv <- frame.Result(frame.NewResultSpec(callID, payload, fill32(0x01)))
			}
		}
	}()
}

func TestStationDiscoveryAddsNewlyFoundStation(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()

	bootstrap := newFakeSession()
	dialer.script("seed.example", 4433, bootstrap)

	discoveredRealm := fill32(0xAB)
	uri := dht.DiscoveryURI(discoveredRealm, listStationsProcedure)
	adv, err := dht.NewProcedureAdvertisement(fill32(0x01), uri, fill32(0x02), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}

	discoveredHost := "discovered.example"
	discovered := newFakeSession()
	dialer.script(discoveredHost, 4433, discovered)

	autoReplyDiscovery(bootstrap, adv, discoveredHost, 4433)

	opts := testOpts(id, dialer.dial)
	opts.StationDiscovery = StationDiscoveryOpts{Enabled: true, RefreshInterval: time.Hour, MaxLinks: 5}
	p, err := Connect(context.Background(), []Seed{{Host: "seed.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()

	waitFor(t, 2*time.Second, func() bool { return dialer.dialCount(discoveredHost, 4433) > 0 })
	waitFor(t, 2*time.Second, func() bool { return p.Status().HealthyLinks == 2 })

	if p.linkCount() != 2 {
		t.Fatalf("linkCount() = %d, want 2 (1 bootstrap + 1 discovered)", p.linkCount())
	}
}

// TestStationDiscoveryDisabledByDefaultChangesNothing is the "zero
// config means zero behavior change" guarantee: a Pool built with the
// zero-value StationDiscoveryOpts must never call _dht.find_records_by_type
// or list_stations at all, and must behave exactly like a pre-discovery
// pool otherwise.
func TestStationDiscoveryDisabledByDefaultChangesNothing(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	bootstrap := newFakeSession()
	dialer.script("seed.example", 4433, bootstrap)

	p, err := Connect(context.Background(), []Seed{{Host: "seed.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	// Give a background discovery loop, if one were mistakenly running,
	// ample time to have made a call by now.
	time.Sleep(100 * time.Millisecond)

	for _, f := range bootstrap.Sent() {
		procV, ok := f.Get("procedure")
		if !ok {
			continue
		}
		procRaw, _ := procV.AsBytes()
		t.Fatalf("discovery-disabled pool made a call to procedure %q -- StationDiscovery zero value must be a complete no-op", string(procRaw))
	}
	if p.linkCount() != 1 {
		t.Fatalf("linkCount() = %d, want 1 (bootstrap only, discovery disabled)", p.linkCount())
	}
}

// TestStationDiscoveryRespectsMaxLinks: with MaxLinks == 1 (the
// bootstrap link itself), a discovered station must NOT be added even
// though it was found -- confirms the cap is enforced against the
// TOTAL link count (bootstrap + discovered), not just discovered ones.
func TestStationDiscoveryRespectsMaxLinks(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	bootstrap := newFakeSession()
	dialer.script("seed.example", 4433, bootstrap)

	discoveredRealm := fill32(0xCD)
	uri := dht.DiscoveryURI(discoveredRealm, listStationsProcedure)
	adv, err := dht.NewProcedureAdvertisement(fill32(0x01), uri, fill32(0x02), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	discoveredHost := "should-not-be-dialed.example"
	dialer.script(discoveredHost, 4433, newFakeSession())
	autoReplyDiscovery(bootstrap, adv, discoveredHost, 4433)

	opts := testOpts(id, dialer.dial)
	opts.StationDiscovery = StationDiscoveryOpts{Enabled: true, RefreshInterval: time.Hour, MaxLinks: 1}
	p, err := Connect(context.Background(), []Seed{{Host: "seed.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	// Let a discovery attempt run its course (it will find the station
	// and reject adding it, MaxLinks already met).
	time.Sleep(150 * time.Millisecond)

	if dialer.dialCount(discoveredHost, 4433) != 0 {
		t.Fatalf("discovered station was dialed despite MaxLinks == 1 (bootstrap already at the cap)")
	}
	if p.linkCount() != 1 {
		t.Fatalf("linkCount() = %d, want 1 -- MaxLinks must cap the TOTAL, not just discovered links", p.linkCount())
	}
}

// TestStationDiscoveryDoesNotTearDownLinkMissingFromRefresh: a second
// discovery refresh whose station list omits a previously-discovered
// station must NOT remove that station's link -- replication lag in
// the directory isn't evidence a station is gone. Modeled directly
// (not by waiting a real RefreshInterval) by calling discoverOnce
// twice: once with the station present, once with an empty list.
func TestStationDiscoveryDoesNotTearDownLinkMissingFromRefresh(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	bootstrap := newFakeSession()
	dialer.script("seed.example", 4433, bootstrap)

	discoveredHost := "discovered.example"
	dialer.script(discoveredHost, 4433, newFakeSession())

	opts := testOpts(id, dialer.dial)
	opts.StationDiscovery = StationDiscoveryOpts{Enabled: true, RefreshInterval: time.Hour, MaxLinks: 5}
	p, err := Connect(context.Background(), []Seed{{Host: "seed.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	// First "refresh": station present -- addDiscoveredLinks adds it directly,
	// bypassing the DHT-realm-resolution round trip (already covered by
	// TestStationDiscoveryAddsNewlyFoundStation) to isolate this test's
	// actual subject: the SECOND refresh's behavior.
	station := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("quic_port"), Val: cbor.Int(4433)},
		{Key: cbor.Text("host_advertised"), Val: cbor.List([]cbor.Value{cbor.Bytes([]byte(discoveredHost))})},
	})
	p.addDiscoveredLinks([]cbor.Value{station})
	waitFor(t, time.Second, func() bool { return p.linkCount() == 2 })

	// Second "refresh": empty station list (as if the directory no
	// longer lists it, or a filter changed) -- must not remove anything.
	p.addDiscoveredLinks(nil)
	time.Sleep(50 * time.Millisecond)

	if p.linkCount() != 2 {
		t.Fatalf("linkCount() = %d after an empty refresh, want 2 -- a station missing from a refresh must not tear down its link", p.linkCount())
	}
}

func TestResolveListStationsRealmSkipsDirectDialOnlyAdvertisement(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	bootstrap := newFakeSession()
	dialer.script("seed.example", 4433, bootstrap)

	// A DIFFERENT procedure name that happens to share nothing with
	// listStationsProcedure but sit at the same DHT record type --
	// resolveListStationsRealm must not match it.
	otherRealm := fill32(0xEF)
	otherURI := dht.DiscoveryURI(otherRealm, "_/hecate_stations.list_stations")
	otherAdv, err := dht.NewProcedureAdvertisement(fill32(0x01), otherURI, fill32(0x02), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}

	realRealm := fill32(0x12)
	realURI := dht.DiscoveryURI(realRealm, listStationsProcedure)
	realAdv, err := dht.NewProcedureAdvertisement(fill32(0x03), realURI, fill32(0x04), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}

	go func() {
		replied := 0
		for {
			select {
			case <-bootstrap.done:
				return
			default:
			}
			frames := bootstrap.Sent()
			if len(frames) <= replied {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			f := frames[len(frames)-1]
			replied = len(frames)
			callID, _ := frame.FrameCallID(f)
			bootstrap.recv <- frame.Result(frame.NewResultSpec(
				callID,
				cbor.List([]cbor.Value{otherAdv.ToRPCValue(), realAdv.ToRPCValue()}),
				fill32(0x01),
			))
			return
		}
	}()

	opts := testOpts(id, dialer.dial)
	p, err := Connect(context.Background(), []Seed{{Host: "seed.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	realm, ok := p.resolveListStationsRealm()
	if !ok {
		t.Fatalf("resolveListStationsRealm: no match found, want realRealm")
	}
	if string(realm) != string(realRealm) {
		t.Fatalf("resolveListStationsRealm resolved %x, want the real listStationsProcedure realm %x (the direct-dial-only advertisement must be skipped)", realm, realRealm)
	}
}

// TestDialTargetFromStationRowPrefersHostnameOverBareIP is a regression
// test for a real bug caught live (2026-09-05): every station on the
// real fleet advertises host_advertised as a bare IPv6 literal, never a
// DNS name, so dialing it under this package's WebPKI trust always
// failed TLS cert validation ("doesn't contain any IP SANs"). hostname
// is the field actually covered by each station's own certificate and
// must be preferred whenever both are present -- matches a real
// mesh_list_stations row shape exactly, not a synthetic one.
func TestDialTargetFromStationRowPrefersHostnameOverBareIP(t *testing.T) {
	row := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("hostname"), Val: cbor.Bytes([]byte("station-de-frankfurt.macula.io"))},
		{Key: cbor.Text("host_advertised"), Val: cbor.List([]cbor.Value{cbor.Bytes([]byte("2a01:7e01::f03c:94ff:fe22:719e"))})},
		{Key: cbor.Text("quic_port"), Val: cbor.Int(4433)},
	})
	host, port, ok := dialTargetFromStationRow(row)
	if !ok {
		t.Fatalf("dialTargetFromStationRow returned ok=false for a well-formed row")
	}
	if host != "station-de-frankfurt.macula.io" {
		t.Fatalf("dialTargetFromStationRow picked host=%q, want the DNS hostname, not the bare IP in host_advertised", host)
	}
	if port != 4433 {
		t.Fatalf("dialTargetFromStationRow port = %d, want 4433", port)
	}
}

// TestDialTargetFromStationRowFallsBackToHostAdvertised covers the
// no-node_record-yet case (confirmed live: one real row had
// host_advertised + quic_port but no hostname/city/kind at all) --
// there's still something dialable there, just not WebPKI-safe unless
// the deployment's cert setup happens to cover it; not this function's
// job to judge that, only to prefer the better field when it exists.
func TestDialTargetFromStationRowFallsBackToHostAdvertised(t *testing.T) {
	row := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("host_advertised"), Val: cbor.List([]cbor.Value{cbor.Bytes([]byte("2600:3c0b::2000:1fff:fe35:416b"))})},
		{Key: cbor.Text("quic_port"), Val: cbor.Int(4433)},
	})
	host, _, ok := dialTargetFromStationRow(row)
	if !ok || host != "2600:3c0b::2000:1fff:fe35:416b" {
		t.Fatalf("dialTargetFromStationRow(host_advertised only) = (%q, ok=%v), want the fallback IP", host, ok)
	}
}

// TestAddDiscoveredLinksSkipsStationAlreadyLinkedByNodeID is a
// regression test for a real gap Fable's review found: addLink itself
// dedupes by host:port SPELLING only, so a discovered row naming the
// SAME station under a different spelling than the bootstrap seed used
// (different case, a CNAME, an IP-literal seed) would otherwise add a
// second connection to a station this pool already holds -- which the
// station's own per-identity dedupe answers by kicking the older link,
// the exact permanent flap CallStation's own doc names as a known gap
// for its differently-shaped case. addDiscoveredLinks must catch this
// by PEER IDENTITY (node_id), not spelling.
func TestAddDiscoveredLinksSkipsStationAlreadyLinkedByNodeID(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()

	bootstrapNodeID := fill32(0x55)
	dialer.scriptNodeID("seed.example", 4433, bootstrapNodeID)
	dialer.script("seed.example", 4433, newFakeSession())

	opts := testOpts(id, dialer.dial)
	opts.StationDiscovery = StationDiscoveryOpts{Enabled: true, RefreshInterval: time.Hour, MaxLinks: 5}
	p, err := Connect(context.Background(), []Seed{{Host: "seed.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })
	waitFor(t, time.Second, func() bool { return p.hasLinkForNodeID(bootstrapNodeID) })

	// A "discovered" row for the SAME station (same node_id) but under
	// a differently-spelled host -- e.g. a CNAME or a case difference --
	// which addLink's own key-based dedupe would NOT catch on its own.
	differentSpellingRow := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("hostname"), Val: cbor.Bytes([]byte("SEED.EXAMPLE"))},
		{Key: cbor.Text("quic_port"), Val: cbor.Int(4433)},
		{Key: cbor.Text("node_id"), Val: cbor.Bytes(bootstrapNodeID)},
	})
	p.addDiscoveredLinks([]cbor.Value{differentSpellingRow})
	time.Sleep(50 * time.Millisecond)

	if dialer.dialCount("SEED.EXAMPLE", 4433) != 0 {
		t.Fatalf("addDiscoveredLinks dialed a differently-spelled hostname for a station already linked by node_id -- dedupe-by-identity did not work")
	}
	if p.linkCount() != 1 {
		t.Fatalf("linkCount() = %d, want 1 -- a same-node_id row must not add a second link", p.linkCount())
	}
}

// TestAddDiscoveredLinksSkipsBareIPUnderWebPKI is a regression test for
// the second real gap Fable's review found: a discovered row whose
// only dialable host is a bare IP literal (host_advertised, no
// hostname) can NEVER become healthy under transport.WebPKI (TLS cert
// validation fails on every redial, forever) -- adding it anyway
// permanently occupies one MaxLinks slot with a link that will never
// do anything useful. Must be skipped before it ever reaches addLink.
func TestAddDiscoveredLinksSkipsBareIPUnderWebPKI(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	dialer.script("seed.example", 4433, newFakeSession())

	opts := testOpts(id, dialer.dial)
	opts.Trust = transport.WebPKI{}
	opts.StationDiscovery = StationDiscoveryOpts{Enabled: true, RefreshInterval: time.Hour, MaxLinks: 5}
	p, err := Connect(context.Background(), []Seed{{Host: "seed.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	bareIPHost := "2600:3c0b::2000:1fff:fe35:416b"
	bareIPRow := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("host_advertised"), Val: cbor.List([]cbor.Value{cbor.Bytes([]byte(bareIPHost))})},
		{Key: cbor.Text("quic_port"), Val: cbor.Int(4433)},
	})
	p.addDiscoveredLinks([]cbor.Value{bareIPRow})
	time.Sleep(50 * time.Millisecond)

	if dialer.dialCount(bareIPHost, 4433) != 0 {
		t.Fatalf("addDiscoveredLinks dialed a bare-IP-only station under WebPKI trust -- this link can never become healthy and would permanently waste a MaxLinks slot")
	}
	if p.linkCount() != 1 {
		t.Fatalf("linkCount() = %d, want 1 -- a bare-IP-only row must be rejected under WebPKI, not added", p.linkCount())
	}
}
