package record

import (
	"slices"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror station_endpoint_payload_and_reader_test in macula's
// macula_record_tests at merge-11.0.0 871986a3, with the builder's bounds and
// the reader's host forms beside it. A station endpoint's storage key is in
// storage_key_test.go.

func TestAStationEndpointCarriesItsPayloadAndReadsBack(t *testing.T) {
	keys := keysFor(t)
	built := must[Record](t)(NewStationEndpoint(4433, StationEndpointOptions{HostAdvertised: []string{"beam00.lab"}}))
	verified := must[Verified](t)(Verify(wireOf(t, must[Record](t)(Sign(built, keys.node))), profile.PQPure, nowMs())).Record()
	endpoint := must[StationEndpoint](t)(ReadStationEndpoint(verified))
	if endpoint.QUICPort != 4433 || !slices.Equal(endpoint.HostAdvertised, []string{"beam00.lab"}) {
		t.Errorf("read port %d and hosts %q, want 4433 and beam00.lab", endpoint.QUICPort, endpoint.HostAdvertised)
	}
	if hosts, _ := payloadField(verified.Payload, "host_advertised").AsList(); len(hosts) != 1 || hosts[0].Kind() != cbor.KindBytes {
		t.Errorf("host_advertised travels as %v, want one byte string", hosts)
	}
}

// A station endpoint built without a ttl lives its type's maximum, 5 minutes;
// its ALPN travels as text, and no hosts leave host_advertised out.
func TestAStationEndpointDefaultsToFiveMinutesAndCarriesItsALPN(t *testing.T) {
	r := must[Record](t)(NewStationEndpoint(4433, StationEndpointOptions{ALPN: "macula/1"}))
	if lived := int64(r.ExpiresAt - r.CreatedAt); lived != 5*testMinute {
		t.Errorf("a station endpoint built without a ttl lives %d ms, want 5 minutes", lived)
	}
	if alpn, _ := payloadField(r.Payload, "alpn").AsText(); alpn != "macula/1" {
		t.Errorf("alpn %q, want macula/1", alpn)
	}
	if _, present := r.Payload.Get("host_advertised"); present {
		t.Error("a station endpoint without hosts carries host_advertised")
	}
}

func TestNewStationEndpointRefusesPortZero(t *testing.T) {
	_, err := NewStationEndpoint(0, StationEndpointOptions{})
	wantRefusal(t, "a station endpoint on port 0", err, ErrInvalidPort)
}

// The reader takes host_advertised as macula_record's host_list/1 does: a list
// of hosts as bytes or text, or one host, and none when it is absent.
func TestReadStationEndpointReadsHostsAsMaculaDoes(t *testing.T) {
	for _, c := range []struct {
		name  string
		hosts cbor.Value
		want  []string
	}{
		{"a list of bytes and text", cbor.List([]cbor.Value{cbor.Bytes([]byte("a")), cbor.Text("b"), cbor.Uint64(1)}), []string{"a", "b"}},
		{"one host as bytes", cbor.Bytes([]byte("c")), []string{"c"}},
	} {
		r := Record{Type: TypeStationEndpoint, Payload: cbor.Map([]cbor.MapEntry{uintEntry("quic_port", 1), valueEntry("host_advertised", c.hosts)})}
		if endpoint := must[StationEndpoint](t)(ReadStationEndpoint(r)); endpoint.QUICPort != 1 || !slices.Equal(endpoint.HostAdvertised, c.want) {
			t.Errorf("%s reads port %d and hosts %q, want 1 and %q", c.name, endpoint.QUICPort, endpoint.HostAdvertised, c.want)
		}
	}
	if endpoint := must[StationEndpoint](t)(ReadStationEndpoint(Record{Type: TypeStationEndpoint, Payload: cbor.Map(nil)})); endpoint.QUICPort != 0 || endpoint.HostAdvertised != nil {
		t.Errorf("an empty payload reads port %d and hosts %q, want neither", endpoint.QUICPort, endpoint.HostAdvertised)
	}
	_, err := ReadStationEndpoint(Record{Type: TypeNodeRecord, Payload: cbor.Map(nil)})
	wantRefusal(t, "read a node record as a station endpoint", err, ErrMalformed)
}
