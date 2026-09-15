package record

import (
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
)

// ErrInvalidPort is a station endpoint's QUIC port of 0.
var ErrInvalidPort = errors.New("record: a QUIC port outside 1 to 65535")

// StationEndpointOptions are a station endpoint's optional fields, as
// macula_record's station_endpoint/2 takes them: the hosts it is dialled at,
// which travel as byte strings and are left out when there are none, and its
// ALPN, left out when empty. TTLMs is 0 for the default and maximum, 5 minutes.
type StationEndpointOptions struct {
	HostAdvertised []string
	ALPN           string
	TTLMs          uint64
}

// NewStationEndpoint is an unsigned record of a station's dialable endpoint,
// signed by the station and stored under its node_id's station endpoint key. A
// QUIC port of 0 is ErrInvalidPort.
func NewStationEndpoint(quicPort uint16, opts StationEndpointOptions) (Record, error) {
	if quicPort == 0 {
		return Record{}, ErrInvalidPort
	}
	entries := []cbor.MapEntry{uintEntry("quic_port", uint64(quicPort))}
	if len(opts.HostAdvertised) > 0 {
		hosts := make([]cbor.Value, len(opts.HostAdvertised))
		for i, host := range opts.HostAdvertised {
			hosts[i] = cbor.Bytes([]byte(host))
		}
		entries = append(entries, valueEntry("host_advertised", cbor.List(hosts)))
	}
	if opts.ALPN != "" {
		entries = append(entries, textEntry("alpn", opts.ALPN))
	}
	return unsigned(TypeStationEndpoint, cbor.Map(entries), opts.TTLMs)
}

// StationEndpoint is a station endpoint's payload, as macula_record's
// read_station_endpoint/1 reads it: its QUIC port, 0 when the payload carries
// none from 1 to 65535, and the hosts it is dialled at.
type StationEndpoint struct {
	QUICPort       uint16
	HostAdvertised []string
}

// ReadStationEndpoint reads a station endpoint's payload. A record of another
// type is ErrMalformed.
func ReadStationEndpoint(r Record) (StationEndpoint, error) {
	if r.Type != TypeStationEndpoint {
		return StationEndpoint{}, fmt.Errorf("%w: a record of type %#02x is not a station endpoint", ErrMalformed, uint8(r.Type))
	}
	endpoint := StationEndpoint{HostAdvertised: hostList(payloadField(r.Payload, "host_advertised"))}
	if port, isInt := payloadField(r.Payload, "quic_port").AsInt64(); isInt && port >= 1 && port <= 65535 {
		endpoint.QUICPort = uint16(port)
	}
	return endpoint, nil
}

// hostList reads host_advertised as macula_record's host_list/1 does: a list of
// hosts or a single host, each as bytes or text, and none when it is absent. An
// item of another kind is left out.
func hostList(v cbor.Value) []string {
	items, isList := v.AsList()
	if !isList {
		items = []cbor.Value{v}
	}
	var hosts []string
	for _, item := range items {
		if b, isBytes := item.AsBytes(); isBytes {
			hosts = append(hosts, string(b))
			continue
		}
		if s, isText := item.AsText(); isText {
			hosts = append(hosts, s)
		}
	}
	return hosts
}
