package record

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// stationEndpointVectors is macula's test/vectors/station_endpoint_v1.json
// (macula 5370915f, sha256 ebae3fa7275370579c2f042ee1b744efb701bcb71429312c638055fc720c1b3a),
// copied into testdata by scripts/interop/copy_station_endpoint_vectors.sh:
// signed station endpoints, five per profile, and what macula_record's
// read_station_endpoint/1 reads from each. station_version is null where the
// reader returns no release. Signing is randomized, so the committed file is
// the vector.
type stationEndpointVectors struct {
	Profiles map[string]struct {
		Cases []stationEndpointCase `json:"cases"`
	} `json:"profiles"`
}

// stationEndpointCase is one signed station endpoint and what macula's reader
// reads from it.
type stationEndpointCase struct {
	Name           string   `json:"name"`
	NowMs          int64    `json:"now_ms"`
	Record         string   `json:"record"`
	QUICPort       uint16   `json:"quic_port"`
	HostAdvertised []string `json:"host_advertised"`
	StationVersion *string  `json:"station_version"`
}

// TestStationEndpointVectors holds ReadStationEndpoint to macula's reader: the
// release a station names as text of 1 to 64 bytes reads back, and none, bytes,
// empty text or text past 64 bytes read as no release.
func TestStationEndpointVectors(t *testing.T) {
	vectors := readStationEndpointVectors(t)
	cases := 0
	for name, p := range vectors.Profiles {
		for _, c := range p.Cases {
			cases++
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				checkStationEndpoint(t, profile.Profile(name), c)
			})
		}
	}
	if cases != 10 {
		t.Errorf("%d vector cases, want 10 (five per profile)", cases)
	}
}

func readStationEndpointVectors(t *testing.T) stationEndpointVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "station_endpoint_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors stationEndpointVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

// checkStationEndpoint holds ReadStationEndpoint to macula's reader on one
// vector: no release where the case names none.
func checkStationEndpoint(t *testing.T, p profile.Profile, c stationEndpointCase) {
	t.Helper()
	wire, err := hex.DecodeString(c.Record)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(wire, p, c.NowMs)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	endpoint, err := ReadStationEndpoint(verified.Record())
	if err != nil {
		t.Fatalf("ReadStationEndpoint: %v", err)
	}
	if endpoint.QUICPort != c.QUICPort || !slices.Equal(endpoint.HostAdvertised, c.HostAdvertised) {
		t.Errorf("read port %d and hosts %q, want %d and %q", endpoint.QUICPort, endpoint.HostAdvertised, c.QUICPort, c.HostAdvertised)
	}
	want := ""
	if c.StationVersion != nil {
		want = *c.StationVersion
	}
	if endpoint.StationVersion != want {
		t.Errorf("read station_version %q, want %q", endpoint.StationVersion, want)
	}
}
