package transport

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/profile"
)

// stationSpec is how a test station's TLS behaves.
type stationSpec struct {
	groups []tls.CurveID
	key    crypto.Signer
	// aes256 narrows the client's offered TLS 1.3 suites to
	// TLS_AES_256_GCM_SHA384 before the station picks one. A Go TLS 1.3
	// station otherwise picks TLS_AES_128_GCM_SHA256, and macula's stations
	// offer only the AES-256 suite. It works because crypto/tls (Go 1.27)
	// hands GetConfigForClient the client hello's own suite list, picks the
	// suite from it afterwards, and hashes the hello as it arrived. Were that
	// to change, the station would pick AES-128 and the success tests would
	// fail, not pass.
	aes256 bool
	// chain presents the leaf twice, as a two-certificate chain.
	chain bool
}

// testStation is a station in a test: a QUIC listener on loopback, and the
// leaf certificate DER it presents.
type testStation struct {
	host string
	port uint16
	leaf []byte
}

func mldsa87Key(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("ML-DSA-87 key: %v", err)
	}
	return key
}

func selfSigned(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "station"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("self-signed certificate: %v", err)
	}
	return der
}

func startStation(t *testing.T, spec stationSpec) testStation {
	t.Helper()
	leaf := selfSigned(t, spec.key)
	certificate := tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: spec.key}
	if spec.chain {
		certificate.Certificate = append(certificate.Certificate, leaf)
	}
	config := &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		CurvePreferences: spec.groups,
		MinVersion:       tls.VersionTLS13,
		NextProtos:       []string{ALPN},
	}
	if spec.aes256 {
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			for i := range hello.CipherSuites {
				hello.CipherSuites[i] = tls.TLS_AES_256_GCM_SHA384
			}
			return nil, nil
		}
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", config, &quic.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})
	go func() {
		for {
			if _, err := listener.Accept(ctx); err != nil {
				return
			}
		}
	}()
	addr := listener.Addr().(*net.UDPAddr)
	return testStation{host: "127.0.0.1", port: uint16(addr.Port), leaf: leaf}
}

func targetFor(s testStation, p profile.Profile) Target {
	return Target{Host: s.host, Port: s.port, Profile: p, ExpectedNodeID: [32]byte{1}}
}

func dialWithin(t *testing.T, target Target) (Dialed, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialed, err := DialTarget(ctx, target)
	if err == nil {
		t.Cleanup(func() { _ = dialed.Conn.CloseWithError(0, "test done") })
	}
	return dialed, err
}

// A profile dial reaches a station of its profile over the profile's group and
// the AES-256 suite, and returns the leaf DER exactly as the station presented
// it. No connection resumes a session or sends early data.
func TestDialTargetReachesAStationOfItsProfile(t *testing.T) {
	profiles := map[profile.Profile]tls.CurveID{
		profile.PQPure:   tls.MLKEM1024,
		profile.PQHybrid: tls.SecP384r1MLKEM1024,
	}
	for p, group := range profiles {
		t.Run(string(p), func(t *testing.T) {
			station := startStation(t, stationSpec{groups: []tls.CurveID{group}, key: mldsa87Key(t), aes256: true})
			for dial := range 2 {
				dialed, err := dialWithin(t, targetFor(station, p))
				if err != nil {
					t.Fatalf("dial %d: %v", dial+1, err)
				}
				state := dialed.Conn.ConnectionState()
				if state.TLS.CurveID != group || state.TLS.CipherSuite != tls.TLS_AES_256_GCM_SHA384 {
					t.Errorf("dial %d settled on %s and %s", dial+1, state.TLS.CurveID, tls.CipherSuiteName(state.TLS.CipherSuite))
				}
				if !bytes.Equal(dialed.Leaf, station.leaf) {
					t.Errorf("dial %d: the leaf differs from the DER the station presented", dial+1)
				}
				if state.TLS.DidResume || state.Used0RTT {
					t.Errorf("dial %d resumed %t, used early data %t; want a full handshake", dial+1, state.TLS.DidResume, state.Used0RTT)
				}
			}
		})
	}
}

// A profile dial refuses a station that does not follow the profile: another
// group, a suite other than AES-256, a leaf that is not ML-DSA-87, or more than
// one certificate.
func TestDialTargetRefusesAStationThatDoesNotFollowTheProfile(t *testing.T) {
	pure := []tls.CurveID{tls.MLKEM1024}
	cases := []struct {
		name string
		spec func(t *testing.T) stationSpec
		want error
	}{
		{"a pq_hybrid station", func(t *testing.T) stationSpec {
			return stationSpec{groups: []tls.CurveID{tls.SecP384r1MLKEM1024}, key: mldsa87Key(t), aes256: true}
		}, nil},
		{"a classical X25519 station", func(t *testing.T) stationSpec {
			return stationSpec{groups: []tls.CurveID{tls.X25519}, key: mldsa87Key(t), aes256: true}
		}, nil},
		{"an X25519MLKEM768 station", func(t *testing.T) stationSpec {
			return stationSpec{groups: []tls.CurveID{tls.X25519MLKEM768}, key: mldsa87Key(t), aes256: true}
		}, nil},
		{"a station that picks AES-128", func(t *testing.T) stationSpec {
			return stationSpec{groups: pure, key: mldsa87Key(t)}
		}, ErrWrongCipherSuite},
		{"a station with an ECDSA P-384 leaf", func(t *testing.T) stationSpec {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatalf("ECDSA key: %v", err)
			}
			return stationSpec{groups: pure, key: key, aes256: true}
		}, ErrStationCertificate},
		{"a station that presents two certificates", func(t *testing.T) stationSpec {
			return stationSpec{groups: pure, key: mldsa87Key(t), aes256: true, chain: true}
		}, ErrStationCertificate},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			station := startStation(t, c.spec(t))
			_, err := dialWithin(t, targetFor(station, profile.PQPure))
			if err == nil {
				t.Fatal("the pq_pure dial succeeded, want it refused")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("the pq_pure dial: %v, want %v", err, c.want)
			}
		})
	}
}

// A target without an expected node_id or a known profile is refused before
// anything is dialed.
func TestDialTargetRefusesATargetItCannotCheck(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1: a dial there would wait for the context, not
	// return one of these errors.
	address := Target{Host: "192.0.2.1", Port: 4433}
	cases := []struct {
		name   string
		target Target
		want   error
	}{
		{"no expected node_id", Target{Host: address.Host, Port: address.Port, Profile: profile.PQPure}, ErrNoExpectedNodeID},
		{"no profile", Target{Host: address.Host, Port: address.Port, ExpectedNodeID: [32]byte{1}}, profile.ErrMissing},
		{"an unknown profile", Target{Host: address.Host, Port: address.Port, Profile: "classical", ExpectedNodeID: [32]byte{1}}, profile.ErrUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			started := time.Now()
			if _, err := DialTarget(ctx, c.target); !errors.Is(err, c.want) {
				t.Fatalf("DialTarget = %v, want %v", err, c.want)
			}
			if waited := time.Since(started); waited > 500*time.Millisecond {
				t.Fatalf("DialTarget returned after %s, want it refused before dialing", waited)
			}
		})
	}
}

// The handshake check refuses each way a TLS connection can differ from the
// profile, and accepts the one that follows it.
func TestCheckProfileConnection(t *testing.T) {
	definition, err := profile.PQPure.Definition()
	if err != nil {
		t.Fatalf("definition: %v", err)
	}
	certificate := func(key crypto.Signer) *x509.Certificate {
		parsed, err := x509.ParseCertificate(selfSigned(t, key))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return parsed
	}
	leaf := certificate(mldsa87Key(t))
	mldsa65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("ML-DSA-65 key: %v", err)
	}
	following := tls.ConnectionState{CurveID: tls.MLKEM1024, CipherSuite: tls.TLS_AES_256_GCM_SHA384, PeerCertificates: []*x509.Certificate{leaf}}
	cases := []struct {
		name  string
		state func() tls.ConnectionState
		want  error
	}{
		{"the profile's own", func() tls.ConnectionState { return following }, nil},
		{"another group", func() tls.ConnectionState { s := following; s.CurveID = tls.SecP384r1MLKEM1024; return s }, ErrWrongKeyExchangeGroup},
		{"another suite", func() tls.ConnectionState { s := following; s.CipherSuite = tls.TLS_AES_128_GCM_SHA256; return s }, ErrWrongCipherSuite},
		{"no certificate", func() tls.ConnectionState { s := following; s.PeerCertificates = nil; return s }, ErrStationCertificate},
		{"two certificates", func() tls.ConnectionState {
			s := following
			s.PeerCertificates = []*x509.Certificate{leaf, leaf}
			return s
		}, ErrStationCertificate},
		{"an ML-DSA-65 leaf", func() tls.ConnectionState {
			s := following
			s.PeerCertificates = []*x509.Certificate{certificate(mldsa65)}
			return s
		}, ErrStationCertificate},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := checkProfileConnection(c.state(), definition); !errors.Is(err, c.want) {
				t.Fatalf("checkProfileConnection = %v, want %v", err, c.want)
			}
		})
	}
}
