package transport

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/profile"
)

// stationSpec is how a test station's TLS behaves.
type stationSpec struct {
	groups []tls.CurveID
	key    crypto.Signer
	// signer signs the station's handshake in place of key, when set: the leaf
	// holds key, and CertificateVerify is made with signer.
	signer crypto.Signer
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
	// protocols are the ALPN protocols the station accepts, macula's alone
	// when empty.
	protocols []string
	// noProtocol makes the station select no ALPN protocol.
	noProtocol bool
	// selects is an ALPN protocol the station selects whatever the client
	// offered, when set. The station writes it over the client's offered
	// protocols before crypto/tls negotiates, which works for the reason
	// aes256 does.
	selects string
}

// testStation is a station in a test: a QUIC listener on loopback, and the
// leaf certificate DER it presents.
type testStation struct {
	host string
	port uint16
	leaf []byte
}

// The TLS alerts a dialing client refuses a station's handshake with, and the
// base a TLS alert is added to as a QUIC transport error code (RFC 9001,
// section 4.8).
const (
	cryptoErrorBase            = 0x100
	alertDecryptError          = 51
	alertNoApplicationProtocol = 120
)

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
	if spec.signer != nil {
		certificate.PrivateKey = spec.signer
	}
	if spec.chain {
		certificate.Certificate = append(certificate.Certificate, leaf)
	}
	config := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		CurvePreferences:   spec.groups,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         stationProtocols(spec),
		GetConfigForClient: rewriteHello(spec),
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

// stationProtocols are the ALPN protocols a station's configuration accepts.
func stationProtocols(spec stationSpec) []string {
	switch {
	case spec.noProtocol:
		return nil
	case spec.selects != "":
		return []string{spec.selects}
	case len(spec.protocols) > 0:
		return spec.protocols
	}
	return []string{ALPN}
}

// rewriteHello is a station's GetConfigForClient when its spec changes the
// client hello crypto/tls negotiates from: the offered suites narrowed to
// AES-256, and the offered protocols replaced by the one the station selects.
func rewriteHello(spec stationSpec) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	if !spec.aes256 && spec.selects == "" {
		return nil
	}
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if spec.aes256 {
			fill(hello.CipherSuites, tls.TLS_AES_256_GCM_SHA384)
		}
		if spec.selects != "" {
			fill(hello.SupportedProtos, spec.selects)
		}
		return nil, nil
	}
}

func fill[T any](s []T, v T) {
	for i := range s {
		s[i] = v
	}
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

// checkClientRefused checks that a dial failed because the client's TLS refused
// the station's handshake with alert, and not because the station closed the
// connection.
func checkClientRefused(t *testing.T, err error, alert quic.TransportErrorCode) {
	t.Helper()
	var transportErr *quic.TransportError
	switch {
	case err == nil:
		t.Fatal("the dial succeeded, want the client to refuse it")
	case !errors.As(err, &transportErr):
		t.Fatalf("the dial: %v, want a QUIC transport error", err)
	case transportErr.Remote || transportErr.ErrorCode != cryptoErrorBase+alert:
		t.Fatalf("the dial: %v (remote %t, code %#x), want the client's own refusal with code %#x",
			err, transportErr.Remote, uint64(transportErr.ErrorCode), uint64(cryptoErrorBase+alert))
	}
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

// The leaf a profile dial returns is its caller's own. crypto/tls shares one
// parsed certificate among the connections that received the same bytes, so a
// caller writing into one dial's leaf must not reach another dial's.
func TestDialTargetReturnsALeafItsCallerOwns(t *testing.T) {
	station := startStation(t, stationSpec{groups: []tls.CurveID{tls.MLKEM1024}, key: mldsa87Key(t), aes256: true})
	first, err := dialWithin(t, targetFor(station, profile.PQPure))
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	clear(first.Leaf)
	second, err := dialWithin(t, targetFor(station, profile.PQPure))
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	if !bytes.Equal(second.Leaf, station.leaf) {
		t.Error("the second dial's leaf changed when the first dial's leaf was written, want each dial's leaf its own")
	}
}

// A profile dial refuses a station that does not follow the profile: another
// group, a suite other than AES-256, a leaf that is not ML-DSA-87, or more than
// one certificate. A station that accepts only another ALPN protocol refuses
// the dial itself.
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
		{"a station with an ML-DSA-65 leaf", func(t *testing.T) stationSpec {
			key, err := mldsa.GenerateKey(mldsa.MLDSA65())
			if err != nil {
				t.Fatalf("ML-DSA-65 key: %v", err)
			}
			return stationSpec{groups: pure, key: key, aes256: true}
		}, ErrStationCertificate},
		{"a station that presents two certificates", func(t *testing.T) stationSpec {
			return stationSpec{groups: pure, key: mldsa87Key(t), aes256: true, chain: true}
		}, ErrStationCertificate},
		{"a station with an Ed25519 leaf", func(t *testing.T) stationSpec {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("Ed25519 key: %v", err)
			}
			return stationSpec{groups: pure, key: key, aes256: true}
		}, ErrStationCertificate},
		{"a station that accepts only another ALPN protocol", func(t *testing.T) stationSpec {
			return stationSpec{groups: pure, key: mldsa87Key(t), aes256: true, protocols: []string{"not-macula"}}
		}, nil},
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

// A profile dial refuses a station whose leaf holds one ML-DSA-87 key while its
// handshake is signed with another. The leaf follows the profile, so the
// refusal is crypto/tls checking CertificateVerify against that leaf. The
// connection handshake binds the node_id to this leaf, and relies on that
// check.
func TestDialTargetRefusesAStationWhoseHandshakeIsSignedByAnotherKey(t *testing.T) {
	station := startStation(t, stationSpec{groups: []tls.CurveID{tls.MLKEM1024}, key: mldsa87Key(t), signer: mldsa87Key(t), aes256: true})
	_, err := dialWithin(t, targetFor(station, profile.PQPure))
	checkClientRefused(t, err, alertDecryptError)
}

// A profile dial refuses a station that selects no ALPN protocol, or one the
// client never offered. The refusal is the client's own: crypto/tls on a QUIC
// client requires the station to select one of the protocols it offered.
func TestDialTargetRefusesAStationThatSelectsNoOrAnotherALPNProtocol(t *testing.T) {
	cases := []struct {
		name string
		spec stationSpec
	}{
		{"a station that selects no protocol", stationSpec{noProtocol: true}},
		{"a station that selects a protocol the client never offered", stationSpec{selects: "not-macula"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := c.spec
			spec.groups, spec.key, spec.aes256 = []tls.CurveID{tls.MLKEM1024}, mldsa87Key(t), true
			station := startStation(t, spec)
			_, err := dialWithin(t, targetFor(station, profile.PQPure))
			checkClientRefused(t, err, alertNoApplicationProtocol)
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

// A profile dial's TLS configuration, per profile: TLS 1.3 alone, the profile's
// group alone, macula's ALPN protocol alone, no session tickets and no session
// cache, and the station's leaf checked in VerifyConnection, which crypto/tls
// runs on every handshake, not in VerifyPeerCertificate. No chain is checked
// and no roots are set, so VerifyConnection is the only way a station is
// accepted.
func TestProfileTLSConfigFollowsTheProfile(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) {
			definition, err := p.Definition()
			if err != nil {
				t.Fatalf("definition: %v", err)
			}
			config := profileTLSConfig("station.test", definition, make(chan error, 1))
			if config.ServerName != "station.test" {
				t.Errorf("ServerName %q, want the target's host", config.ServerName)
			}
			if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 {
				t.Errorf("versions %#x to %#x, want TLS 1.3 alone", config.MinVersion, config.MaxVersion)
			}
			if !slices.Equal(config.CurvePreferences, []tls.CurveID{definition.KeyExchangeGroup}) {
				t.Errorf("groups %v, want %s alone", config.CurvePreferences, definition.KeyExchangeGroup)
			}
			if !slices.Equal(config.NextProtos, []string{ALPN}) {
				t.Errorf("ALPN protocols %q, want %q alone", config.NextProtos, ALPN)
			}
			if !config.SessionTicketsDisabled || config.ClientSessionCache != nil {
				t.Errorf("session tickets disabled %t, session cache %v, want tickets disabled and no cache",
					config.SessionTicketsDisabled, config.ClientSessionCache)
			}
			if config.VerifyPeerCertificate != nil || config.VerifyConnection == nil {
				t.Errorf("VerifyPeerCertificate set %t, VerifyConnection set %t, want VerifyConnection alone",
					config.VerifyPeerCertificate != nil, config.VerifyConnection != nil)
			}
			if !config.InsecureSkipVerify || config.RootCAs != nil {
				t.Errorf("InsecureSkipVerify %t, RootCAs set %t, want no chain check and no roots",
					config.InsecureSkipVerify, config.RootCAs != nil)
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

// keyOfScheme accepts a key only for a TLS signature scheme it maps to ML-DSA
// parameters, and only a key of those parameters. For any other scheme it
// refuses every key.
func TestKeyOfSchemeAcceptsOnlyAKeyOfAMappedScheme(t *testing.T) {
	key := mldsa87Key(t).Public()
	cases := []struct {
		name   string
		key    any
		scheme tls.SignatureScheme
		want   bool
	}{
		{"an ML-DSA-87 key for ML-DSA-87", key, tls.MLDSA87, true},
		{"an ML-DSA-87 key for ML-DSA-65", key, tls.MLDSA65, false},
		{"an ML-DSA-87 key for Ed25519, a scheme with no ML-DSA parameters", key, tls.Ed25519, false},
		{"an ML-DSA-87 key for a scheme TLS does not define", key, tls.SignatureScheme(0xfefe), false},
		{"no key for ML-DSA-87", nil, tls.MLDSA87, false},
	}
	for _, c := range cases {
		if got := keyOfScheme(c.key, c.scheme); got != c.want {
			t.Errorf("%s: %t, want %t", c.name, got, c.want)
		}
	}
}
