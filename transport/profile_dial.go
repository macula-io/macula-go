package transport

import (
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/profile"
)

// Target is a station to dial under a crypto profile: where it listens, the
// profile of its realm, and the node_id it must prove in the connection
// handshake. A dial has no default profile, and none goes without an expected
// node_id.
type Target struct {
	Host           string
	Port           uint16
	Profile        profile.Profile
	ExpectedNodeID [32]byte
}

// Dialed is a QUIC connection to a station whose TLS handshake passed its
// profile's checks, with the station's leaf certificate DER exactly as it
// arrived, which the connection handshake's binding and proof hash.
type Dialed struct {
	Conn   *quic.Conn
	Leaf   []byte
	Target Target
}

// The refusals of DialTarget: a target it will not dial, and a TLS handshake
// that does not follow the target's profile.
var (
	// ErrNoExpectedNodeID is a target whose expected node_id is the zero
	// value, which names no station.
	ErrNoExpectedNodeID = errors.New("transport: the dial target names no expected node_id")
	// ErrWrongKeyExchangeGroup is a TLS handshake that settled on a key
	// exchange group other than the profile's.
	ErrWrongKeyExchangeGroup = errors.New("transport: the TLS handshake used another key exchange group")
	// ErrWrongCipherSuite is a TLS handshake that settled on a cipher suite
	// other than the profile's TLS_AES_256_GCM_SHA384.
	ErrWrongCipherSuite = errors.New("transport: the TLS handshake used another cipher suite")
	// ErrStationCertificate is a station that presented anything but exactly
	// one certificate, with an ML-DSA-87 key.
	ErrStationCertificate = errors.New("transport: the station did not present one ML-DSA-87 certificate")
)

// DialTarget dials target over QUIC with the TLS 1.3 settings of its profile,
// the one way a post-quantum station is dialed. The client offers only the
// profile's key exchange group and keeps no session cache, so every
// connection is a full handshake with a certificate and no early data. It
// checks no chain, name, CA or expiry, since station certificates are
// self-signed; crypto/tls still verifies the handshake signature against the
// leaf. Before the connection is used, DialTarget refuses a handshake on
// another group or cipher suite, and a station that presents anything but one
// ML-DSA-87 leaf.
//
// A target without an expected node_id, or without a known profile, is refused
// before anything is dialed. DialTarget does not compare the node_id: the
// connection handshake does, against the station's identity key and the leaf
// this dial returns.
func DialTarget(ctx context.Context, target Target) (Dialed, error) {
	definition, err := dialable(target)
	if err != nil {
		return Dialed{}, err
	}
	addr := net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port)))
	refused := make(chan error, 1)
	conn, err := quic.DialAddr(ctx, addr, profileTLSConfig(target.Host, definition, refused), quicConfig)
	if err != nil {
		select {
		case refusal := <-refused:
			return Dialed{}, fmt.Errorf("transport: dial %s: %w", addr, refusal)
		default:
			return Dialed{}, fmt.Errorf("transport: dial %s: %w", addr, err)
		}
	}
	leaf := conn.ConnectionState().TLS.PeerCertificates[0].Raw
	return Dialed{Conn: conn, Leaf: leaf, Target: target}, nil
}

// dialable is the definition of target's profile, when target names a known
// profile and an expected node_id.
func dialable(target Target) (profile.Definition, error) {
	p, err := profile.Parse(string(target.Profile))
	if err != nil {
		return profile.Definition{}, err
	}
	if target.ExpectedNodeID == [32]byte{} {
		return profile.Definition{}, ErrNoExpectedNodeID
	}
	return p.Definition()
}

// profileTLSConfig is a profile's TLS 1.3 client configuration. Its
// VerifyConnection refuses a handshake that does not follow the profile, and
// hands the refusal to refused, so the dial can return it whatever error the
// QUIC layer wraps it in.
func profileTLSConfig(serverName string, definition profile.Definition, refused chan<- error) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{ALPN},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{definition.KeyExchangeGroup},
		InsecureSkipVerify: true, // self-signed station certificates: VerifyConnection checks the profile instead
		VerifyConnection: func(state tls.ConnectionState) error {
			err := checkProfileConnection(state, definition)
			if err != nil {
				select {
				case refused <- err:
				default:
				}
			}
			return err
		},
	}
}

// checkProfileConnection refuses a TLS handshake that settled on a group or
// cipher suite other than the profile's, or whose station presented anything
// but exactly one certificate with an ML-DSA-87 key.
func checkProfileConnection(state tls.ConnectionState, definition profile.Definition) error {
	switch {
	case state.CurveID != definition.KeyExchangeGroup:
		return fmt.Errorf("%w: %s", ErrWrongKeyExchangeGroup, state.CurveID)
	case state.CipherSuite != definition.TLSCipherSuite:
		return fmt.Errorf("%w: %s", ErrWrongCipherSuite, tls.CipherSuiteName(state.CipherSuite))
	case len(state.PeerCertificates) != 1 || !isMLDSA87(state.PeerCertificates[0].PublicKey):
		return ErrStationCertificate
	}
	return nil
}

// isMLDSA87 reports whether key is an ML-DSA-87 public key.
func isMLDSA87(key any) bool {
	public, ok := key.(*mldsa.PublicKey)
	return ok && public.Parameters().String() == mldsa.MLDSA87().String()
}
