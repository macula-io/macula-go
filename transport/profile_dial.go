package transport

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/identity"
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
// profile's checks, with the caller's own copy of the station's leaf
// certificate DER exactly as it arrived, which the connection handshake's
// binding and proof hash.
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
	// ErrStationCertificate is a station that presented anything but exactly
	// one certificate, with a key of the profile's TLS signature scheme
	// (ML-DSA-87 in both profiles).
	ErrStationCertificate = errors.New("transport: the station did not present one certificate with a key of the profile's signature scheme")
)

// DialTarget dials target over QUIC with the TLS 1.3 settings of its profile,
// the one way a post-quantum station is dialed. The client offers only the
// profile's key exchange group and macula's ALPN protocol, and keeps no session
// cache, so every connection is a full handshake with a certificate and no
// early data. It checks no chain, name, CA or expiry, since station
// certificates are self-signed. Before the connection is used, DialTarget
// refuses a handshake on another group or cipher suite, a station that presents
// anything but one leaf with a key of the profile's signature scheme, and a
// station that selects no ALPN protocol or another one.
//
// Those checks see the leaf before the station has shown that it holds the
// leaf's key. What shows it is the completed handshake: crypto/tls verifies the
// station's CertificateVerify signature against the leaf, and DialTarget
// returns a connection only once its handshake has completed.
//
// A target without an expected node_id, or without a known profile, is refused
// before anything is dialed, and so is every target in a binary built with
// GOFIPS140=v1.0.0, which has no ML-DSA (identity.ErrPostQuantumUnavailable).
// DialTarget does not compare the node_id: the connection handshake does,
// against the station's identity key and the leaf this dial returns.
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
	// crypto/tls shares one parsed certificate among the connections that
	// received the same bytes, so the caller gets a copy of the leaf.
	leaf := bytes.Clone(conn.ConnectionState().TLS.PeerCertificates[0].Raw)
	return Dialed{Conn: conn, Leaf: leaf, Target: target}, nil
}

// dialable is the definition of target's profile, when this binary has ML-DSA
// and target names a known profile and an expected node_id.
func dialable(target Target) (profile.Definition, error) {
	if err := identity.CheckPostQuantum(); err != nil {
		return profile.Definition{}, err
	}
	p, err := profile.Parse(string(target.Profile))
	if err != nil {
		return profile.Definition{}, err
	}
	if target.ExpectedNodeID == [32]byte{} {
		return profile.Definition{}, ErrNoExpectedNodeID
	}
	return p.Definition()
}

// KeyExchangeGroups are the TLS key exchange groups a dial offers and accepts,
// in order: macula-pqc's, the crate every macula 12 station builds its TLS
// from, whatever a node's profile. Nothing classical. A profile's own group is
// a declared target in macula and not what a connection negotiates.
var KeyExchangeGroups = []tls.CurveID{tls.SecP384r1MLKEM1024, tls.SecP256r1MLKEM768}

// profileTLSConfig is a profile's TLS 1.3 client configuration. It holds no
// session cache and disables session tickets, so no connection resumes, and
// offers only macula's ALPN protocol, which crypto/tls requires a QUIC server
// to select. Its VerifyConnection refuses a handshake that does not follow the
// profile, and hands the refusal to refused, so the dial can return it
// whatever error the QUIC layer wraps it in.
func profileTLSConfig(serverName string, definition profile.Definition, refused chan<- error) *tls.Config {
	return &tls.Config{
		ServerName:             serverName,
		NextProtos:             []string{ALPN},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       slices.Clone(KeyExchangeGroups),
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     true, // self-signed station certificates: VerifyConnection checks the profile instead
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

// checkProfileConnection refuses a TLS handshake that settled on a group
// outside KeyExchangeGroups, or whose station presented anything but exactly
// one certificate with a key of the profile's TLS signature scheme. The TLS 1.3
// cipher suite is not checked: macula's stations take rustls' default suites
// and pin none, and Go orders its client's suites itself.
func checkProfileConnection(state tls.ConnectionState, definition profile.Definition) error {
	switch {
	case !slices.Contains(KeyExchangeGroups, state.CurveID):
		return fmt.Errorf("%w: %s", ErrWrongKeyExchangeGroup, state.CurveID)
	case len(state.PeerCertificates) != 1 || !keyOfScheme(state.PeerCertificates[0].PublicKey, definition.TLSSignatureScheme):
		return ErrStationCertificate
	}
	return nil
}

// mldsaSchemes are the ML-DSA parameter sets of the TLS signature schemes.
var mldsaSchemes = map[tls.SignatureScheme]mldsa.Parameters{
	tls.MLDSA44: mldsa.MLDSA44(),
	tls.MLDSA65: mldsa.MLDSA65(),
	tls.MLDSA87: mldsa.MLDSA87(),
}

// keyOfScheme reports whether key is a public key of the TLS signature scheme.
func keyOfScheme(key any, scheme tls.SignatureScheme) bool {
	public, isMLDSA := key.(*mldsa.PublicKey)
	parameters, known := mldsaSchemes[scheme]
	return isMLDSA && known && public.Parameters() == parameters
}
