// Package transport dials a macula-station over raw QUIC (not HTTP/3 —
// see plans/PLAN_WIRE_PROTOCOL.md §1: despite the "HTTP/3 mesh"
// branding elsewhere, there is no h3 dependency anywhere in the
// reference implementation). ALPN is the single string "macula".
package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

// ALPN is the single protocol string a client MUST negotiate.
const ALPN = "macula"

// Trust selects how the QUIC/TLS layer verifies the peer's certificate —
// independent of, and in addition to, the application-layer CONNECT/
// HELLO signature check (frame.Verify), which runs regardless of Trust.
type Trust interface {
	tlsConfig(serverName string) *tls.Config
}

// WebPKI is standard CA-bundle + hostname validation, via the host
// system's certificate pool. The default since macula 5.0.0; matches
// what the live production fleet actually presents (§2's empirical
// note: macula-station-frankfurt presents a 3-certificate RSA chain,
// Let's-Encrypt-anchored, not a self-signed Ed25519 cert).
type WebPKI struct{}

func (WebPKI) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		NextProtos: []string{ALPN},
	}
}

// Pinned pins the server cert's Ed25519 SubjectPublicKeyInfo to an
// exact known key — used when the dialer already knows the peer's
// identity (DHT records, pre-shared relay identities), skipping CA/
// hostname validation entirely in favor of an exact key match.
type Pinned struct {
	NodeID []byte // 32-byte Ed25519 public key the peer's cert must present
}

func (p Pinned) tlsConfig(serverName string) *tls.Config {
	expected := ed25519.PublicKey(p.NodeID)
	return &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{ALPN},
		InsecureSkipVerify: true, // we do our own verification below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("transport: pinned verify: no certificate presented")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("transport: pinned verify: parse leaf cert: %w", err)
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("transport: pinned verify: leaf cert is not Ed25519")
			}
			if !pub.Equal(expected) {
				return fmt.Errorf("transport: pinned verify: leaf cert pubkey does not match the pinned NodeID")
			}
			return nil
		},
	}
}

// Insecure skips TLS verification entirely. Dev/lab only — logs nothing
// itself, but callers should.
type Insecure struct{}

func (Insecure) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{ALPN},
		InsecureSkipVerify: true,
	}
}

// quicConfig sets the same idle-timeout/keepalive shape the Erlang
// reference SDK uses (macula_quic.erl's own defaults: idle_timeout_ms
// 300_000, keep_alive_interval_ms 15_000 — "idle_timeout=300s tolerates
// short snapshot-RPC gaps without closing the conn; keep_alive=15s sends
// PING ~10x before any timeout could fire"). quic-go's own zero-value
// default (previously passed as a literal nil here) is a 30s idle
// timeout with NO keepalive at all — an idle-but-healthy connection
// (e.g. a pool link carrying a subscription with no recent traffic)
// would be torn down by quic-go itself well before anything at the
// application layer noticed, and a NATed path's mapping can silently
// expire in that same window with nothing to refresh it.
var quicConfig = &quic.Config{
	MaxIdleTimeout:  300_000 * time.Millisecond,
	KeepAlivePeriod: 15_000 * time.Millisecond,
}

// Dial establishes a raw QUIC connection to host:port with ALPN
// "macula" and the given trust mode.
//
// host is joined with port via net.JoinHostPort, not a bare "%s:%d"
// format — a bare IPv6 literal (e.g. a station_endpoint record's
// host_advertised, which macula-station may publish as one) needs
// bracketing ("[::1]:4433") or the result is ambiguous/unparseable, since
// the address itself is full of colons. JoinHostPort brackets only when
// host contains a colon, so hostnames and IPv4 literals are unaffected.
func Dial(ctx context.Context, host string, port uint16, trust Trust) (*quic.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	tlsConf := trust.tlsConfig(host)
	conn, err := quic.DialAddr(ctx, addr, tlsConf, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	return conn, nil
}
