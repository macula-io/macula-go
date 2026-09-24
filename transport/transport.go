// Package transport dials a macula 12 station over raw QUIC with the ALPN
// "macula" and macula-pqc's post-quantum key exchange, as DialTarget does. The
// TLS layer checks only that the peer holds the key of its self-signed ML-DSA-87
// certificate; the v4 handshake that follows proves the peer is the node the
// Target pins.
package transport

// ALPN is the single protocol string a client MUST negotiate.
const ALPN = "macula"
