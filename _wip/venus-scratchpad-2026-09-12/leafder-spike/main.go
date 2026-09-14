// Spike: after macula-go's own transport.Dial returns (the exact call
// connection.connectOne makes at connection.go:104, before CONNECT is
// sent), is the station's leaf certificate readable as the raw DER bytes
// the server actually sent? Local QUIC server, no fleet.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/macula-io/macula-go/transport"
	"github.com/quic-go/quic-go"
)

func selfSigned(name string, pub crypto.PublicKey, priv crypto.Signer) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spike-" + name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
}

func run(name string, pub crypto.PublicKey, priv crypto.Signer) bool {
	der, err := selfSigned(name, pub, priv)
	if err != nil {
		fmt.Printf("[%s] FAIL create certificate: %v\n", name, err)
		return false
	}
	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		NextProtos:   []string{transport.ALPN},
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", srvTLS, nil)
	if err != nil {
		fmt.Printf("[%s] FAIL listen: %v\n", name, err)
		return false
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(context.Background()); err == nil {
			time.Sleep(3 * time.Second)
			_ = c
		}
	}()
	port := uint16(ln.Addr().(*net.UDPAddr).Port)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := transport.Dial(ctx, "127.0.0.1", port, transport.Insecure{})
	if err != nil {
		fmt.Printf("[%s] FAIL transport.Dial: %v\n", name, err)
		return false
	}
	defer conn.CloseWithError(0, "spike done")

	handshakeDone := false
	select {
	case <-conn.HandshakeComplete():
		handshakeDone = true
	default:
	}
	cs := conn.ConnectionState().TLS
	if len(cs.PeerCertificates) == 0 {
		fmt.Printf("[%s] FAIL no peer certificates in ConnectionState\n", name)
		return false
	}
	raw := cs.PeerCertificates[0].Raw
	same := bytes.Equal(raw, der)
	sum := sha512.Sum384(raw)
	fmt.Printf("[%s] handshake already complete when transport.Dial returned: %v\n", name, handshakeDone)
	fmt.Printf("[%s] leaf certificate %d bytes, byte-identical to the DER the server sent: %v\n", name, len(raw), same)
	fmt.Printf("[%s] SHA-384 of leaf (first 8 bytes): %x\n", name, sum[:8])
	fmt.Printf("[%s] TLS version %#x, key exchange group %v, peer cert key %T\n", name, cs.Version, cs.CurveID, cs.PeerCertificates[0].PublicKey)
	return handshakeDone && same
}

func main() {
	ok := true
	epub, epriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("ed25519 keygen:", err)
		os.Exit(2)
	}
	ok = run("ed25519", epub, epriv) && ok
	mk, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		fmt.Println("mldsa keygen:", err)
		os.Exit(2)
	}
	ok = run("mldsa87", mk.Public(), mk) && ok
	if !ok {
		fmt.Println("RESULT: FAIL")
		os.Exit(1)
	}
	fmt.Println("RESULT: PASS -- raw leaf DER readable after transport.Dial, before any stream (CONNECT) exists")
}
