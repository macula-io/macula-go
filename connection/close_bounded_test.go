package connection

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// tinyWindowQUICConfig gives the receiver a deliberately tiny flow-control
// window so a modest write from the other side blocks without needing a
// multi-megabyte payload -- the whole point of this test is proving a
// blocked write gets unblocked by a deadline, not exercising real
// throughput.
func tinyWindowQUICConfig() *quic.Config {
	return &quic.Config{
		InitialStreamReceiveWindow:     4096,
		MaxStreamReceiveWindow:         4096,
		InitialConnectionReceiveWindow: 4096,
		MaxConnectionReceiveWindow:     4096,
	}
}

func selfSignedServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"macula-test"}}
}

// TestSendFrameIsBoundedByWriteDeadline reproduces, without any macula
// protocol involved, the exact mechanism Session.Close's own
// closeSendTimeout relies on: a peer that stops reading leaves
// Stream.Write parked waiting for flow-control credit with no deadline
// set, indefinitely; setting one via SetWriteDeadline (what Close now
// does immediately before its own SendFrame call) unblocks that same
// parked write instead of leaving it stuck forever. This is the gap
// flagged in adversarial review: the fix's mechanism was reasoned about
// against quic-go's own source, never actually exercised.
//
// A raw loopback QUIC stream pair is enough to prove this -- no CONNECT/
// HELLO handshake needed, since the bug and the fix both live entirely
// below the macula protocol, in how a QUIC stream's Write behaves.
func TestSendFrameIsBoundedByWriteDeadline(t *testing.T) {
	tlsConf := selfSignedServerTLSConfig(t)
	quicConf := tinyWindowQUICConfig()

	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, quicConf)
	if err != nil {
		t.Fatalf("quic.ListenAddr: %v", err)
	}
	defer ln.Close()

	stopServer := make(chan struct{})
	go func() {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			t.Logf("server: Accept: %v", err)
			return
		}
		defer conn.CloseWithError(0, "test done")
		// AcceptStream only unblocks once the peer's stream actually
		// carries data on the wire (opening a stream client-side, with
		// nothing written to it yet, sends nothing) -- so this
		// necessarily happens concurrently with the client's write
		// below, not before it.
		_, err = conn.AcceptStream(context.Background())
		if err != nil {
			t.Logf("server: AcceptStream: %v", err)
			return
		}
		// Deliberately never read from it -- this is the "peer stopped
		// draining" condition the pool's own outbox-overflow exit
		// exists to detect, and the exact condition under which
		// Session.Close's own GOODBYE write used to hang forever.
		<-stopServer
	}()
	defer close(stopServer)

	clientTLSConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"macula-test"}}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, err := quic.DialAddr(dialCtx, ln.Addr().String(), clientTLSConf, quicConf)
	if err != nil {
		t.Fatalf("quic.DialAddr: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	stream, err := conn.OpenStreamSync(dialCtx)
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	fs := newFrameStream(stream)

	// Big enough to exceed the 4096-byte window several times over, so
	// the write genuinely blocks on flow control rather than completing
	// inside quic-go's own send buffer.
	payload := make([]byte, 512*1024)

	// Mirrors Session.Close exactly: set a bounded write deadline
	// immediately before the send that might block.
	const testCloseSendTimeout = 1 * time.Second
	if err := stream.SetWriteDeadline(time.Now().Add(testCloseSendTimeout)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	start := time.Now()
	writeDone := make(chan error, 1)
	go func() {
		_, err := fs.stream.Write(payload)
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("expected the write to fail once the deadline fired (peer never read), got nil error after %s", elapsed)
		}
		if elapsed > 3*time.Second {
			t.Fatalf("write took %s to fail -- the deadline did not bound it as expected", elapsed)
		}
		t.Logf("write blocked on flow control and failed after %s, as expected: %v", elapsed, err)
	case <-time.After(4 * time.Second):
		t.Fatalf("write did not return within 4s of a 1s deadline -- SetWriteDeadline did not unblock the parked Write (this is exactly the bug Session.Close's own fix addresses)")
	}
}
