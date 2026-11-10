package teststation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/transport"
)

// relayWindow bounds what either end of a relayed stream may have in flight
// while its reader is not reading, so a test can be sure the relay still holds
// bytes when it ends a direction.
const relayWindow = 32 << 10

// relaySent is how much the caller sends: more than the window, so the relay
// can never have handed all of it over before a direction ends.
const relaySent = 256 << 10

// relayConn is one QUIC connection seen from both ends: the station's, where a
// relayed stream lives, and the peer that plays both the caller and the
// provider.
func relayConn(t *testing.T, ctx context.Context) (client, station *quic.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ECDSA key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leaf, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	window := &quic.Config{InitialStreamReceiveWindow: relayWindow, MaxStreamReceiveWindow: relayWindow}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13, NextProtos: []string{transport.ALPN}, SessionTicketsDisabled: true,
	}, window)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if client, err = quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{transport.ALPN}, SessionTicketsDisabled: true,
	}, window); err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	if station, err = listener.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}
	return client, station
}

// A relay ends each direction on its own (macula-go#54): its write to the
// caller fails because the caller stopped reading, and that must cost the
// provider nothing of what the caller already sent. The caller's bytes are
// still in the relay when the failure comes, so a relay that resets the other
// stream drops them; the failing direction alone must end, and its source be
// told to stop.
func TestARelayEndsEachDirectionOnItsOwn(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	client, station := relayConn(t, ctx)
	caller, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("the caller's open: %v", err)
	}
	sent := bytes.Repeat([]byte("the caller's own bytes. "), relaySent/len("the caller's own bytes. "))
	writing := make(chan error, 1)
	go func() {
		_, err := io.Copy(caller, bytes.NewReader(sent))
		if err == nil {
			err = caller.Close()
		}
		writing <- err
	}()
	from, err := station.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("the station's accept: %v", err)
	}
	to, err := station.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("the station's open: %v", err)
	}
	(&Station{}).count(from, to) // count needs only the relay's counter
	provider, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("the provider's accept: %v", err)
	}

	// The caller stops reading before the provider has read everything: the
	// relay's write toward the caller fails, and the provider still answers.
	caller.CancelRead(0)
	replied := make(chan error, 1)
	_ = provider.SetWriteDeadline(time.Now().Add(10 * time.Second))
	go func() {
		_, err := io.Copy(provider, bytes.NewReader(bytes.Repeat([]byte("provider bytes. "), relaySent/len("provider bytes. "))))
		replied <- err
	}()

	_ = provider.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(provider)
	if err != nil {
		t.Fatalf("the provider's read ended after %d of the caller's %d bytes: %v", len(got), len(sent), err)
	}
	if !bytes.Equal(got, sent) {
		t.Fatalf("the provider read %d of the caller's %d bytes", len(got), len(sent))
	}
	if err := <-writing; err != nil {
		t.Fatalf("the caller's write: %v", err)
	}
	select {
	case err := <-replied:
		var stopped *quic.StreamError
		if !errors.As(err, &stopped) || !stopped.Remote {
			t.Fatalf("the write to a caller that stopped reading ended with %v, want the caller's own STOP_SENDING", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the write to a caller that stopped reading was never ended")
	}
}

// A relay abandons the direction that failed instead of ending it cleanly, and
// the opposite direction still finishes: a caller that resets mid-message must
// not reach the provider as a whole one, and must still receive the provider's
// answer.
func TestARelayAbandonsTheDirectionThatFailed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	client, station := relayConn(t, ctx)
	caller, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("the caller's open: %v", err)
	}
	if _, err := caller.Write([]byte("cut short")); err != nil {
		t.Fatalf("the caller's write: %v", err)
	}
	caller.CancelWrite(0)
	from, err := station.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("the station's accept: %v", err)
	}
	to, err := station.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("the station's open: %v", err)
	}
	(&Station{}).count(from, to) // count needs only the relay's counter
	provider, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("the provider's accept: %v", err)
	}
	reply := bytes.Repeat([]byte("the provider's own bytes. "), (64<<10)/len("the provider's own bytes. "))
	go func() {
		_, _ = provider.Write(reply)
		_ = provider.Close()
	}()

	_ = provider.SetReadDeadline(time.Now().Add(10 * time.Second))
	cut, err := io.ReadAll(provider)
	var aborted *quic.StreamError
	if !errors.As(err, &aborted) || !aborted.Remote {
		t.Fatalf("the provider's read of a cut-short message ended with %v after %d bytes, want the relay's own reset", err, len(cut))
	}
	_ = caller.SetReadDeadline(time.Now().Add(10 * time.Second))
	delivered, err := io.ReadAll(caller)
	if err != nil {
		t.Fatalf("the caller's read ended after %d of the provider's %d bytes: %v", len(delivered), len(reply), err)
	}
	if !bytes.Equal(delivered, reply) {
		t.Fatalf("the caller read %d of the provider's %d bytes", len(delivered), len(reply))
	}
}
