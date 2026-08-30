// Command certchain demonstrates opt-in, managed-realm authorization
// layered on top of direct-dial: a resolved advertisement's embedded
// X.509 chain must validate against a caller-trusted realm CA and name an
// expected org, or the caller refuses to trust it — even if the plain
// signature check alone would have passed.
//
// The trust anchor here is entirely self-issued: cert-chain authorization
// is a client-side check on an opaque payload the station never
// inspects, so no real CA or macula-realm involvement is needed to
// demonstrate it.
//
// Run: go run ./examples/certchain
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/connection"
	"github.com/macula-io/macula-go-sdk/directdial"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/transport"
)

const (
	host      = "station-de-frankfurt.macula.io"
	port      = 4433
	procedure = "examples.certchain.grant"
	org       = "acme"
)

func selfIssuedRealmCA() (pemBytes []byte, cert *x509.Certificate, priv ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("ed25519.GenerateKey (CA): %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Realm CA", Organization: []string{"Example Realm CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		log.Fatalf("x509.CreateCertificate (CA): %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		log.Fatalf("x509.ParseCertificate (CA): %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, priv
}

func leafFor(ca *x509.Certificate, caPriv ed25519.PrivateKey, subjectPub ed25519.PublicKey, forOrg string) []byte {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "example-service", Organization: []string{forOrg}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, subjectPub, caPriv)
	if err != nil {
		log.Fatalf("x509.CreateCertificate (leaf): %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func main() {
	providerID, err := identity.Generate()
	if err != nil {
		log.Fatalf("identity.Generate (provider): %v", err)
	}
	callerID, err := identity.Generate()
	if err != nil {
		log.Fatalf("identity.Generate (caller): %v", err)
	}

	realmCAPEM, caCert, caPriv := selfIssuedRealmCA()
	chainPEM := leafFor(caCert, caPriv, ed25519.PublicKey(providerID.NodeID()), org)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := connection.Connect(ctx, host, port, transport.WebPKI{}, providerID)
	if err != nil {
		log.Fatalf("connection.Connect (provider): %v", err)
	}
	defer provider.Close("normal", nil, providerID)

	realm := make([]byte, 32)
	if err := directdial.AdvertiseDirectWithCertChain(provider, providerID, realm, procedure, time.Hour, chainPEM); err != nil {
		log.Fatalf("AdvertiseDirectWithCertChain: %v", err)
	}

	served := make(chan error, 1)
	go func() {
		lookup := func(_ []byte, proc string) (connection.CallHandler, bool) {
			if proc != procedure {
				return nil, false
			}
			return func(cbor.Value) (cbor.Value, error) { return cbor.Text("granted"), nil }, true
		}
		served <- provider.ServeOneCall(lookup, providerID, 20*time.Second)
	}()

	caller, err := connection.Connect(ctx, host, port, transport.WebPKI{}, callerID)
	if err != nil {
		log.Fatalf("connection.Connect (caller): %v", err)
	}
	defer caller.Close("normal", nil, callerID)

	resp, err := directdial.CallWithCertChain(ctx, caller, callerID, realm, procedure, realmCAPEM, org, cbor.Null(), 15*time.Second)
	if errors.Is(err, directdial.ErrStationEndpointNotFound) {
		// KNOWN EXTERNAL CONDITION, not a bug in this example or in
		// cert-chain itself: the demo fleet's station_endpoint DHT
		// records carry a short TTL and aren't always freshly
		// republished -- see the README's Known limitations section.
		fmt.Fprintln(os.Stderr, "resolved station currently has no reachable station_endpoint (known fleet flakiness, not a code issue) -- try again shortly")
		<-served
		return
	}
	if err != nil {
		log.Fatalf("CallWithCertChain (expected org): %v", err)
	}
	fmt.Printf("call authorized for org %q: is_error=%v payload=%s\n", org, resp.IsError, resp.Payload)
	if err := <-served; err != nil {
		log.Fatalf("ServeOneCall: %v", err)
	}

	// Negative control: the same resolved record, checked against the
	// WRONG expected org, must be refused -- proves the check actually
	// inspects the chain rather than trusting any signed advertisement.
	_, _, _, err = directdial.ResolveWithCertChain(caller, callerID, realm, procedure, realmCAPEM, "not-"+org)
	if err == nil {
		log.Fatal("ResolveWithCertChain unexpectedly succeeded for the wrong org")
	}
	fmt.Printf("resolve correctly refused for the wrong org: %v\n", errors.Unwrap(err))
}
