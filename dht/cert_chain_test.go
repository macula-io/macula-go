package dht

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func testCA(t *testing.T) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey (CA): %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Realm CA", Organization: []string{"Test Realm CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate (CA): %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate (CA): %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return caPEM, caCert, caPriv
}

func testLeaf(t *testing.T, ca *x509.Certificate, caPriv ed25519.PrivateKey, advertiserPub ed25519.PublicKey, org string, notAfter time.Time) []byte {
	t.Helper()
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-service", Organization: []string{org}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, advertiserPub, caPriv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate (leaf): %v", err)
	}
	return leafDER
}

func pemBundle(ders ...[]byte) []byte {
	var buf bytes.Buffer
	for _, der := range ders {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return buf.Bytes()
}

func TestVerifyAdvertisementCertChainValid(t *testing.T) {
	caPEM, caCert, caPriv := testCA(t)
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	leafDER := testLeaf(t, caCert, caPriv, advertiser.NodeID(), "acme-corp", time.Now().Add(time.Hour))

	rec, err := NewProcedureAdvertisementWithCertChain(advertiser.NodeID(), "0000/acme-corp/widget.build_v1", station.NodeID(), time.Hour, pemBundle(leafDER))
	if err != nil {
		t.Fatalf("NewProcedureAdvertisementWithCertChain: %v", err)
	}
	rec = Sign(rec, advertiser)

	if err := VerifyAdvertisementCertChain(caPEM, rec, "acme-corp"); err != nil {
		t.Fatalf("VerifyAdvertisementCertChain: %v", err)
	}
}

func TestVerifyAdvertisementCertChainAbsent(t *testing.T) {
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), "0000/acme-corp/widget.build_v1", station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	rec = Sign(rec, advertiser)

	caPEM, _, _ := testCA(t)
	if err := VerifyAdvertisementCertChain(caPEM, rec, "acme-corp"); !errors.Is(err, ErrCertChainAbsent) {
		t.Fatalf("err = %v, want ErrCertChainAbsent", err)
	}
}

func TestVerifyAdvertisementCertChainBadSignature(t *testing.T) {
	caPEM, caCert, caPriv := testCA(t)
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	leafDER := testLeaf(t, caCert, caPriv, advertiser.NodeID(), "acme-corp", time.Now().Add(time.Hour))

	rec, err := NewProcedureAdvertisementWithCertChain(advertiser.NodeID(), "0000/acme-corp/widget.build_v1", station.NodeID(), time.Hour, pemBundle(leafDER))
	if err != nil {
		t.Fatalf("NewProcedureAdvertisementWithCertChain: %v", err)
	}
	rec = Sign(rec, advertiser)
	rec.Signature[0] ^= 0xFF

	if err := VerifyAdvertisementCertChain(caPEM, rec, "acme-corp"); !errors.Is(err, ErrCertChainBadSignature) {
		t.Fatalf("err = %v, want ErrCertChainBadSignature", err)
	}
}

func TestVerifyAdvertisementCertChainKeyMismatch(t *testing.T) {
	caPEM, caCert, caPriv := testCA(t)
	advertiser := mustKeyPair(t)
	otherKey := mustKeyPair(t)
	station := mustKeyPair(t)
	leafDER := testLeaf(t, caCert, caPriv, otherKey.NodeID(), "acme-corp", time.Now().Add(time.Hour))

	rec, err := NewProcedureAdvertisementWithCertChain(advertiser.NodeID(), "0000/acme-corp/widget.build_v1", station.NodeID(), time.Hour, pemBundle(leafDER))
	if err != nil {
		t.Fatalf("NewProcedureAdvertisementWithCertChain: %v", err)
	}
	rec = Sign(rec, advertiser)

	if err := VerifyAdvertisementCertChain(caPEM, rec, "acme-corp"); !errors.Is(err, ErrCertChainKeyMismatch) {
		t.Fatalf("err = %v, want ErrCertChainKeyMismatch", err)
	}
}

func TestVerifyAdvertisementCertChainOrgMismatch(t *testing.T) {
	caPEM, caCert, caPriv := testCA(t)
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	leafDER := testLeaf(t, caCert, caPriv, advertiser.NodeID(), "acme-corp", time.Now().Add(time.Hour))

	rec, err := NewProcedureAdvertisementWithCertChain(advertiser.NodeID(), "0000/other-org/widget.build_v1", station.NodeID(), time.Hour, pemBundle(leafDER))
	if err != nil {
		t.Fatalf("NewProcedureAdvertisementWithCertChain: %v", err)
	}
	rec = Sign(rec, advertiser)

	if err := VerifyAdvertisementCertChain(caPEM, rec, "other-org"); !errors.Is(err, ErrCertChainOrgMismatch) {
		t.Fatalf("err = %v, want ErrCertChainOrgMismatch", err)
	}
}

func TestVerifyAdvertisementCertChainExpired(t *testing.T) {
	caPEM, caCert, caPriv := testCA(t)
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	leafDER := testLeaf(t, caCert, caPriv, advertiser.NodeID(), "acme-corp", time.Now().Add(-time.Hour))

	rec, err := NewProcedureAdvertisementWithCertChain(advertiser.NodeID(), "0000/acme-corp/widget.build_v1", station.NodeID(), time.Hour, pemBundle(leafDER))
	if err != nil {
		t.Fatalf("NewProcedureAdvertisementWithCertChain: %v", err)
	}
	rec = Sign(rec, advertiser)

	if err := VerifyAdvertisementCertChain(caPEM, rec, "acme-corp"); !errors.Is(err, ErrCertChainUntrusted) {
		t.Fatalf("err = %v, want ErrCertChainUntrusted", err)
	}
}

func TestVerifyAdvertisementCertChainWrongCA(t *testing.T) {
	_, caCert, caPriv := testCA(t)
	otherCAPEM, _, _ := testCA(t)
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	leafDER := testLeaf(t, caCert, caPriv, advertiser.NodeID(), "acme-corp", time.Now().Add(time.Hour))

	rec, err := NewProcedureAdvertisementWithCertChain(advertiser.NodeID(), "0000/acme-corp/widget.build_v1", station.NodeID(), time.Hour, pemBundle(leafDER))
	if err != nil {
		t.Fatalf("NewProcedureAdvertisementWithCertChain: %v", err)
	}
	rec = Sign(rec, advertiser)

	if err := VerifyAdvertisementCertChain(otherCAPEM, rec, "acme-corp"); !errors.Is(err, ErrCertChainUntrusted) {
		t.Fatalf("err = %v, want ErrCertChainUntrusted", err)
	}
}

func TestVerifyAdvertisementCertChainUndecodable(t *testing.T) {
	caPEM, _, _ := testCA(t)
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	rec, err := NewProcedureAdvertisementWithCertChain(advertiser.NodeID(), "0000/acme-corp/widget.build_v1", station.NodeID(), time.Hour, []byte("not a pem cert bundle"))
	if err != nil {
		t.Fatalf("NewProcedureAdvertisementWithCertChain: %v", err)
	}
	rec = Sign(rec, advertiser)

	if err := VerifyAdvertisementCertChain(caPEM, rec, "acme-corp"); !errors.Is(err, ErrCertChainUndecodable) {
		t.Fatalf("err = %v, want ErrCertChainUndecodable", err)
	}
}
