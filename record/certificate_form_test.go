package record

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// macula 11.0.0's realm issues no certificates, so a provider authorization has
// no certificate form. A certificate chain that validates to its realm CA, and
// that would have authorized the advertisement before the form was removed, is
// refused as ErrAuthorizationFormUnsupported, as macula_record's
// verify_authorization/3 refuses it, while a storing verifier still accepts the
// advertisement that carries it. Package record reads no certificate, so this
// test mints the chain with crypto/x509 and checks that it validates. It mirrors
// a_certificate_chain_authorization_is_refused_as_an_unsupported_form_test in
// macula's macula_record_cert_chain_tests at merge-11.0.0 2d2c2ecb.
func TestAValidCertificateChainIsAnUnsupportedForm(t *testing.T) {
	keys := keysFor(t)
	realmKey := must[*mldsa.PrivateKey](t)(mldsa.GenerateKey(mldsa.MLDSA87()))
	orgKey := must[*mldsa.PrivateKey](t)(mldsa.GenerateKey(mldsa.MLDSA87()))
	aYear := time.Now().Add(365 * 24 * time.Hour)
	mintCertificate := func(commonName, org string, public *mldsa.PublicKey, issuer *x509.Certificate,
		issuerKey *mldsa.PrivateKey, isCA bool) (*x509.Certificate, []byte) {
		template := &x509.Certificate{
			SerialNumber:          must[*big.Int](t)(rand.Int(rand.Reader, big.NewInt(1<<60))),
			Subject:               pkix.Name{CommonName: commonName, Organization: []string{org}},
			NotBefore:             time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:              aYear,
			BasicConstraintsValid: true,
			IsCA:                  isCA,
		}
		if issuer == nil {
			issuer = template
		}
		der := must[[]byte](t)(x509.CreateCertificate(rand.Reader, template, issuer, public, issuerKey))
		return must[*x509.Certificate](t)(x509.ParseCertificate(der)), der
	}
	realmCA, _ := mintCertificate("io.macula", "io.macula", realmKey.PublicKey(), nil, realmKey, true)
	orgCA, orgDER := mintCertificate("io.macula.acme", "acme", orgKey.PublicKey(), realmCA, realmKey, true)
	leafKey := must[*mldsa.PublicKey](t)(mldsa.NewPublicKey(mldsa.MLDSA87(), keys.node.PublicKey()))
	leaf, leafDER := mintCertificate("svc", "acme", leafKey, orgCA, orgKey, false)
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(realmCA)
	intermediates.AddCert(orgCA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("the minted chain does not validate to its realm CA: %v", err)
	}
	entries, _ := advertisementPayload(keys.node.KeyID()).AsMap()
	chain := cbor.Map([]cbor.MapEntry{valueEntry("certificate_chain", cbor.List([]cbor.Value{cbor.Bytes(leafDER), cbor.Bytes(orgDER)}))})
	built := must[Record](t)(unsigned(TypeProcedureAdvertisement, cbor.Map(withEntry(entries, "authorization", chain)), 0))
	advertisement, err := Verify(wireOf(t, must[Record](t)(Sign(built, keys.node))), profile.PQPure, nowMs())
	if err != nil {
		t.Fatalf("a storing verifier refuses the advertisement carrying a certificate chain: %v, want it verified", err)
	}
	wantRefusal(t, "an advertisement authorized by a valid certificate chain",
		VerifyAuthorization(advertisement, realmTrust(t), nowMs()), ErrAuthorizationFormUnsupported)
}
