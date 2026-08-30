package dht

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// Direct-dial dual-trust (Slice 7c Direction B) — X.509 cert chain.
//
// Managed realms root trust in the realm CA, not in the (keyless) realm
// tag. A provider embeds its own service-cert chain (leaf ++ org CA, PEM)
// in its procedure_advertisement; a verifying consumer chains it to the
// realm CA it received at its own issuance. No publisher records, no live
// authority — the trust material already travels with the advertisement.
//
// Ported from macula_record.erl's verify_advertisement_cert_chain/3 (and
// its cert_chain_step_*/pem_cert_ders/cert_subject_pubkey/validate_path/
// cert_org helpers) — same algorithm, same five failure modes, using
// crypto/x509's native path validation instead of hand-rolling ASN.1
// walking. Opt-in: this has no effect on plain (non-cert-chain)
// direct-dial, which remains exactly as it was.

// ErrCertChainAbsent means the advertisement carries no cert_chain field
// at all — the common, unmanaged-realm case. Not itself a sign of
// tampering; callers that require managed-realm authorization should
// treat this as "not authorized," not as evidence of an attack.
var ErrCertChainAbsent = errors.New("dht: advertisement carries no cert_chain")

// ErrCertChainBadSignature means the advertisement's own Ed25519 envelope
// signature does not verify — checked BEFORE the cert chain is even
// examined, since nothing in an unverified record can be trusted.
var ErrCertChainBadSignature = errors.New("dht: advertisement signature does not verify")

// ErrCertChainUndecodable means cert_chain is present but is not a
// decodable PEM bundle containing at least one certificate.
var ErrCertChainUndecodable = errors.New("dht: cert_chain is not a decodable PEM certificate bundle")

// ErrCertChainKeyMismatch means the leaf certificate's Ed25519 subject
// public key does not match the advertisement's own signing key — the
// chain does not actually belong to whoever signed this record.
var ErrCertChainKeyMismatch = errors.New("dht: leaf cert public key does not match the advertisement's signer")

// ErrCertChainUntrusted means the chain does not validate to the given
// realm CA (expired, wrong issuer, broken path, etc.) — wraps the
// underlying x509 error via errors.Unwrap.
var ErrCertChainUntrusted = errors.New("dht: cert chain does not validate to the trusted realm CA")

// ErrCertChainOrgMismatch means the chain validates, but the leaf
// certificate's Organization (O) does not match the procedure's expected
// org segment — a validly-signed cert for the WRONG org, i.e. a squat.
var ErrCertChainOrgMismatch = errors.New("dht: leaf cert organization does not match the expected org")

// VerifyAdvertisementCertChain verifies a resolved procedure_advertisement
// record's embedded X.509 service-cert chain against a trusted realm CA,
// for Slice 7c Direction B managed-realm authorization.
//
// realmCAPEM is the realm CA the caller already trusts (obtained at its
// own issuance, out of band — never resolved from the mesh itself). rec is
// a resolved procedure_advertisement. expectedOrg is the <org> segment of
// the procedure URI the caller intended to reach.
//
// Passes (returns nil) only when: rec's own envelope signature verifies;
// rec carries a cert_chain; the chain decodes to at least one certificate;
// the leaf certificate's Ed25519 subject public key equals rec's signing
// key (Key field); the leaf chains to realmCAPEM; and the leaf's
// Organization RDN equals expectedOrg. Any other outcome is a distinct
// sentinel error (test with errors.Is) — never silently return an
// unauthorized advertisement as trusted.
func VerifyAdvertisementCertChain(realmCAPEM []byte, rec Record, expectedOrg string) error {
	if err := Verify(rec); err != nil {
		return fmt.Errorf("%w: %v", ErrCertChainBadSignature, err)
	}
	adv, err := ReadProcedureAdvertisement(rec)
	if err != nil {
		return fmt.Errorf("dht: cert chain: %w", err)
	}
	if len(adv.CertChain) == 0 {
		return ErrCertChainAbsent
	}

	chain, err := decodeCertChain(adv.CertChain)
	if err != nil {
		return err
	}
	leaf := chain[0]

	leafKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || len(rec.Key) != ed25519.PublicKeySize || !ed25519.PublicKey(rec.Key).Equal(leafKey) {
		return ErrCertChainKeyMismatch
	}

	if err := validateCertPath(realmCAPEM, chain); err != nil {
		return fmt.Errorf("%w: %v", ErrCertChainUntrusted, err)
	}

	if len(leaf.Subject.Organization) == 0 || leaf.Subject.Organization[0] != expectedOrg {
		return ErrCertChainOrgMismatch
	}
	return nil
}

// decodeCertChain parses a leaf-first PEM bundle (as embedded: leaf ++ org
// CA ++ ...) into parsed certificates, leaf-first, matching
// macula_record's pem_cert_ders/1.
func decodeCertChain(certChainPEM []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := certChainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCertChainUndecodable, err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, ErrCertChainUndecodable
	}
	return out, nil
}

// validateCertPath validates chain (leaf-first: [leaf, org CA, ...]) to
// realmCAPEM as trust anchor. Any certificate in chain past the leaf is
// treated as an intermediate — mirrors macula_record's validate_path/2,
// which hands Erlang's pkix_path_validation the same leaf..anchor chain.
func validateCertPath(realmCAPEM []byte, chain []*x509.Certificate) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(realmCAPEM) {
		return fmt.Errorf("dht: realm CA PEM contains no parseable certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	return err
}
