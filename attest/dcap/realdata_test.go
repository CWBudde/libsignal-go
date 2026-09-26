// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// TestIntelPCKChain validates the recorded evidence's PCK chain the way
// dcap.rs verify_certificates does: a root trust store pinned to Intel's
// root key, the PCK CRL validated through its issuer chain, then the PCK
// chain against both CRLs.
func TestIntelPCKChain(t *testing.T) {
	e, err := dcap.ParseEvidence(readTestdata(t, "dcap.evidence"))
	if err != nil {
		t.Fatal(err)
	}
	blob := readTestdata(t, "dcap.endorsements")
	pckCRL, err := dcap.ParseRevocationList(endorsementField(t, blob, fieldCRLPCKCert))
	if err != nil {
		t.Fatal(err)
	}
	rootCRL, err := dcap.ParseRevocationList(endorsementField(t, blob, fieldCRLPCKProcCA))
	if err != nil {
		t.Fatal(err)
	}
	crlChain, err := dcap.ParseCertChainPEM(endorsementField(t, blob, fieldPCKCRLIssuerChain))
	if err != nil {
		t.Fatal(err)
	}
	pck := e.Quote.Support.PCKCertChain
	root := pck.Root()
	if len(pck.Certificates()) != 3 {
		t.Fatalf("PCK chain has %d certificates", len(pck.Certificates()))
	}
	now := pckCRL.CRL().ThisUpdate
	if rootCRL.CRL().ThisUpdate.After(now) {
		now = rootCRL.CRL().ThisUpdate
	}
	if !e.ValidAt(now) || !pckCRL.ValidAt(now) || !rootCRL.ValidAt(now) {
		t.Fatalf("fixture not valid at %s", now)
	}

	verify := func(now time.Time, key *ecdsa.PublicKey) error {
		trusted, err := dcap.RootTrustStore(root, rootCRL, key, now)
		if err != nil {
			return err
		}
		if err := crlChain.Validate(trusted, []*dcap.RevocationList{pckCRL}); err != nil {
			return err
		}
		trusted = dcap.NewTrustStore([]*x509.Certificate{root}, []*dcap.RevocationList{rootCRL, pckCRL}, now)
		return pck.Validate(trusted, nil)
	}
	if err := verify(now, dcap.IntelRootKey()); err != nil {
		t.Fatalf("Intel PCK chain: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verify(now, &other.PublicKey); !errors.Is(err, dcap.ErrUntrustedKey) {
		t.Errorf("other root key: %v", err)
	}
	// Two years later the CRLs (and certificates) have expired, as in
	// test_verify_remote_attestation_expired_attestation.
	if err := verify(now.AddDate(2, 0, 0), dcap.IntelRootKey()); err == nil {
		t.Error("expired collateral accepted")
	}
	// Without the PCK CRL there is no CRL for the leaf.
	trusted := dcap.NewTrustStore([]*x509.Certificate{root}, []*dcap.RevocationList{rootCRL}, now)
	if err := pck.Validate(trusted, nil); !errors.Is(err, dcap.ErrCRL) {
		t.Errorf("missing PCK CRL: %v", err)
	}
}
