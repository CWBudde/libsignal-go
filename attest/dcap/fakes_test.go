// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// signingInfo is upstream's fakes::SigningInfo: test certificates and
// keys standing in for Intel's.
type signingInfo struct {
	root              *testCert
	pckChain          []*testCert // leaf, intermediate, root
	pckIssuerCRLChain []*testCert
	tcbIssuerChain    []*testCert
	qeIDIssuerChain   []*testCert
	attestKey         *ecdsa.PrivateKey
	rootRevoked       []*big.Int
	pckRevoked        []*big.Int
}

// issueChain returns n certificates issued in a line below root, followed
// by root: leaf first (TestCert::issue_chain).
func issueChain(t testing.TB, root *testCert, n int) []*testCert {
	t.Helper()
	chain := []*testCert{root}
	for i := range n {
		chain = append([]*testCert{newTestCert(t, chain[0], fmt.Sprintf("issued %d", i))}, chain...)
	}
	return chain
}

func newSigningInfo(t testing.TB) *signingInfo {
	t.Helper()
	root := newTestCert(t, nil, "root")
	pck := issueChain(t, root, 2)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signingInfo{
		root:              root,
		pckChain:          pck,
		pckIssuerCRLChain: []*testCert{pck[1], root},
		// In Intel's collateral these are the same chain.
		tcbIssuerChain:  issueChain(t, root, 1),
		qeIDIssuerChain: issueChain(t, root, 1),
		attestKey:       key,
	}
}

// fakeAttestation is upstream's FakeAttestationBuilder: evidence and
// endorsements parsed from the recorded blobs, to be changed by a test and
// then re-signed with the signing info's keys.
type fakeAttestation struct {
	info *signingInfo
	ev   *dcap.Evidence
	en   *dcap.Endorsements
}

// newFake returns evidence and endorsements that attest successfully once
// signed: the collateral expires tomorrow and has the minimum TCB
// evaluation data number.
func newFake(t testing.TB) *fakeAttestation {
	t.Helper()
	ev, err := dcap.ParseEvidence(readTestdata(t, "dcap.evidence"))
	if err != nil {
		t.Fatal(err)
	}
	en, err := dcap.ParseEndorsements(readTestdata(t, "dcap.endorsements"))
	if err != nil {
		t.Fatal(err)
	}
	tomorrow := time.Now().AddDate(0, 0, 1)
	en.TCBInfo.NextUpdate = tomorrow
	en.QEIdentity.NextUpdate = tomorrow
	en.TCBInfo.TCBEvaluationDataNumber = dcap.TCBEvaluationDataNumberMin
	en.QEIdentity.TCBEvaluationDataNumber = dcap.TCBEvaluationDataNumberMin
	return &fakeAttestation{info: newSigningInfo(t), ev: ev, en: en}
}

func signRaw(t testing.TB, key *ecdsa.PrivateKey, data []byte) [64]byte {
	t.Helper()
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

func chainOf(t testing.TB, cs []*testCert) *dcap.CertChain {
	t.Helper()
	c, err := dcap.NewCertChain(certsOf(cs))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// sign sets the attestation key, the QE report data and both report
// signatures, and swaps in the test chains and CRLs. It overwrites any
// signature set by hand.
func (f *fakeAttestation) sign(t testing.TB) {
	t.Helper()
	info, s := f.info, &f.ev.Quote.Support
	pub, err := info.attestKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	s.AttestPubKey = [64]byte(pub[1:])
	h := sha256.New()
	h.Write(s.AttestPubKey[:])
	h.Write(s.AuthData)
	data := s.QEReportBody[dcap.RBReportData : dcap.RBReportData+64]
	clear(data)
	copy(data, h.Sum(nil))
	s.ISVSignature = signRaw(t, info.attestKey, f.ev.Quote.Body[:])
	s.QEReportSignature = signRaw(t, info.pckChain[0].key, s.QEReportBody[:])

	f.en.RootCRL = info.root.crl(t, info.rootRevoked...)
	f.en.PCKIssuerCRL = info.pckIssuerCRLChain[0].crl(t, info.pckRevoked...)
	f.en.QEIdentityIssuerChain = chainOf(t, info.qeIDIssuerChain)
	f.en.TCBIssuerChain = chainOf(t, info.tcbIssuerChain)
	f.en.PCKIssuerCRLChain = chainOf(t, info.pckIssuerCRLChain)
	s.PCKCertChain = chainOf(t, info.pckChain)
}

// attest signs and attests now against the test root.
func (f *fakeAttestation) attest(t testing.TB) (*dcap.Attestation, error) {
	t.Helper()
	f.sign(t)
	root, ok := f.info.root.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("root key is not ECDSA")
	}
	return dcap.Attest(f.ev, f.en, root, time.Now())
}

// qeReport returns the quoting enclave's report body.
func (f *fakeAttestation) qeReport() *dcap.ReportBody { return &f.ev.Quote.Support.QEReportBody }

// isvReport returns the application enclave's report body.
func (f *fakeAttestation) isvReport() []byte {
	return f.ev.Quote.Body[dcap.QuoteReportBodyOffset:]
}

func serialOf(c *testCert) *big.Int { return c.cert.SerialNumber }
