// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"slices"
	"time"
)

// intelQEVendorID is the UUID 939a7233-f79c-4ca9-940a-0db3957f0607.
var intelQEVendorID = [16]byte{
	0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
}

// TCBStanding is the trust level of the platform's TCB.
type TCBStanding struct {
	// SWHardeningNeeded is set if the platform is only trustworthy when
	// the enclave mitigates AdvisoryIDs in software.
	SWHardeningNeeded bool
	AdvisoryIDs       []string
}

// Attestation is what attestation establishes about an enclave, before
// the caller's MRENCLAVE and advisory policy.
type Attestation struct {
	TCBStanding TCBStanding
	MREnclave   [32]byte
	Claims      map[string][]byte
}

// VerifyRemoteAttestation verifies evidence with its endorsements at now
// against Intel's root key and returns the enclave's custom claims. The
// enclave must have MRENCLAVE mrenclave, and every advisory of a TCB level
// that needs software hardening must be in acceptableAdvisories
// (dcap.rs verify_remote_attestation).
func VerifyRemoteAttestation(evidence, endorsements []byte, mrenclave [32]byte, acceptableAdvisories []string, now time.Time) (map[string][]byte, error) {
	a, err := attestBytes(evidence, endorsements, IntelRootKey(), now)
	if err != nil {
		return nil, err
	}
	return a.check(mrenclave, acceptableAdvisories)
}

func (a *Attestation) check(mrenclave [32]byte, acceptableAdvisories []string) (map[string][]byte, error) {
	if a.TCBStanding.SWHardeningNeeded {
		for _, id := range a.TCBStanding.AdvisoryIDs {
			if !slices.Contains(acceptableAdvisories, id) {
				return nil, fmt.Errorf("%w: TCB contains unmitigated unaccepted advisory ids: %q",
					ErrAdvisory, a.TCBStanding.AdvisoryIDs)
			}
		}
	}
	if a.MREnclave != mrenclave {
		return nil, fmt.Errorf("%w: expected %s, was %s", ErrMREnclave,
			hex.EncodeToString(mrenclave[:]), hex.EncodeToString(a.MREnclave[:]))
	}
	return a.Claims, nil
}

func attestBytes(evidence, endorsements []byte, rootKey *ecdsa.PublicKey, now time.Time) (*Attestation, error) {
	ev, err := ParseEvidence(evidence)
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}
	en, err := ParseEndorsements(endorsements)
	if err != nil {
		return nil, fmt.Errorf("endorsements: %w", err)
	}
	return attest(ev, en, rootKey, now)
}

// attest checks that ev comes from an SGX enclave trusted by Intel's
// rootKey at now (dcap.rs attest_impl).
func attest(ev *Evidence, en *Endorsements, rootKey *ecdsa.PublicKey, now time.Time) (*Attestation, error) {
	// 1. Verify the signature chain from the quote to the PCK certificate
	// and 2. that no key in it is revoked, all within their validity.
	if !ev.ValidAt(now) {
		return nil, fmt.Errorf("evidence: %w: not valid at %d", ErrExpired, now.Unix())
	}
	if !en.ValidAt(now) {
		return nil, fmt.Errorf("endorsements: %w: not valid at %d", ErrExpired, now.Unix())
	}
	if err := verifyCertificates(rootKey, ev, en, now); err != nil {
		return nil, err
	}
	// 3. The quoting enclave is Intel's and up to date.
	if err := verifyEnclaveSource(ev, en); err != nil {
		return nil, err
	}
	if err := verifyEnclaveSignatures(ev); err != nil {
		return nil, err
	}
	standing, err := verifyTCBStatus(ev, en)
	if err != nil {
		return nil, err
	}
	if err := verifyClaimsHash(ev); err != nil {
		return nil, err
	}
	// MRENCLAVE values should only be trusted for non-debug builds, but
	// reject debug enclaves as an extra precaution.
	report := ev.Quote.Body.ReportBody()
	if report.HasFlag(FlagDebug) {
		return nil, fmt.Errorf("%w: application enclave in debug mode", ErrDebug)
	}
	return &Attestation{TCBStanding: standing, MREnclave: report.MREnclave(), Claims: ev.Claims.Map}, nil
}

// verifyCertificates checks that all chains and CRLs lead to rootKey.
// Like upstream it checks RFC 5280 path validity only, not chain lengths
// or subjects.
func verifyCertificates(rootKey *ecdsa.PublicKey, ev *Evidence, en *Endorsements, now time.Time) error {
	root := en.TCBIssuerChain.Root()
	trusted, err := RootTrustStore(root, en.RootCRL, rootKey, now)
	if err != nil {
		return fmt.Errorf("root trust store: %w", err)
	}
	if err := en.PCKIssuerCRLChain.Validate(trusted, []*RevocationList{en.PCKIssuerCRL}); err != nil {
		return fmt.Errorf("pck crl: %w", err)
	}
	trusted = NewTrustStore([]*x509.Certificate{root}, []*RevocationList{en.RootCRL, en.PCKIssuerCRL}, now)
	if err := en.TCBIssuerChain.Validate(trusted, nil); err != nil {
		return fmt.Errorf("tcb issuer: %w", err)
	}
	if err := ev.Quote.Support.PCKCertChain.Validate(trusted, nil); err != nil {
		return fmt.Errorf("pck: %w", err)
	}
	if err := en.QEIdentityIssuerChain.Validate(trusted, nil); err != nil {
		return fmt.Errorf("qe id issuer: %w", err)
	}
	return nil
}

// verifyEnclaveSource checks the quoting enclave against Intel's QE
// identity (PCS "QE identity v3" steps).
func verifyEnclaveSource(ev *Evidence, en *Endorsements) error {
	if v := ev.Quote.Body.QEVendorID(); v != intelQEVendorID {
		return fmt.Errorf("%w: QE vendor ID %x not Intel", ErrEnclaveSource, v)
	}
	id := en.QEIdentity
	qe := &ev.Quote.Support.QEReportBody
	if qe.MRSigner() != id.MRSigner {
		mrsigner := qe.MRSigner()
		return fmt.Errorf("%w: qe mrsigner mismatch: expected %x, actual %x", ErrEnclaveSource, id.MRSigner, mrsigner)
	}
	if qe.ISVProdID() != id.ISVProdID {
		return fmt.Errorf("%w: qe isvprodid mismatch: expected %d, actual %d", ErrEnclaveSource, qe.ISVProdID(), id.ISVProdID)
	}
	if qe.MiscSelect()&id.MiscSelectMask != id.MiscSelect {
		return fmt.Errorf("%w: qe miscselect mismatch", ErrEnclaveSource)
	}
	attrs := qe.Attributes()
	for i := range attrs {
		if attrs[i]&id.AttributesMask[i] != id.Attributes[i] {
			return fmt.Errorf("%w: attributes mismatch", ErrEnclaveSource)
		}
	}
	if id.ID != EnclaveQE {
		return fmt.Errorf("%w: invalid enclave identity for quoting enclave: %d", ErrEnclaveSource, id.ID)
	}
	// The TCB info is consulted later, but a QE that is not up to date can
	// be rejected now.
	if s := id.TCBStatus(qe.ISVSVN()); s != QEUpToDate {
		return fmt.Errorf("%w: enclave version tcb not up to date (was %s)", ErrEnclaveSource, s)
	}
	return nil
}

// verifyEnclaveSignatures checks that the PCK leaf signed the QE report,
// that the QE report commits to the attestation key, and that the
// attestation key signed the ISV report.
func verifyEnclaveSignatures(ev *Evidence) error {
	s := &ev.Quote.Support
	pck, err := s.PCKCertChain.LeafPublicKey()
	if err != nil {
		return fmt.Errorf("pck cert chain: %w", err)
	}
	if err := s.VerifySignature(pck); err != nil {
		return fmt.Errorf("QE report: %w", err)
	}
	if err := s.VerifyQEReport(); err != nil {
		return fmt.Errorf("QE report: %w", err)
	}
	key, err := s.AttestKey()
	if err != nil {
		return fmt.Errorf("quote attest key: %w", err)
	}
	if err := ev.Quote.VerifySignature(key); err != nil {
		return fmt.Errorf("ISV report: %w", err)
	}
	return nil
}

// verifyTCBStatus matches the TCB info to the platform and finds the
// platform's TCB level (PCS "TCB info v3" steps).
func verifyTCBStatus(ev *Evidence, en *Endorsements) (TCBStanding, error) {
	info := en.TCBInfo
	ext := ev.Quote.Support.PCKExtension
	if ext.FMSPC != info.FMSPC {
		return TCBStanding{}, fmt.Errorf("%w: tcb fmspc mismatch (pck extension %x, tcb info %x)", ErrTCB, ext.FMSPC, info.FMSPC)
	}
	if ext.PCEID != info.PCEID {
		return TCBStanding{}, fmt.Errorf("%w: tcb pceid mismatch (pck extension %x, tcb info %x)", ErrTCB, ext.PCEID, info.PCEID)
	}
	return lookupTCBLevel(&ext.TCB, info)
}

// lookupTCBLevel takes the first TCB level (Intel lists them newest first)
// that the platform's components and PCESVN all reach. Up to date and
// software-hardening-needed levels are acceptable; any other status, or
// no level at all, is not.
func lookupTCBLevel(tcb *PCKTCB, info *TCBInfo) (TCBStanding, error) {
	for _, level := range info.TCBLevels {
		if !inTCBLevel(&level, tcb) {
			continue
		}
		switch level.Status {
		case TCBUpToDate:
			return TCBStanding{}, nil
		case TCBSWHardeningNeeded:
			return TCBStanding{SWHardeningNeeded: true, AdvisoryIDs: level.AdvisoryIDs}, nil
		default:
			return TCBStanding{}, fmt.Errorf("%w: invalid tcb status: %s", ErrTCB, level.Status)
		}
	}
	return TCBStanding{}, fmt.Errorf("%w: unsupported TCB in pck extension", ErrTCB)
}

func inTCBLevel(level *TCBLevel, tcb *PCKTCB) bool {
	for i, c := range tcb.CompSVN {
		if c < level.Components[i] {
			return false
		}
	}
	return tcb.PCESVN >= level.PCESVN
}

// verifyClaimsHash checks that the ISV report data is the SHA-256 of the
// custom claims followed by zeros.
func verifyClaimsHash(ev *Evidence) error {
	data := ev.Quote.Body.ReportBody().ReportData()
	if [32]byte(data[32:]) != [32]byte{} {
		return fmt.Errorf("%w: report data hash had unexpected data", ErrClaims)
	}
	sum := ev.Claims.DataSHA256()
	if !bytes.Equal(sum[:], data[:32]) {
		return fmt.Errorf("%w: custom claims hash mismatch", ErrClaims)
	}
	// Open Enclave lets hosts request a valid report with all-zero report
	// data; claims that hash to zero must not pass as that.
	if [32]byte(data[:32]) == [32]byte{} {
		return fmt.Errorf("%w: valid claims sha256 is all zeros, rejecting", ErrClaims)
	}
	return nil
}

// AttestationMetrics returns the validity timestamps (Unix seconds) of the
// evidence's and endorsements' certificates, CRLs and collateral, without
// verifying anything. A CRL without next update reports 0.
func AttestationMetrics(evidence, endorsements []byte) (map[string]int64, error) {
	ev, err := ParseEvidence(evidence)
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}
	en, err := ParseEndorsements(endorsements)
	if err != nil {
		return nil, fmt.Errorf("endorsements: %w", err)
	}
	unix := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}
		return t.Unix()
	}
	pck := ev.Quote.Support.PCKCertChain.Leaf()
	tcb := en.TCBIssuerChain
	pckCRL, rootCRL := en.PCKIssuerCRL.CRL(), en.RootCRL.CRL()
	return map[string]int64{
		"pck_not_before_ts":         pck.NotBefore.Unix(),
		"pck_not_after_ts":          pck.NotAfter.Unix(),
		"tcb_signer_not_before_ts":  tcb.Leaf().NotBefore.Unix(),
		"tcb_signer_not_after_ts":   tcb.Leaf().NotAfter.Unix(),
		"root_not_before_ts":        tcb.Root().NotBefore.Unix(),
		"root_not_after_ts":         tcb.Root().NotAfter.Unix(),
		"pck_crl_last_update_ts":    unix(pckCRL.ThisUpdate),
		"pck_crl_next_update_ts":    unix(pckCRL.NextUpdate),
		"root_crl_last_update_ts":   unix(rootCRL.ThisUpdate),
		"root_crl_next_update_ts":   unix(rootCRL.NextUpdate),
		"tcb_info_expiration_ts":    en.TCBInfo.NextUpdate.Unix(),
		"qe_identity_expiration_ts": en.QEIdentity.NextUpdate.Unix(),
	}, nil
}
