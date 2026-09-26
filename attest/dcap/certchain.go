// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "crypto/sha256" // hashes for certificate signatures
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// intelRootPubKey is the uncompressed P-256 key of Intel's SGX root CA,
// which signs all DCAP root certificates and root CRLs (dcap.rs).
var intelRootPubKey = []byte{
	0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda,
	0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25,
	0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a,
	0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73,
	0x94,
}

// IntelRootKey returns Intel's pinned SGX root public key.
func IntelRootKey() *ecdsa.PublicKey {
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), intelRootPubKey)
	if err != nil {
		panic("dcap: pinned Intel root key: " + err.Error())
	}
	return k
}

// maxChainLen bounds path building.
const maxChainLen = 16

// CertChain is a certificate chain ordered from leaf to root, each
// certificate issued by the next (cert_chain.rs).
type CertChain struct {
	certs []*x509.Certificate
}

// ParseCertChainPEM parses the CERTIFICATE blocks of PEM data (other
// blocks and surrounding text are skipped) and sorts them.
func ParseCertChainPEM(data []byte) (*CertChain, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, malformed("certificate: %v", err)
		}
		certs = append(certs, c)
	}
	return NewCertChain(certs)
}

// NewCertChain sorts certs from leaf to root. It fails if the chain has no
// self-issued root or has missing or extra links.
func NewCertChain(certs []*x509.Certificate) (*CertChain, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: empty chain", ErrCertChain)
	}
	certs = append([]*x509.Certificate(nil), certs...)
	if err := sortChain(certs); err != nil {
		return nil, err
	}
	return &CertChain{certs: certs}, nil
}

// sortChain is upstream's CertChain::sort: move the last self-issued
// certificate to the end, then, walking backwards, place the certificate
// each one issued just before it.
func sortChain(certs []*x509.Certificate) error {
	errInvalid := fmt.Errorf("%w: invalid certificate chain", ErrCertChain)
	root := -1
	for i := len(certs) - 1; i >= 0; i-- {
		if issued(certs[i], certs[i]) {
			root = i
			break
		}
	}
	if root < 0 {
		return errInvalid
	}
	end := len(certs) - 1
	certs[end], certs[root] = certs[root], certs[end]
	for curr := len(certs) - 1; curr >= 1; curr-- {
		next := -1
		for i := curr - 1; i >= 0; i-- {
			if issued(certs[curr], certs[i]) {
				next = i
				break
			}
		}
		if next < 0 {
			return errInvalid
		}
		certs[curr-1], certs[next] = certs[next], certs[curr-1]
	}
	return nil
}

// issued follows BoringSSL's X509_check_issued: the names match, the
// subject's authority key ID (if any) matches the issuer's subject key ID
// (if any), and the issuer may sign certificates if it has key usage.
// Signatures are not checked here.
func issued(issuer, subject *x509.Certificate) bool {
	if !bytes.Equal(issuer.RawSubject, subject.RawIssuer) {
		return false
	}
	if len(subject.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 &&
		!bytes.Equal(subject.AuthorityKeyId, issuer.SubjectKeyId) {
		return false
	}
	return issuer.KeyUsage == 0 || issuer.KeyUsage&x509.KeyUsageCertSign != 0
}

// Leaf returns the first certificate.
func (c *CertChain) Leaf() *x509.Certificate { return c.certs[0] }

// Root returns the last, self-issued certificate.
func (c *CertChain) Root() *x509.Certificate { return c.certs[len(c.certs)-1] }

// Certificates returns the chain, leaf first.
func (c *CertChain) Certificates() []*x509.Certificate {
	return append([]*x509.Certificate(nil), c.certs...)
}

// LeafPublicKey returns the leaf's ECDSA key.
func (c *CertChain) LeafPublicKey() (*ecdsa.PublicKey, error) {
	k, ok := c.Leaf().PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: leaf key is not ECDSA", ErrCertChain)
	}
	return k, nil
}

// ValidAt reports whether every certificate is valid at t (bounds
// inclusive).
func (c *CertChain) ValidAt(t time.Time) bool {
	for _, cert := range c.certs {
		if t.Before(cert.NotBefore) || t.After(cert.NotAfter) {
			return false
		}
	}
	return true
}

// TrustStore holds trusted certificates and CRLs, like the BoringSSL
// X509Store upstream builds.
type TrustStore struct {
	// Roots are the trust anchors.
	Roots []*x509.Certificate
	// CRLs are trusted CRLs, used together with the chain's own.
	CRLs []*RevocationList
	// CheckCRLs requires a CRL from the issuer of every certificate on the
	// path, the root included (CRL_CHECK | CRL_CHECK_ALL).
	CheckCRLs bool
	// Time is the verification time; zero means now.
	Time time.Time
}

// NewTrustStore is upstream's from_trusted: previously validated
// certificates and CRLs, with CRL checks for every certificate, at now.
func NewTrustStore(roots []*x509.Certificate, crls []*RevocationList, now time.Time) *TrustStore {
	return &TrustStore{Roots: roots, CRLs: crls, CheckCRLs: true, Time: now}
}

// RootTrustStore is upstream's root_trust_store: root must be self-issued
// and, like rootCRL, signed by rootKey (normally IntelRootKey).
func RootTrustStore(root *x509.Certificate, rootCRL *RevocationList, rootKey *ecdsa.PublicKey, now time.Time) (*TrustStore, error) {
	if !issued(root, root) {
		return nil, fmt.Errorf("%w: invalid root certificate (not self signed)", ErrCertChain)
	}
	if !verifyWithKey(rootKey, root.SignatureAlgorithm, root.RawTBSCertificate, root.Signature) {
		return nil, fmt.Errorf("%w: root certificate", ErrUntrustedKey)
	}
	crl := rootCRL.crl
	if !verifyWithKey(rootKey, crl.SignatureAlgorithm, crl.RawTBSRevocationList, crl.Signature) {
		return nil, fmt.Errorf("%w: root CRL", ErrUntrustedKey)
	}
	return NewTrustStore([]*x509.Certificate{root}, []*RevocationList{rootCRL}, now), nil
}

func verifyWithKey(key *ecdsa.PublicKey, algo x509.SignatureAlgorithm, signed, sig []byte) bool {
	var h crypto.Hash
	switch algo {
	case x509.ECDSAWithSHA256:
		h = crypto.SHA256
	case x509.ECDSAWithSHA384:
		h = crypto.SHA384
	case x509.ECDSAWithSHA512:
		h = crypto.SHA512
	default:
		return false
	}
	d := h.New()
	d.Write(signed)
	return ecdsa.VerifyASN1(key, d.Sum(nil), sig)
}

// Validate checks that the chain's leaf leads to a root in store: every
// link issued and signed by the next certificate, issuers being CAs within
// their path length, no unhandled critical extensions, every certificate
// (the trust anchor included) valid at the store's time and, with
// CheckCRLs, not revoked according to its issuer's CRL from store.CRLs or
// crls. The trust anchor's self-signature is not checked, as in BoringSSL.
func (c *CertChain) Validate(store *TrustStore, crls []*RevocationList) error {
	now := store.Time
	if now.IsZero() {
		now = time.Now()
	}
	path, err := c.buildPath(store)
	if err != nil {
		return err
	}
	for i, cert := range path {
		if len(cert.UnhandledCriticalExtensions) > 0 {
			return fmt.Errorf("%w: unhandled critical extension at depth %d", ErrCertChain, i)
		}
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("%w: certificate at depth %d not valid at %s", ErrCertChain, i, now.UTC())
		}
		if i == 0 {
			continue
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return fmt.Errorf("%w: issuer at depth %d is not a CA", ErrCertChain, i)
		}
		// i-1 intermediates below this one, not counting self-issued ones.
		if cert.MaxPathLen >= 0 && (cert.MaxPathLen > 0 || cert.MaxPathLenZero) && i-1 > cert.MaxPathLen {
			return fmt.Errorf("%w: path length constraint at depth %d", ErrCertChain, i)
		}
		if err := path[i-1].CheckSignatureFrom(cert); err != nil {
			return fmt.Errorf("%w: signature at depth %d: %w", ErrCertChain, i-1, err)
		}
	}
	if !store.CheckCRLs {
		return nil
	}
	all := append(append([]*RevocationList(nil), store.CRLs...), crls...)
	for i, cert := range path {
		issuer := cert
		if i+1 < len(path) {
			issuer = path[i+1]
		}
		if err := checkRevocation(cert, issuer, all, now); err != nil {
			return fmt.Errorf("depth %d: %w", i, err)
		}
	}
	return nil
}

// buildPath walks from the leaf, preferring a trusted issuer at each step
// (trusted-first), until it reaches a trust anchor.
func (c *CertChain) buildPath(store *TrustStore) ([]*x509.Certificate, error) {
	cur := c.Leaf()
	path := []*x509.Certificate{cur}
	for len(path) <= maxChainLen {
		for _, root := range store.Roots {
			if root.Equal(cur) {
				return path, nil
			}
		}
		for _, root := range store.Roots {
			if issued(root, cur) {
				return append(path, root), nil
			}
		}
		if issued(cur, cur) {
			return nil, fmt.Errorf("%w: self-signed certificate not in the trust store", ErrCertChain)
		}
		var next *x509.Certificate
		for _, cand := range c.certs {
			if cand != cur && issued(cand, cur) && !contains(path, cand) {
				next = cand
				break
			}
		}
		if next == nil {
			return nil, fmt.Errorf("%w: unable to get issuer certificate", ErrCertChain)
		}
		path = append(path, next)
		cur = next
	}
	return nil, fmt.Errorf("%w: chain too long", ErrCertChain)
}

func contains(certs []*x509.Certificate, c *x509.Certificate) bool {
	for _, x := range certs {
		if x == c {
			return true
		}
	}
	return false
}

// checkRevocation finds the issuer's CRL among crls and checks cert
// against it. Like BoringSSL it prefers a CRL that verifies and is current,
// and reports why the best candidate failed otherwise.
func checkRevocation(cert, issuer *x509.Certificate, crls []*RevocationList, now time.Time) error {
	found := fmt.Errorf("%w: unable to get CRL", ErrCRL)
	for _, rl := range crls {
		crl := rl.crl
		if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
			continue
		}
		if err := checkCRL(crl, issuer, now); err != nil {
			found = err
			continue
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("%w: serial %s", ErrRevoked, cert.SerialNumber)
			}
		}
		return nil
	}
	return found
}

func checkCRL(crl *x509.RevocationList, issuer *x509.Certificate, now time.Time) error {
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("%w: issuer may not sign CRLs", ErrCRL)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("%w: signature: %w", ErrCRL, err)
	}
	if now.Before(crl.ThisUpdate) {
		return fmt.Errorf("%w: CRL not yet valid", ErrCRL)
	}
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return fmt.Errorf("%w: CRL has expired", ErrCRL)
	}
	return nil
}
