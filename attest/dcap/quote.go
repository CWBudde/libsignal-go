// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// Sizes of the fixed-layout structures (sgx_report_body.rs, sgx_quote.rs).
const (
	ReportBodySize      = 384
	QuoteBodySize       = 432
	signatureHeaderSize = 578
)

// ReportBody is an SGX enclave report body (sgx_report_body_t), kept as its
// wire bytes: signatures cover exactly these bytes.
type ReportBody [ReportBodySize]byte

// Offsets into ReportBody.
const (
	rbCPUSVN     = 0
	rbMiscSelect = 16
	rbAttributes = 48
	rbMREnclave  = 64
	rbMRSigner   = 128
	rbISVProdID  = 256
	rbISVSVN     = 258
	rbReportData = 320
)

// SGX attribute flags (the low 64 bits of the attributes).
const (
	FlagInited       uint64 = 1 << 0
	FlagDebug        uint64 = 1 << 1
	FlagMode64Bit    uint64 = 1 << 2
	FlagProvisionKey uint64 = 1 << 3
	FlagEInitToken   uint64 = 1 << 5
	FlagKSS          uint64 = 1 << 7
)

// CPUSVN returns the CPU security version.
func (r *ReportBody) CPUSVN() [16]byte { return [16]byte(r[rbCPUSVN:]) }

// MiscSelect returns the MISCSELECT field.
func (r *ReportBody) MiscSelect() uint32 {
	return binary.LittleEndian.Uint32(r[rbMiscSelect:])
}

// Attributes returns the 16-byte SGX attributes.
func (r *ReportBody) Attributes() [16]byte { return [16]byte(r[rbAttributes:]) }

// HasFlag reports whether all bits of flag are set in the attributes.
func (r *ReportBody) HasFlag(flag uint64) bool {
	return binary.LittleEndian.Uint64(r[rbAttributes:])&flag == flag
}

// MREnclave returns the enclave measurement.
func (r *ReportBody) MREnclave() [32]byte { return [32]byte(r[rbMREnclave:]) }

// MRSigner returns the hash of the enclave signer's key.
func (r *ReportBody) MRSigner() [32]byte { return [32]byte(r[rbMRSigner:]) }

// ISVProdID returns the product ID.
func (r *ReportBody) ISVProdID() uint16 { return binary.LittleEndian.Uint16(r[rbISVProdID:]) }

// ISVSVN returns the security version.
func (r *ReportBody) ISVSVN() uint16 { return binary.LittleEndian.Uint16(r[rbISVSVN:]) }

// ReportData returns the 64 bytes of user report data.
func (r *ReportBody) ReportData() [64]byte { return [64]byte(r[rbReportData:]) }

// QuoteBody is the v3 quote header followed by the ISV enclave report
// (sgx_quote_t up to the signature length), as wire bytes.
type QuoteBody [QuoteBodySize]byte

const (
	quoteV3          = 3
	signTypeECDSA256 = 2 // SgxAttestationAlgorithm::EcdsaP256
	certTypePCKChain = 5 // CertificationKeyType::PckCertChain
)

// Version returns the quote version.
func (q *QuoteBody) Version() uint16 { return binary.LittleEndian.Uint16(q[0:]) }

// SignType returns the attestation key type.
func (q *QuoteBody) SignType() uint16 { return binary.LittleEndian.Uint16(q[2:]) }

// QESVN returns the quoting enclave's security version.
func (q *QuoteBody) QESVN() uint16 { return binary.LittleEndian.Uint16(q[8:]) }

// PCESVN returns the provisioning certification enclave's security version.
func (q *QuoteBody) PCESVN() uint16 { return binary.LittleEndian.Uint16(q[10:]) }

// QEVendorID returns the quoting enclave vendor UUID.
func (q *QuoteBody) QEVendorID() [16]byte { return [16]byte(q[12:]) }

// ReportBody returns the ISV enclave report.
func (q *QuoteBody) ReportBody() *ReportBody { return (*ReportBody)(q[48:]) }

// Quote is an SGX v3 ECDSA quote.
type Quote struct {
	Body    QuoteBody
	Support QuoteSupport
}

// QuoteSupport is the ECDSA quote signature data (Intel A.4.4): the
// signatures, the quoting enclave's report and the PCK certificate chain.
type QuoteSupport struct {
	// ISVSignature signs Body with the attestation key.
	ISVSignature [64]byte
	// AttestPubKey is the raw x‖y P-256 attestation key.
	AttestPubKey [64]byte
	// QEReportBody is the quoting enclave's report.
	QEReportBody ReportBody
	// QEReportSignature signs QEReportBody with the PCK leaf key.
	QEReportSignature [64]byte
	// AuthData is hashed with AttestPubKey into the QE report data.
	AuthData []byte
	// PCKCertChain is the chain of the PCK certificate that signed the QE report.
	PCKCertChain *CertChain
	// PCKExtension is the SGX extension of the PCK leaf certificate.
	PCKExtension *PCKExtension
}

// ParseQuote reads a quote from the front of b and returns the rest.
// Like upstream, the signature length is only checked as a lower bound and
// the signature data is read from its own fields.
func ParseQuote(b []byte) (*Quote, []byte, error) {
	if len(b) < QuoteBodySize {
		return nil, nil, malformed("incorrect buffer size")
	}
	if v := binary.LittleEndian.Uint16(b); v != quoteV3 {
		return nil, nil, fmt.Errorf("%w: SGX quote version %d", ErrUnsupported, v)
	}
	q := &Quote{Body: QuoteBody(b[:QuoteBodySize])}
	if t := q.Body.SignType(); t != signTypeECDSA256 {
		return nil, nil, fmt.Errorf("%w: SGX attestation algorithm %d", ErrUnsupported, t)
	}
	r := reader{b[QuoteBodySize:]}
	sigLen, ok := r.u32()
	if !ok {
		return nil, nil, malformed("underflow reading signature length")
	}
	if uint64(len(r.b)) < uint64(sigLen) {
		return nil, nil, malformed("underflow reading signature")
	}
	if err := q.Support.read(&r); err != nil {
		return nil, nil, err
	}
	return q, r.b, nil
}

// ParseQuoteSupport reads the quote signature data on its own, returning
// the rest.
func ParseQuoteSupport(b []byte) (*QuoteSupport, []byte, error) {
	var s QuoteSupport
	r := reader{b}
	if err := s.read(&r); err != nil {
		return nil, nil, err
	}
	return &s, r.b, nil
}

func (s *QuoteSupport) read(r *reader) error {
	header, ok := r.bytes(signatureHeaderSize)
	if !ok {
		return malformed("incorrect buffer size")
	}
	s.ISVSignature = [64]byte(header[0:])
	s.AttestPubKey = [64]byte(header[64:])
	s.QEReportBody = ReportBody(header[128:])
	s.QEReportSignature = [64]byte(header[128+ReportBodySize:])
	authSize := binary.LittleEndian.Uint16(header[signatureHeaderSize-2:])
	if s.AuthData, ok = r.bytes(int(authSize)); !ok {
		return malformed("buffer underflow")
	}
	keyType, ok1 := r.u16()
	certSize, ok2 := r.u32()
	if !ok1 || !ok2 {
		return malformed("buffer underflow")
	}
	if keyType != certTypePCKChain {
		return fmt.Errorf("%w: certification key type %d", ErrUnsupported, keyType)
	}
	if uint64(len(r.b)) < uint64(certSize) {
		return malformed("remaining data does not match expected size")
	}
	pemData, _ := r.bytes(int(certSize))
	chain, err := ParseCertChainPEM(pemData)
	if err != nil {
		return fmt.Errorf("CertChain: %w", err)
	}
	s.PCKCertChain = chain
	ext, err := pckExtensionOf(chain.Leaf())
	if err != nil {
		return err
	}
	s.PCKExtension = ext
	return nil
}

// VerifySignature checks the ISV signature over the quote body with pub,
// normally the attestation key.
func (q *Quote) VerifySignature(pub *ecdsa.PublicKey) error {
	return verifyRawSignature(pub, q.Body[:], &q.Support.ISVSignature)
}

// ValidAt reports whether the PCK certificate chain is valid at t.
func (q *Quote) ValidAt(t time.Time) bool { return q.Support.PCKCertChain.ValidAt(t) }

// VerifySignature checks the QE report signature with pub, normally the PCK
// leaf certificate's key.
func (s *QuoteSupport) VerifySignature(pub *ecdsa.PublicKey) error {
	return verifyRawSignature(pub, s.QEReportBody[:], &s.QEReportSignature)
}

// AttestKey returns the quoting enclave's attestation key.
func (s *QuoteSupport) AttestKey() (*ecdsa.PublicKey, error) {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, s.AttestPubKey[:]...))
	if err != nil {
		return nil, malformed("attestation public key: %v", err)
	}
	return pub, nil
}

// VerifyQEReport checks that the QE report data is
// SHA-256(attestation key ‖ auth data) followed by 32 zero bytes.
func (s *QuoteSupport) VerifyQEReport() error {
	h := sha256.New()
	h.Write(s.AttestPubKey[:])
	h.Write(s.AuthData)
	data := s.QEReportBody.ReportData()
	if !bytes.Equal(h.Sum(nil), data[:32]) {
		return fmt.Errorf("%w: should be hash of attestation key and auth data", ErrQEReport)
	}
	if [32]byte(data[32:]) != [32]byte{} {
		return fmt.Errorf("%w: should be zero padded", ErrQEReport)
	}
	return nil
}
