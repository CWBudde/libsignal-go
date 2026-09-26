// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"
)

// TCBEvaluationDataNumberMin is the oldest TCB recovery event accepted in
// TCB info and QE identities (constants.rs SGX_TCB_EVALUATION_DATA_NUMBER_MIN).
const TCBEvaluationDataNumberMin = 21

// veryExpiredTestEvalNumber is the TCB evaluation data number of upstream's
// oldest recorded blobs (cds2_test, dcap_v3), which upstream accepts only
// under cfg(test) (endorsements.rs
// SGX_TCB_EVALUATION_NUMBER_USED_ONLY_IN_TESTS_THAT_WILL_NEVER_VALIDATE_SINCE_IT_IS_VERY_EXPIRED).
const veryExpiredTestEvalNumber = 12

// acceptVeryExpiredTestEvalNumber is set only by this package's tests
// (export_test.go); production builds never accept that number.
var acceptVeryExpiredTestEvalNumber bool

// evalNumberOK reports whether a TCB evaluation data number is recent enough.
func evalNumberOK(n uint16) bool {
	return n >= TCBEvaluationDataNumberMin ||
		(acceptVeryExpiredTestEvalNumber && n == veryExpiredTestEvalNumber)
}

// Open Enclave endorsements layout (oe_endorsements_t and
// oe_sgx_endorsements_fields_t, endorsements.rs).
const (
	oeEndorsementsV1 = 1
	oeEnclaveTypeSGX = 2
)

// Endorsement fields, in blob order.
const (
	fieldVersion = iota
	fieldTCBInfo
	fieldTCBIssuerChain
	fieldCRLPCKCert
	fieldCRLPCKProcCA
	fieldPCKCRLIssuerChain
	fieldQEIDInfo
	fieldQEIDIssuerChain
	fieldCreationDatetime
	numEndorsementFields
)

// Endorsements is the DCAP collateral for evidence (SgxEndorsements): TCB
// info and QE identity, both verified against their issuer chains, and the
// CRLs of the PCK chain.
type Endorsements struct {
	TCBInfo        *TCBInfo
	TCBIssuerChain *CertChain
	// PCKIssuerCRL is the CRL of the PCK certificate's issuer.
	PCKIssuerCRL *RevocationList
	// RootCRL is the Intel root CA's CRL (OE's CRL_PCK_PROC_CA).
	RootCRL *RevocationList
	// PCKIssuerCRLChain is the chain whose leaf issues PCKIssuerCRL.
	PCKIssuerCRLChain     *CertChain
	QEIdentity            *EnclaveIdentity
	QEIdentityIssuerChain *CertChain
}

// ParseEndorsements parses an Open Enclave SGX endorsements blob. The TCB
// info and QE identity signatures are checked against the leaf keys of
// their issuer chains; the chains themselves are checked by attestation.
func ParseEndorsements(b []byte) (*Endorsements, error) {
	r := reader{b}
	version, ok1 := r.u32()
	enclaveType, ok2 := r.u32()
	_, ok3 := r.u32() // buffer size
	num, ok4 := r.u32()
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, malformed("endorsements too short")
	}
	if version != oeEndorsementsV1 {
		return nil, fmt.Errorf("%w: endorsements version %d", ErrUnsupported, version)
	}
	if enclaveType != oeEnclaveTypeSGX {
		return nil, fmt.Errorf("%w: enclave type %d", ErrUnsupported, enclaveType)
	}
	if uint64(len(r.b)) < 4*uint64(num) {
		return nil, malformed("not enough data for offsets")
	}
	offsets := make([]int, num)
	for i := range offsets {
		off, _ := r.u32()
		offsets[i] = int(off)
	}
	data := r.b
	if err := validateOffsets(offsets, data); err != nil {
		return nil, err
	}
	field := func(i int) []byte {
		if i == len(offsets)-1 {
			return data[offsets[i]:]
		}
		return data[offsets[i]:offsets[i+1]]
	}

	if v := field(fieldVersion); len(v) != 4 {
		return nil, malformed("invalid SGX endorsement version field")
	} else if n := binary.LittleEndian.Uint32(v); n != oeEndorsementsV1 {
		return nil, fmt.Errorf("%w: SGX endorsement version %d", ErrUnsupported, n)
	}
	tcbInfo, tcbSig, err := splitSigned(stripTrailingNull(field(fieldTCBInfo)), "tcbInfo")
	if err != nil {
		return nil, fmt.Errorf("tcb info: %w", err)
	}
	var e Endorsements
	if e.TCBIssuerChain, err = ParseCertChainPEM(field(fieldTCBIssuerChain)); err != nil {
		return nil, fmt.Errorf("TcbIssuerChain: %w", err)
	}
	if e.PCKIssuerCRL, err = ParseRevocationList(field(fieldCRLPCKCert)); err != nil {
		return nil, fmt.Errorf("CrlPckCert: %w", err)
	}
	if e.RootCRL, err = ParseRevocationList(field(fieldCRLPCKProcCA)); err != nil {
		return nil, fmt.Errorf("CrlPckProcCa: %w", err)
	}
	if e.PCKIssuerCRLChain, err = ParseCertChainPEM(field(fieldPCKCRLIssuerChain)); err != nil {
		return nil, fmt.Errorf("PckCrlIssuerChain: %w", err)
	}
	key, err := e.TCBIssuerChain.LeafPublicKey()
	if err != nil {
		return nil, fmt.Errorf("tcb issuer chain: %w", err)
	}
	if e.TCBInfo, err = verifyTCBInfo(tcbInfo, tcbSig, key); err != nil {
		return nil, err
	}
	qeID, qeSig, err := splitSigned(stripTrailingNull(field(fieldQEIDInfo)), "enclaveIdentity")
	if err != nil {
		return nil, fmt.Errorf("quoting enclave identity info: %w", err)
	}
	if e.QEIdentityIssuerChain, err = ParseCertChainPEM(field(fieldQEIDIssuerChain)); err != nil {
		return nil, fmt.Errorf("QeIdIssuerChain: %w", err)
	}
	if key, err = e.QEIdentityIssuerChain.LeafPublicKey(); err != nil {
		return nil, fmt.Errorf("qe identity issuer chain: %w", err)
	}
	if e.QEIdentity, err = verifyEnclaveIdentity(qeID, qeSig, key); err != nil {
		return nil, err
	}
	if !utf8.Valid(stripTrailingNull(field(fieldCreationDatetime))) {
		return nil, malformed("CreationDatetime: invalid UTF-8")
	}
	return &e, nil
}

func validateOffsets(offsets []int, data []byte) error {
	if len(offsets) < numEndorsementFields {
		return malformed("too few fields")
	}
	if len(data) <= offsets[len(offsets)-1] {
		return malformed("data is too short for offsets")
	}
	for i := 1; i < len(offsets); i++ {
		if offsets[i] <= offsets[i-1] {
			return malformed("offsets are not strictly increasing")
		}
	}
	return nil
}

// ValidAt reports whether all chains, CRLs, the TCB info and the QE
// identity are valid at t.
func (e *Endorsements) ValidAt(t time.Time) bool {
	return e.QEIdentityIssuerChain.ValidAt(t) &&
		e.PCKIssuerCRLChain.ValidAt(t) &&
		e.TCBIssuerChain.ValidAt(t) &&
		e.TCBInfo.ValidAt(t) &&
		e.QEIdentity.ValidAt(t) &&
		e.PCKIssuerCRL.ValidAt(t) &&
		e.RootCRL.ValidAt(t)
}

// splitSigned reads {"<key>": <object>, "signature": "<hex r‖s>"} and
// returns the object's raw bytes, which the signature covers.
func splitSigned(data []byte, key string) (json.RawMessage, *[64]byte, error) {
	f := fieldsOf(key, "signature")
	if err := decodeObject(data, f); err != nil {
		return nil, nil, err
	}
	var sig [64]byte
	if err := decodeHex(f.get("signature"), sig[:], "signature"); err != nil {
		return nil, nil, err
	}
	return f.get(key), &sig, nil
}

func verifyTCBInfo(raw json.RawMessage, sig *[64]byte, key *ecdsa.PublicKey) (*TCBInfo, error) {
	if err := verifyRawSignature(key, raw, sig); err != nil {
		return nil, fmt.Errorf("tcb info: %w", err)
	}
	info, err := ParseTCBInfo(raw)
	if err != nil {
		return nil, fmt.Errorf("tcb info: %w", err)
	}
	for _, level := range info.TCBLevels {
		if level.Version != info.Version {
			return nil, malformed("mismatched tcb info versions, should all be %d", info.Version)
		}
	}
	if info.TCBType != 0 {
		return nil, fmt.Errorf("%w: tcb type %d", ErrUnsupported, info.TCBType)
	}
	return info, nil
}

func verifyEnclaveIdentity(raw json.RawMessage, sig *[64]byte, key *ecdsa.PublicKey) (*EnclaveIdentity, error) {
	if err := verifyRawSignature(key, raw, sig); err != nil {
		return nil, fmt.Errorf("enclave identity: %w", err)
	}
	id, err := ParseEnclaveIdentity(raw)
	if err != nil {
		return nil, fmt.Errorf("enclave identity: %w", err)
	}
	if id.Version != enclaveIdentityV2 {
		return nil, fmt.Errorf("%w: enclave identity version %d", ErrUnsupported, id.Version)
	}
	return id, nil
}

// TCBInfoVersion is the version of the TCB info JSON: 2 from the PCS v3
// API, 3 (with advisory IDs and a new TCB level layout) from v4.
type TCBInfoVersion uint16

// TCB info versions.
const (
	TCBInfoV2 TCBInfoVersion = 2
	TCBInfoV3 TCBInfoVersion = 3
)

// TCBInfo is Intel's TCB info for one platform model (FMSPC).
type TCBInfo struct {
	Version                 TCBInfoVersion
	IssueDate               time.Time
	NextUpdate              time.Time
	FMSPC                   [6]byte
	PCEID                   [2]byte
	TCBType                 uint16
	TCBEvaluationDataNumber uint16
	TCBLevels               []TCBLevel
}

// TCBLevel is one TCB level of the TCB info.
type TCBLevel struct {
	// Version is the layout the level was written in.
	Version     TCBInfoVersion
	Components  [16]uint8
	PCESVN      uint16
	Date        time.Time
	Status      TCBStatus
	AdvisoryIDs []string
}

// TCBStatus is the status of a TCB level.
type TCBStatus int

// TCB level statuses.
const (
	TCBUpToDate TCBStatus = iota
	TCBOutOfDate
	TCBConfigurationNeeded
	TCBSWHardeningNeeded
	TCBConfigurationAndSWHardeningNeeded
	TCBOutOfDateConfigurationNeeded
	TCBRevoked
)

var tcbStatuses = map[string]TCBStatus{
	"UpToDate":                          TCBUpToDate,
	"OutOfDate":                         TCBOutOfDate,
	"ConfigurationNeeded":               TCBConfigurationNeeded,
	"SWHardeningNeeded":                 TCBSWHardeningNeeded,
	"ConfigurationAndSWHardeningNeeded": TCBConfigurationAndSWHardeningNeeded,
	"OutOfDateConfigurationNeeded":      TCBOutOfDateConfigurationNeeded,
	"Revoked":                           TCBRevoked,
}

func (s TCBStatus) String() string {
	for name, v := range tcbStatuses {
		if v == s {
			return name
		}
	}
	return fmt.Sprintf("TCBStatus(%d)", int(s))
}

// ParseTCBInfo decodes the tcbInfo JSON object. It does not check the
// signature, the level layouts or the TCB type.
func ParseTCBInfo(data []byte) (*TCBInfo, error) {
	f := fieldsOf("version", "issueDate", "nextUpdate", "fmspc", "pceId", "tcbType",
		"tcbEvaluationDataNumber", "tcbLevels")
	if err := decodeObject(data, f); err != nil {
		return nil, err
	}
	var info TCBInfo
	v, err := decodeU16(f.get("version"), "version")
	if err != nil {
		return nil, err
	}
	info.Version = TCBInfoVersion(v)
	if info.Version != TCBInfoV2 && info.Version != TCBInfoV3 {
		return nil, fmt.Errorf("%w: TCB info version %d", ErrUnsupported, v)
	}
	if info.IssueDate, err = decodeTime(f.get("issueDate"), "issueDate"); err != nil {
		return nil, err
	}
	if info.NextUpdate, err = decodeTime(f.get("nextUpdate"), "nextUpdate"); err != nil {
		return nil, err
	}
	if err := decodeHex(f.get("fmspc"), info.FMSPC[:], "fmspc"); err != nil {
		return nil, err
	}
	if err := decodeHex(f.get("pceId"), info.PCEID[:], "pceId"); err != nil {
		return nil, err
	}
	if info.TCBType, err = decodeU16(f.get("tcbType"), "tcbType"); err != nil {
		return nil, err
	}
	if info.TCBEvaluationDataNumber, err = decodeU16(f.get("tcbEvaluationDataNumber"), "tcbEvaluationDataNumber"); err != nil {
		return nil, err
	}
	levels, err := decodeArray(f.get("tcbLevels"), "tcbLevels")
	if err != nil {
		return nil, err
	}
	info.TCBLevels = make([]TCBLevel, len(levels))
	for i, raw := range levels {
		if err := info.TCBLevels[i].decode(raw); err != nil {
			return nil, fmt.Errorf("tcbLevels[%d]: %w", i, err)
		}
	}
	return &info, nil
}

func (l *TCBLevel) decode(data []byte) error {
	f := fieldsOf("tcb", "tcbDate", "tcbStatus", "advisoryIDs")
	f["advisoryIDs"].optional = true
	if err := decodeObject(data, f); err != nil {
		return err
	}
	if err := l.decodeTCB(f.get("tcb")); err != nil {
		return err
	}
	var err error
	if l.Date, err = decodeTime(f.get("tcbDate"), "tcbDate"); err != nil {
		return err
	}
	if l.Status, err = decodeEnum(f.get("tcbStatus"), tcbStatuses, "tcbStatus"); err != nil {
		return err
	}
	l.AdvisoryIDs = []string{}
	if f.has("advisoryIDs") {
		ids, err := decodeArray(f.get("advisoryIDs"), "advisoryIDs")
		if err != nil {
			return err
		}
		for _, raw := range ids {
			id, err := decodeString(raw, "advisoryIDs")
			if err != nil {
				return err
			}
			l.AdvisoryIDs = append(l.AdvisoryIDs, id)
		}
	}
	return nil
}

// decodeTCB decodes the untagged Tcb enum: the v2 layout if it fits, else
// the v3 layout.
func (l *TCBLevel) decodeTCB(data []byte) error {
	errV2 := l.decodeTCBV2(data)
	if errV2 == nil {
		return nil
	}
	if errV3 := l.decodeTCBV3(data); errV3 != nil {
		return jsonErr("tcb: data did not match any variant (v2: %v; v3: %v)", errV2, errV3)
	}
	return nil
}

func (l *TCBLevel) decodeTCBV2(data []byte) error {
	keys := make([]string, 0, 17)
	for i := range 16 {
		keys = append(keys, fmt.Sprintf("sgxtcbcomp%02dsvn", i+1))
	}
	f := fieldsOf(append(keys, "pcesvn")...)
	if err := decodeObject(data, f); err != nil {
		return err
	}
	var comps [16]uint8
	for i, k := range keys {
		v, err := decodeU8(f.get(k), k)
		if err != nil {
			return err
		}
		comps[i] = v
	}
	pcesvn, err := decodeU16(f.get("pcesvn"), "pcesvn")
	if err != nil {
		return err
	}
	l.Version, l.Components, l.PCESVN = TCBInfoV2, comps, pcesvn
	return nil
}

func (l *TCBLevel) decodeTCBV3(data []byte) error {
	f := fieldsOf("sgxtcbcomponents", "pcesvn")
	if err := decodeObject(data, f); err != nil {
		return err
	}
	elems, err := decodeArray(f.get("sgxtcbcomponents"), "sgxtcbcomponents")
	if err != nil {
		return err
	}
	if len(elems) != 16 {
		return jsonErr("sgxtcbcomponents: want 16 elements, got %d", len(elems))
	}
	var comps [16]uint8
	for i, raw := range elems {
		c := fieldsOf("svn")
		if err := decodeObject(raw, c); err != nil {
			return err
		}
		if comps[i], err = decodeU8(c.get("svn"), "svn"); err != nil {
			return err
		}
	}
	pcesvn, err := decodeU16(f.get("pcesvn"), "pcesvn")
	if err != nil {
		return err
	}
	l.Version, l.Components, l.PCESVN = TCBInfoV3, comps, pcesvn
	return nil
}

// ValidAt reports whether t is not after NextUpdate and the TCB
// evaluation data number is recent enough. The issue date is ignored: it
// may be very recent, and clocks skew.
func (i *TCBInfo) ValidAt(t time.Time) bool {
	return evalNumberOK(i.TCBEvaluationDataNumber) && !t.After(i.NextUpdate)
}

const enclaveIdentityV2 = 2

// EnclaveType is the kind of enclave an identity describes.
type EnclaveType int

// Enclave types.
const (
	EnclaveQE  EnclaveType = iota // quoting enclave
	EnclaveQVE                    // quote verification enclave
)

var enclaveTypes = map[string]EnclaveType{"QE": EnclaveQE, "QVE": EnclaveQVE}

// EnclaveIdentity is Intel's identity of the quoting enclave.
type EnclaveIdentity struct {
	ID                      EnclaveType
	Version                 uint16
	IssueDate               time.Time
	NextUpdate              time.Time
	TCBEvaluationDataNumber uint16
	// MiscSelect and MiscSelectMask are the hex bytes read little-endian,
	// like the report's MISCSELECT.
	MiscSelect     uint32
	MiscSelectMask uint32
	Attributes     [16]byte
	AttributesMask [16]byte
	MRSigner       [32]byte
	ISVProdID      uint16
	TCBLevels      []QETCBLevel
}

// QETCBLevel is one TCB level of an enclave identity.
type QETCBLevel struct {
	ISVSVN uint16
	Date   time.Time
	Status QETCBStatus
}

// QETCBStatus is the status of an enclave identity TCB level, a subset of
// TCBStatus.
type QETCBStatus int

// Enclave identity TCB level statuses.
const (
	QEUpToDate QETCBStatus = iota
	QEOutOfDate
	QERevoked
)

var qeTCBStatuses = map[string]QETCBStatus{
	"UpToDate": QEUpToDate, "OutOfDate": QEOutOfDate, "Revoked": QERevoked,
}

func (s QETCBStatus) String() string {
	for name, v := range qeTCBStatuses {
		if v == s {
			return name
		}
	}
	return fmt.Sprintf("QETCBStatus(%d)", int(s))
}

// ParseEnclaveIdentity decodes the enclaveIdentity JSON object. It does
// not check the signature or the version.
func ParseEnclaveIdentity(data []byte) (*EnclaveIdentity, error) {
	f := fieldsOf("id", "version", "issueDate", "nextUpdate", "tcbEvaluationDataNumber",
		"miscselect", "miscselectMask", "attributes", "attributesMask", "mrsigner",
		"isvprodid", "tcbLevels")
	if err := decodeObject(data, f); err != nil {
		return nil, err
	}
	var id EnclaveIdentity
	var err error
	if id.ID, err = decodeEnum(f.get("id"), enclaveTypes, "id"); err != nil {
		return nil, err
	}
	if id.Version, err = decodeU16(f.get("version"), "version"); err != nil {
		return nil, err
	}
	if id.IssueDate, err = decodeTime(f.get("issueDate"), "issueDate"); err != nil {
		return nil, err
	}
	if id.NextUpdate, err = decodeTime(f.get("nextUpdate"), "nextUpdate"); err != nil {
		return nil, err
	}
	if id.TCBEvaluationDataNumber, err = decodeU16(f.get("tcbEvaluationDataNumber"), "tcbEvaluationDataNumber"); err != nil {
		return nil, err
	}
	var misc, mask [4]byte
	if err := decodeHex(f.get("miscselect"), misc[:], "miscselect"); err != nil {
		return nil, err
	}
	if err := decodeHex(f.get("miscselectMask"), mask[:], "miscselectMask"); err != nil {
		return nil, err
	}
	id.MiscSelect = binary.LittleEndian.Uint32(misc[:])
	id.MiscSelectMask = binary.LittleEndian.Uint32(mask[:])
	if err := decodeHex(f.get("attributes"), id.Attributes[:], "attributes"); err != nil {
		return nil, err
	}
	if err := decodeHex(f.get("attributesMask"), id.AttributesMask[:], "attributesMask"); err != nil {
		return nil, err
	}
	if err := decodeHex(f.get("mrsigner"), id.MRSigner[:], "mrsigner"); err != nil {
		return nil, err
	}
	if id.ISVProdID, err = decodeU16(f.get("isvprodid"), "isvprodid"); err != nil {
		return nil, err
	}
	levels, err := decodeArray(f.get("tcbLevels"), "tcbLevels")
	if err != nil {
		return nil, err
	}
	id.TCBLevels = make([]QETCBLevel, len(levels))
	for i, raw := range levels {
		if err := id.TCBLevels[i].decode(raw); err != nil {
			return nil, fmt.Errorf("tcbLevels[%d]: %w", i, err)
		}
	}
	return &id, nil
}

func (l *QETCBLevel) decode(data []byte) error {
	f := fieldsOf("tcb", "tcbDate", "tcbStatus")
	if err := decodeObject(data, f); err != nil {
		return err
	}
	tcb := fieldsOf("isvsvn")
	if err := decodeObject(f.get("tcb"), tcb); err != nil {
		return err
	}
	var err error
	if l.ISVSVN, err = decodeU16(tcb.get("isvsvn"), "isvsvn"); err != nil {
		return err
	}
	if l.Date, err = decodeTime(f.get("tcbDate"), "tcbDate"); err != nil {
		return err
	}
	l.Status, err = decodeEnum(f.get("tcbStatus"), qeTCBStatuses, "tcbStatus")
	return err
}

// TCBStatus returns the status of the first level (levels are in
// descending ISVSVN order) whose ISVSVN is at most reportISVSVN, or
// QERevoked if there is none.
func (id *EnclaveIdentity) TCBStatus(reportISVSVN uint16) QETCBStatus {
	for _, level := range id.TCBLevels {
		if level.ISVSVN <= reportISVSVN {
			return level.Status
		}
	}
	return QERevoked
}

// ValidAt reports whether t is not after NextUpdate and the TCB
// evaluation data number is recent enough.
func (id *EnclaveIdentity) ValidAt(t time.Time) bool {
	return evalNumberOK(id.TCBEvaluationDataNumber) && !t.After(id.NextUpdate)
}
