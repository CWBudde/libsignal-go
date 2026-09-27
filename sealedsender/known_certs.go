package sealedsender

import (
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/cwbudde/libsignal-go/curve"
)

// knownServerCertificateHex are the server certificates a SenderCertificate may
// reference by key id instead of embedding (KNOWN_SERVER_CERTIFICATES in
// sealed_sender.rs): 2 is used by the staging service, 3 by production, and
// 0x7357C357 is a test certificate signed by an all-zero private key.
var knownServerCertificateHex = map[uint32]string{
	2:          "0a25080212210539450d63ebd0752c0fd4038b9d07a916f5e174b756d409b5ca79f4c97400631e124064c5a38b1e927497d3d4786b101a623ab34a7da3954fae126b04dba9d7a3604ed88cdc8550950f0d4a9134ceb7e19b94139151d2c3d6e1c81e9d1128aafca806",
	3:          "0a250803122105bc9d1d290be964810dfa7e94856480a3f7060d004c9762c24c575a1522353a5a1240c11ec3c401eb0107ab38f8600e8720a63169e0e2eb8a3fae24f63099f85ea319c3c1c46d3454706ae2a679d1fee690a488adda98a2290b66c906bb60295ed781",
	0x7357C357: "0a2908d786df9a07122105847c0d2c375234f365e660955187a3735a0f7613d1609d3a6a4d8c53aeaa5a221240e0b9ebacdfc3aa2827f7924b697784d1c25e44ca05dd433e1a38dc6382eb2730d419ca9a250b1be9d5a9463e61efd6781777a91b83c97b844d014206e2829785",
}

var knownServerCertificates = sync.OnceValue(func() map[uint32]*ServerCertificate {
	out := make(map[uint32]*ServerCertificate, len(knownServerCertificateHex))
	for id, h := range knownServerCertificateHex {
		raw, err := hex.DecodeString(h)
		if err != nil {
			panic(fmt.Sprintf("sealedsender: known server certificate %#x: %v", id, err))
		}
		cert, err := DeserializeServerCertificate(raw)
		if err != nil {
			panic(fmt.Sprintf("sealedsender: known server certificate %#x: %v", id, err))
		}
		out[id] = cert
	}
	return out
})

// ResolvedSigner returns the ServerCertificate that signed c: the embedded one,
// or the known certificate its key id references (SenderCertificate::signer).
// An unknown id returns ErrUnknownServerCertificateID.
func (c *SenderCertificate) ResolvedSigner() (*ServerCertificate, error) {
	if c.signer != nil {
		return c.signer, nil
	}
	if c.signerID == nil {
		return nil, fmt.Errorf("%w: sender certificate has no signer", ErrInvalidCertificate)
	}
	cert, ok := knownServerCertificates()[*c.signerID]
	if !ok {
		return nil, fmt.Errorf("%w: %#x", ErrUnknownServerCertificateID, *c.signerID)
	}
	return cert, nil
}

// ValidateWithTrustRoots is Validate for several trust roots: the signer must
// be signed by at least one of them. Every root is checked, so the time taken
// does not reveal which one matched (validate_with_trust_roots).
func (c *SenderCertificate) ValidateWithTrustRoots(trustRoots []curve.PublicKey, opts ...ValidateOption) (bool, error) {
	cfg := validateConfig{now: time.Now()}
	for _, opt := range opts {
		opt(&cfg)
	}
	signer, err := c.ResolvedSigner()
	if err != nil {
		return false, err
	}
	anyValid := false
	for _, root := range trustRoots {
		if signer.Validate(root) {
			anyValid = true
		}
	}
	if !anyValid {
		return false, nil
	}
	if !signer.PublicKey().VerifySignature(c.signature, c.certificate) {
		return false, nil
	}
	return !cfg.now.After(c.expiration), nil
}
