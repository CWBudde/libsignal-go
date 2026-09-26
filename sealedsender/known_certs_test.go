package sealedsender

import (
	"encoding/base64"
	"testing"

	"github.com/cwbudde/libsignal-go/curve"
)

// TestKnownServerCertificates checks the table against the trust roots
// upstream lists next to it.
func TestKnownServerCertificates(t *testing.T) {
	roots := map[uint32]string{
		2:          "BYhU6tPjqP46KGZEzRs1OL4U39V5dlPJ/X09ha4rErkm",
		3:          "BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6",
		0x7357C357: "BS/lfaNHzWJDFSjarF+7KQcw//aEr8TPwu2QmV9Yyzt0",
	}
	certs := knownServerCertificates()
	if len(certs) != len(roots) {
		t.Fatalf("%d known certificates, want %d", len(certs), len(roots))
	}
	for id, root := range roots {
		raw, err := base64.StdEncoding.DecodeString(root)
		if err != nil {
			t.Fatal(err)
		}
		key, err := curve.DeserializePublicKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		cert := certs[id]
		if cert == nil || cert.KeyID() != id || !cert.Validate(key) {
			t.Errorf("known certificate %#x does not validate under its trust root", id)
		}
	}

	// A sender certificate that references a known signer resolves it.
	byID := &SenderCertificate{signerID: new(uint32)}
	*byID.signerID = 3
	if signer, err := byID.ResolvedSigner(); err != nil || signer != certs[3] {
		t.Errorf("ResolvedSigner(3) = %v, %v", signer, err)
	}
	*byID.signerID = 99
	if _, err := byID.ResolvedSigner(); err == nil {
		t.Error("ResolvedSigner accepted an unknown id")
	}
}
