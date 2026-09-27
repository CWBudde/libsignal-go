// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package devicetransfer_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/devicetransfer"
)

// FuzzGenerateCertificate parses arbitrary bytes as the private key
// (PKCS#8, PKCS#1 or SEC 1 DER) a device-transfer certificate is made for. It
// must never panic, and any certificate it returns must parse as X.509.
func FuzzGenerateCertificate(f *testing.F) {
	for _, name := range []string{"ec.key", "rsa.key"} {
		b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: fixed testdata file names
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{})
	now := time.Unix(1_700_000_000, 0)

	f.Fuzz(func(t *testing.T, key []byte) {
		der, err := devicetransfer.GenerateCertificate(key, "fuzz", 10, now)
		if err != nil {
			return
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			t.Fatalf("generated certificate does not parse: %v", err)
		}
	})
}
