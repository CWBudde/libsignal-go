// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package enclave_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/attest/enclave"
)

// readTestdata reads a recorded blob of upstream's rust/attest/tests/data,
// kept once in attest/dcap/testdata.
func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "dcap", "testdata", name)) //nolint:gosec // G304: fixed testdata file names
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hexFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := hex.DecodeString(string(bytes.TrimSpace(readTestdata(t, name))))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

// sgx_session.rs testutil.
var (
	// validStart is when the cds2_test PCK CRL becomes valid; the collateral
	// lasts 30 days.
	validStart = time.Unix(1655846111, 0)
	// testsDataTime is the time of handshake_from_tests_data.
	testsDataTime = time.UnixMilli(1655857680000)
)

func privateKey(t testing.TB) []byte { return hexFile(t, "cds2_test.privatekey") }

// publicKey is the enclave key the cds2_test attestation claims: the K of
// NK.
func publicKey(t testing.TB) []byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(privateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

func sgxHandshake(t testing.TB, now time.Time) (*enclave.Handshake, error) {
	t.Helper()
	return enclave.NewSGXHandshake(hexFile(t, "cds2_test.mrenclave"),
		readTestdata(t, "cds2_test.evidence"), readTestdata(t, "cds2_test.endorsements"),
		nil, now, enclave.PreQuantum)
}

// handshakeFromTestsData is testutil::handshake_from_tests_data.
func handshakeFromTestsData(t testing.TB) *enclave.Handshake {
	t.Helper()
	h, err := sgxHandshake(t, testsDataTime)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// cdsi is the recorded CDSI attestation of cds2.rs attest_cds2.
type cdsi struct {
	mrenclave, msg []byte
	now            time.Time
	advisories     []string
}

func loadCDSI(t testing.TB) cdsi {
	t.Helper()
	return cdsi{
		mrenclave:  readTestdata(t, "cdsi.mrenclave"),
		msg:        readTestdata(t, "cdsi.handshakestart"),
		now:        time.Unix(int64(binary.BigEndian.Uint64(readTestdata(t, "cdsi.timestamp"))), 0), //nolint:gosec // G115: recorded timestamp
		advisories: strings.Split(string(readTestdata(t, "cdsi.advisories")), "\n"),
	}
}
