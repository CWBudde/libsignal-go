// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"crypto/x509"
	"errors"
	"slices"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// Ports of cert_chain.rs's tests.

func TestSortChain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		n       int
		shuffle func([]*x509.Certificate)
	}{
		{"sort_reversed", 5, slices.Reverse[[]*x509.Certificate]},
		{"sort_ordered", 5, func([]*x509.Certificate) {}},
		{"sort_unordered", 5, func(c []*x509.Certificate) {
			c[4], c[2] = c[2], c[4]
			c[0], c[3] = c[3], c[0]
		}},
		{"sort_small", 2, slices.Reverse[[]*x509.Certificate]},
		{"sort_singleton", 1, func([]*x509.Certificate) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain := certsOf(testChain(t, tc.n))
			want := names(chain)
			tc.shuffle(chain)
			if err := dcap.SortChain(chain); err != nil {
				t.Fatalf("chain should be valid: %v", err)
			}
			if got := names(chain); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestSortChainRejectsGaps(t *testing.T) {
	chain := certsOf(testChain(t, 4))
	if err := dcap.SortChain(slices.Delete(chain, 1, 2)); !errors.Is(err, dcap.ErrCertChain) {
		t.Fatalf("missing link: %v", err)
	}
	if _, err := dcap.NewCertChain(nil); !errors.Is(err, dcap.ErrCertChain) {
		t.Fatalf("empty chain: %v", err)
	}
	// No self-issued root.
	if err := dcap.SortChain(certsOf(testChain(t, 3))[:2]); !errors.Is(err, dcap.ErrCertChain) {
		t.Fatalf("rootless chain: %v", err)
	}
}

func TestNewChainFromUnsortedCerts(t *testing.T) {
	certs := certsOf(testChain(t, 5))
	want := names(certs)
	certs[4], certs[2] = certs[2], certs[4]
	certs[0], certs[3] = certs[3], certs[0]
	chain, err := dcap.NewCertChain(certs)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(chain.Certificates()); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// trustStore is upstream's test trust_store: CRL checks only with a CRL.
func trustStore(root *x509.Certificate, crl *dcap.RevocationList) *dcap.TrustStore {
	s := &dcap.TrustStore{Roots: []*x509.Certificate{root}}
	if crl != nil {
		s.CRLs, s.CheckCRLs = []*dcap.RevocationList{crl}, true
	}
	return s
}

func mustChain(t *testing.T, cs []*testCert) *dcap.CertChain {
	t.Helper()
	c, err := dcap.NewCertChain(certsOf(cs))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidateChain(t *testing.T) {
	t.Run("validate_valid_chain", func(t *testing.T) {
		c := mustChain(t, testChain(t, 4))
		if err := c.Validate(trustStore(c.Root(), nil), nil); err != nil {
			t.Fatalf("should validate: %v", err)
		}
	})
	t.Run("validate_invalid_chain", func(t *testing.T) {
		certs := certsOf(testChain(t, 4))
		root := certs[3]
		certs = slices.Delete(certs, 2, 3) // delete an intermediate certificate
		if err := dcap.UnsortedChain(certs).Validate(trustStore(root, nil), nil); err == nil {
			t.Fatal("chain with a missing intermediate validated")
		}
	})
	t.Run("validate_revoked_from_root", func(t *testing.T) {
		cs := testChain(t, 3)
		rootCRL := cs[2].crl(t, cs[1].cert.SerialNumber)
		intermediateCRL := cs[1].crl(t)
		err := mustChain(t, cs).Validate(trustStore(cs[2].cert, rootCRL), []*dcap.RevocationList{intermediateCRL})
		if !errors.Is(err, dcap.ErrRevoked) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("validate_revoked_from_intermediate", func(t *testing.T) {
		cs := testChain(t, 3)
		rootCRL := cs[2].crl(t)
		intermediateCRL := cs[1].crl(t, cs[0].cert.SerialNumber)
		err := mustChain(t, cs).Validate(trustStore(cs[2].cert, rootCRL), []*dcap.RevocationList{intermediateCRL})
		if !errors.Is(err, dcap.ErrRevoked) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("validate_other_revoked", func(t *testing.T) {
		cs := testChain(t, 3)
		rootCRL := cs[2].crl(t, serialNumber(t))
		intermediateCRL := cs[1].crl(t, serialNumber(t))
		if err := mustChain(t, cs).Validate(trustStore(cs[2].cert, rootCRL), []*dcap.RevocationList{intermediateCRL}); err != nil {
			t.Fatalf("should validate: %v", err)
		}
	})
	t.Run("validate_no_revoked", func(t *testing.T) {
		cs := testChain(t, 3)
		if err := mustChain(t, cs).Validate(trustStore(cs[2].cert, cs[2].crl(t)), []*dcap.RevocationList{cs[1].crl(t)}); err != nil {
			t.Fatalf("should validate: %v", err)
		}
	})
}

// Beyond upstream's tests: the BoringSSL behaviours the port emulates.
func TestValidateChainStore(t *testing.T) {
	cs := testChain(t, 3)
	chain := mustChain(t, cs)
	store := trustStore(cs[2].cert, cs[2].crl(t))
	if err := chain.Validate(store, nil); !errors.Is(err, dcap.ErrCRL) {
		t.Errorf("missing intermediate CRL: %v", err)
	}
	other := testChain(t, 1)[0]
	if err := chain.Validate(trustStore(other.cert, nil), nil); !errors.Is(err, dcap.ErrCertChain) {
		t.Errorf("untrusted root: %v", err)
	}
	// A CRL signed by the wrong key is not usable.
	forged := other.crl(t)
	if err := chain.Validate(store, []*dcap.RevocationList{forged}); !errors.Is(err, dcap.ErrCRL) {
		t.Errorf("foreign CRL: %v", err)
	}
	// A leaf whose signature does not verify under its issuer.
	raw := append([]byte(nil), cs[0].cert.Raw...)
	raw[len(raw)-5] ^= 1 // inside the signature BIT STRING
	forgedLeaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	bad := dcap.UnsortedChain([]*x509.Certificate{forgedLeaf, cs[1].cert, cs[2].cert})
	if err := bad.Validate(trustStore(cs[2].cert, nil), nil); !errors.Is(err, dcap.ErrCertChain) {
		t.Errorf("forged leaf signature: %v", err)
	}
	future := &dcap.TrustStore{Roots: store.Roots, Time: cs[0].cert.NotAfter.AddDate(0, 0, 1)}
	if err := chain.Validate(future, nil); !errors.Is(err, dcap.ErrCertChain) {
		t.Errorf("expired chain: %v", err)
	}
	if !chain.ValidAt(cs[0].cert.NotBefore) || chain.ValidAt(future.Time) {
		t.Error("ValidAt bounds")
	}
}

func TestRootTrustStore(t *testing.T) {
	root := testChain(t, 1)[0]
	crl := root.crl(t)
	if _, err := dcap.RootTrustStore(root.cert, crl, &root.key.PublicKey, root.cert.NotBefore); err != nil {
		t.Fatal(err)
	}
	other := testChain(t, 1)[0]
	if _, err := dcap.RootTrustStore(root.cert, crl, &other.key.PublicKey, root.cert.NotBefore); !errors.Is(err, dcap.ErrUntrustedKey) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := dcap.RootTrustStore(root.cert, other.crl(t), &root.key.PublicKey, root.cert.NotBefore); !errors.Is(err, dcap.ErrUntrustedKey) {
		t.Errorf("foreign root CRL: %v", err)
	}
	leaf := newTestCert(t, root, "leaf")
	if _, err := dcap.RootTrustStore(leaf.cert, crl, &root.key.PublicKey, root.cert.NotBefore); !errors.Is(err, dcap.ErrCertChain) {
		t.Errorf("not self-issued: %v", err)
	}
}
