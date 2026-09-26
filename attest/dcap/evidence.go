// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import (
	"crypto/sha256"
	"fmt"
	"time"
	"unicode/utf8"
)

// Limits from evidence.rs.
const (
	oeClaimsV1       = 1
	maxClaims        = 256
	maxClaimNameSize = 1024
	maxClaimValue    = 1024 * 1024
)

// Evidence is an Open Enclave evidence blob: an SGX quote followed by
// custom claims.
type Evidence struct {
	Quote  *Quote
	Claims *CustomClaims
}

// ParseEvidence parses evidence. Trailing data after the claims is an
// error.
func ParseEvidence(b []byte) (*Evidence, error) {
	q, rest, err := ParseQuote(b)
	if err != nil {
		return nil, fmt.Errorf("quote: %w", err)
	}
	claims, err := ParseCustomClaims(rest)
	if err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}
	return &Evidence{Quote: q, Claims: claims}, nil
}

// ValidAt reports whether the quote's PCK certificate chain is valid at t.
func (e *Evidence) ValidAt(t time.Time) bool { return e.Quote.ValidAt(t) }

// CustomClaims are Open Enclave custom claims (custom_claims.h).
type CustomClaims struct {
	// Map holds the claims by name, without a trailing NUL.
	Map  map[string][]byte
	data []byte
}

// ParseCustomClaims parses a complete custom claims buffer.
func ParseCustomClaims(b []byte) (*CustomClaims, error) {
	r := reader{b}
	version, ok1 := r.u64()
	num, ok2 := r.u64()
	if !ok1 || !ok2 {
		return nil, malformed("underflow")
	}
	if version != oeClaimsV1 {
		return nil, fmt.Errorf("%w: claims version %d", ErrUnsupported, version)
	}
	if num > maxClaims {
		return nil, malformed("too many custom claims")
	}
	claims := make(map[string][]byte, num)
	for range num {
		nameSize, ok1 := r.u64()
		valueSize, ok2 := r.u64()
		if !ok1 || !ok2 {
			return nil, malformed("underflow")
		}
		if nameSize > maxClaimNameSize {
			return nil, malformed("custom claim name too long")
		}
		if valueSize > maxClaimValue {
			return nil, malformed("custom claim value too long")
		}
		if uint64(len(r.b)) < nameSize+valueSize {
			return nil, malformed("underflow")
		}
		name, _ := r.bytes(int(nameSize))
		name = stripTrailingNull(name)
		if !utf8.Valid(name) {
			return nil, malformed("could not parse claims name to string")
		}
		value, _ := r.bytes(int(valueSize))
		claims[string(name)] = append([]byte(nil), value...)
	}
	if len(r.b) != 0 {
		return nil, malformed("unexpected extra data in buffer")
	}
	return &CustomClaims{Map: claims, data: b}, nil
}

// DataSHA256 returns SHA-256 of the serialized claims, which the report
// data commits to.
func (c *CustomClaims) DataSHA256() [32]byte { return sha256.Sum256(c.data) }
