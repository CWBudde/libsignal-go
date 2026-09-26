// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package noise

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"fmt"
	"io"
)

// Derandomize makes the responder's ekem1 encapsulation read its 32 bytes of
// randomness from the handshake's rand, as snow's resolver in the Rust harness
// does, so that known-answer tests reproduce message 1 byte for byte.
func Derandomize(hs *HandshakeState) {
	hs.encapsulate = func(ek *mlkem.EncapsulationKey1024, r io.Reader) ([]byte, []byte, error) {
		var m [32]byte
		if _, err := io.ReadFull(r, m[:]); err != nil {
			return nil, nil, fmt.Errorf("encapsulation randomness: %w", err)
		}
		return mlkemtest.Encapsulate1024(ek, m[:])
	}
}
