// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768incr

import (
	"bytes"
	"testing"
)

// fuzzKey is one incremental key and a phase-1 encapsulation to it, built
// once per fuzz target so the targets never generate keys per input.
type fuzzKey struct {
	key *IncrementalKey
	enc *EncapsulationResult
	ct2 []byte
}

func newFuzzKey(f *testing.F) fuzzKey {
	f.Helper()
	seed := bytes.Repeat([]byte{0x5A}, 64)
	key, err := GenerateIncrementalKey(seed)
	if err != nil {
		f.Fatal(err)
	}
	var m [messageBytes]byte
	m[0] = 1
	enc, err := Encapsulate1Internal(key.PK1, &m)
	if err != nil {
		f.Fatal(err)
	}
	ct2, err := Encapsulate2(enc.EncapsState, key.PK2)
	if err != nil {
		f.Fatal(err)
	}
	return fuzzKey{key: key, enc: enc, ct2: ct2}
}

// FuzzNewEncapsulationKey768 parses arbitrary bytes as a standard ML-KEM-768
// encapsulation key. It must never panic, and an accepted key must serialize
// back to the same bytes (the encoding is canonical: ByteDecode₁₂ rejects
// coefficients >= q).
func FuzzNewEncapsulationKey768(f *testing.F) {
	k := newFuzzKey(f)
	ek := append(bytes.Clone(k.key.PK2), k.key.PK1[:32]...)
	f.Add(ek)
	f.Add(bytes.Repeat([]byte{0xFF}, EncapsulationKeySize768))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		key, err := NewEncapsulationKey768(b)
		if err != nil {
			return
		}
		if !bytes.Equal(key.Bytes(), b) {
			t.Fatal("encapsulation key does not round-trip")
		}
	})
}

// FuzzIncrementalPublicKey feeds a peer's header (pk1) and chunked key (pk2),
// the two halves SPQR receives in chunks, to the validation and both
// encapsulation phases. None may panic, and an accepted pair must encapsulate.
func FuzzIncrementalPublicKey(f *testing.F) {
	k := newFuzzKey(f)
	f.Add(k.key.PK1, k.key.PK2)
	f.Add(k.key.PK1, bytes.Repeat([]byte{0xFF}, PublicKey2Size))
	f.Add(make([]byte, PublicKey1Size), make([]byte, PublicKey2Size))
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, pk1, pk2 []byte) {
		valid := ValidatePublicKeyParts(pk1, pk2) == nil
		var m [messageBytes]byte
		enc, err := Encapsulate1Internal(pk1, &m)
		if err != nil {
			return
		}
		if len(enc.Ciphertext1) != Ciphertext1Size || len(enc.EncapsState) != EncapsStateSize {
			t.Fatalf("phase 1 output sizes %d/%d", len(enc.Ciphertext1), len(enc.EncapsState))
		}
		ct2, err := Encapsulate2(enc.EncapsState, pk2)
		if valid && err != nil {
			t.Fatalf("validated key failed phase 2: %v", err)
		}
		if err == nil && len(ct2) != Ciphertext2Size {
			t.Fatalf("phase 2 output size %d", len(ct2))
		}
	})
}

// FuzzEncapsState feeds a stored phase-1 state (which may carry libcrux's
// byte-swapped encoding, cryspen/libcrux#1275) to the endianness repair and to
// phase 2. Neither may panic, and the repair must keep the length.
func FuzzEncapsState(f *testing.F) {
	k := newFuzzKey(f)
	f.Add(k.enc.EncapsState)
	f.Add(make([]byte, EncapsStateSize))
	f.Add(bytes.Repeat([]byte{0x01, 0x00}, EncapsStateSize/2))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, state []byte) {
		fixed, err := FixEncapsStateEndianness(state)
		if err != nil {
			return
		}
		if len(fixed) != len(state) {
			t.Fatalf("repair changed the length from %d to %d", len(state), len(fixed))
		}
		_, _ = Encapsulate2(fixed, k.key.PK2)
	})
}

// FuzzDecapsulateCompressedKey decapsulates peer-supplied ciphertext halves
// (ct1, ct2) under a fixed key, and parses arbitrary bytes as a stored
// decapsulation key. Nothing may panic; the honest ciphertext must decapsulate
// to the encapsulated secret.
func FuzzDecapsulateCompressedKey(f *testing.F) {
	k := newFuzzKey(f)
	f.Add(k.key.DK, k.enc.Ciphertext1, k.ct2)
	f.Add(k.key.DK, make([]byte, Ciphertext1Size), make([]byte, Ciphertext2Size))
	f.Add(bytes.Repeat([]byte{0xFF}, DecapsulationKeySize), k.enc.Ciphertext1, k.ct2)
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, dk, ct1, ct2 []byte) {
		ss, err := DecapsulateCompressedKey(dk, ct1, ct2)
		if err != nil {
			return
		}
		if bytes.Equal(dk, k.key.DK) && bytes.Equal(ct1, k.enc.Ciphertext1) && bytes.Equal(ct2, k.ct2) &&
			!bytes.Equal(ss, k.enc.SharedSecret) {
			t.Fatal("honest ciphertext decapsulated to a different secret")
		}
	})
}
