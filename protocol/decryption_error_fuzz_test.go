// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package protocol

import (
	"bytes"
	"testing"

	"github.com/cwbudde/libsignal-go/curve"
)

// FuzzDecryptionErrorMessageForOriginal builds a decryption error message
// from an arbitrary "original" message of each type, as a receiver does for
// a message it could not decrypt. It must never panic, and an accepted result
// must parse back with the ratchet key of the original.
func FuzzDecryptionErrorMessageForOriginal(f *testing.F) {
	ratchet, err := curve.GenerateKeyPair(&fixedReader{b: 21})
	if err != nil {
		f.Fatal(err)
	}
	id, err := curve.GenerateKeyPair(&fixedReader{b: 22})
	if err != nil {
		f.Fatal(err)
	}
	inner, err := NewSignalMessage(CurrentVersion, newMACKey(0x40), ratchet.PublicKey, 7, 3,
		[]byte("body"), id.PublicKey, id.PublicKey, nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	preKeyID, kyberID := uint32(5), uint32(6)
	outer, err := NewPreKeySignalMessage(CurrentVersion, 1234, &preKeyID, 88, &kyberID,
		bytes.Repeat([]byte{0x09}, 1568), ratchet.PublicKey, id.PublicKey, inner)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(MessageTypeWhisper, inner.Serialize())
	f.Add(MessageTypePreKey, outer.Serialize())
	f.Add(MessageTypeSenderKey, []byte{})
	f.Add(MessageTypePlaintext, []byte{0xC0})
	f.Add(uint8(0), []byte{})

	f.Fuzz(func(t *testing.T, typ uint8, b []byte) {
		m, err := DecryptionErrorMessageForOriginal(b, typ, 1_700_000_000_000, 3)
		if err != nil {
			return
		}
		back, err := DeserializeDecryptionErrorMessage(m.Serialized())
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if (m.RatchetKey() == nil) != (back.RatchetKey() == nil) ||
			m.RatchetKey() != nil && !m.RatchetKey().Equal(*back.RatchetKey()) {
			t.Fatal("ratchet key changed in the round trip")
		}
	})
}

// FuzzExtractDecryptionErrorMessage parses arbitrary bytes as the decrypted
// body of a PlaintextContent (a Content protobuf plus the padding boundary
// byte) and extracts its decryption error message. It must never panic.
func FuzzExtractDecryptionErrorMessage(f *testing.F) {
	rk, err := curve.GenerateKeyPair(&fixedReader{b: 23})
	if err != nil {
		f.Fatal(err)
	}
	dem, err := NewDecryptionErrorMessage(&rk.PublicKey, 1, 2)
	if err != nil {
		f.Fatal(err)
	}
	content, err := NewPlaintextContentFromDecryptionError(dem)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(content.Body())
	f.Add([]byte{paddingBoundaryByte})
	f.Add([]byte{0x01})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ExtractDecryptionErrorMessageFromSerializedContent(b)
		if err != nil {
			return
		}
		if _, err := DeserializeDecryptionErrorMessage(m.Serialized()); err != nil {
			t.Fatalf("extracted message does not re-parse: %v", err)
		}
	})
}
