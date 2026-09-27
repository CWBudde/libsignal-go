// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/kem"
)

// preKeyRecordSeeds returns serialized EC, signed EC and Kyber pre-key
// records, generated once for the record fuzzers.
func preKeyRecordSeeds(f *testing.F) (ec, signed, kyber []byte) {
	f.Helper()
	kp, err := curve.GenerateKeyPair(&fixedReader{b: 11})
	if err != nil {
		f.Fatal(err)
	}
	kyberKP, err := kem.GenerateKeyPair(kem.KeyTypeKyber1024, &fixedReader{b: 12})
	if err != nil {
		f.Fatal(err)
	}
	ts := time.UnixMilli(1_700_000_000_000)
	sig := bytes.Repeat([]byte{0x5A}, 64)
	serialize := func(r interface{ Serialize() ([]byte, error) }) []byte {
		b, err := r.Serialize()
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	return serialize(NewPreKeyRecord(7, kp)),
		serialize(NewSignedPreKeyRecord(8, ts, kp, sig)),
		serialize(NewKyberPreKeyRecord(9, ts, kyberKP, sig))
}

// addRecordSeeds adds every record seed to each record fuzzer, so each parser
// also sees the other record shapes, plus a few malformed inputs.
func addRecordSeeds(f *testing.F) {
	ec, signed, kyber := preKeyRecordSeeds(f)
	f.Add(ec)
	f.Add(signed)
	f.Add(kyber)
	f.Add([]byte{})
	f.Add([]byte{0x08})
	f.Add([]byte{0x12, 0x21, 0x05})
}

// checkStableSerialization re-serializes a parsed record and parses it again:
// the second serialization must equal the first.
func checkStableSerialization(t *testing.T, first []byte, reparse func([]byte) ([]byte, error)) {
	t.Helper()
	second, err := reparse(first)
	if err != nil {
		t.Fatalf("re-parse of a serialized record: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("record serialization is not stable")
	}
}

// FuzzDeserializePreKeyRecord parses arbitrary bytes as a stored one-time
// pre-key record. It must never panic, the key accessors must not panic, and
// serialization must be stable.
func FuzzDeserializePreKeyRecord(f *testing.F) {
	addRecordSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DeserializePreKeyRecord(b)
		if err != nil {
			return
		}
		_ = r.ID()
		_, _ = r.KeyPair()
		out, err := r.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		checkStableSerialization(t, out, func(b []byte) ([]byte, error) {
			r, err := DeserializePreKeyRecord(b)
			if err != nil {
				return nil, err
			}
			return r.Serialize()
		})
	})
}

// FuzzDeserializeSignedPreKeyRecord is FuzzDeserializePreKeyRecord for signed
// EC pre-key records.
func FuzzDeserializeSignedPreKeyRecord(f *testing.F) {
	addRecordSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DeserializeSignedPreKeyRecord(b)
		if err != nil {
			return
		}
		_, _, _ = r.ID(), r.Timestamp(), r.Signature()
		_, _ = r.KeyPair()
		out, err := r.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		checkStableSerialization(t, out, func(b []byte) ([]byte, error) {
			r, err := DeserializeSignedPreKeyRecord(b)
			if err != nil {
				return nil, err
			}
			return r.Serialize()
		})
	})
}

// FuzzDeserializeKyberPreKeyRecord is FuzzDeserializePreKeyRecord for Kyber
// pre-key records.
func FuzzDeserializeKyberPreKeyRecord(f *testing.F) {
	addRecordSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DeserializeKyberPreKeyRecord(b)
		if err != nil {
			return
		}
		_, _, _ = r.ID(), r.Timestamp(), r.Signature()
		_, _ = r.KeyPair()
		out, err := r.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		checkStableSerialization(t, out, func(b []byte) ([]byte, error) {
			r, err := DeserializeKyberPreKeyRecord(b)
			if err != nil {
				return nil, err
			}
			return r.Serialize()
		})
	})
}
