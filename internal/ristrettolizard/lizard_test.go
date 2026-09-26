// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package ristrettolizard_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/cwbudde/libsignal-go/internal/ristrettolizard"
	"github.com/gtank/ristretto255"
)

func TestLizard(t *testing.T) {
	for _, tv := range [][2]string{
		{"00000000000000000000000000000000", "f0b7e34484f74cf00f15024b738539738646bbbe1e9bc7509a676815227e774f"},
		{"01010101010101010101010101010101", "cc92e81f585afc5caac88660d8d17e9025a44489a363042123f6af0702156e65"},
		{"000102030405060708090a0b0c0d0e0f", "c830573f8a8e7778671f76cdc796dc0a235cf177f197d9fcba06e84e96247444"},
		{"dddddddddddddddddddddddddddddddd", "ccb60554c081841037f821fa827b6a5bc2531f80e2647f1a858611f4ccfe3056"},
	} {
		b, err := hex.DecodeString(tv[0])
		if err != nil {
			t.Fatal(err)
		}
		input := [16]byte(b)
		p := ristrettolizard.Encode(input)
		if got := hex.EncodeToString(p.Bytes()); got != tv[1] {
			t.Fatalf("encode: %s != %s", got, tv[1])
		}
		out, ok := ristrettolizard.Decode(p)
		if !ok || out != input {
			t.Fatalf("decode %s: %x %v", tv[0], out, ok)
		}
	}
}

func TestMapInverse(t *testing.T) {
	inputs := [][32]byte{{}, {168, 27, 92, 74, 203, 42, 48, 117, 170, 109, 234, 14, 45, 169, 188, 205, 21, 110, 235, 115, 153, 84, 52, 117, 151, 235, 123, 244, 88, 85, 179, 5}}
	for i := range 100 {
		inputs = append(inputs, sha256.Sum256([]byte{byte(i)}))
	}
	for _, input := range inputs {
		input[0] &= 254
		input[31] &= 63
		p := ristrettolizard.Map(input)
		found := false
		for _, c := range ristrettolizard.Inverse(p) {
			if c.Valid == 0 {
				continue
			}
			if ristrettolizard.Map(c.Bytes).Equal(p) != 1 {
				t.Fatal("inverse does not map back")
			}
			if c.Bytes == input {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing inverse of %x", input)
		}
	}
	if ristrettolizard.Map([32]byte{}).Equal(ristretto255.NewIdentityElement()) != 1 {
		t.Fatal("MAP(0) must be identity")
	}
	for _, p := range []*ristretto255.Element{ristretto255.NewIdentityElement(), ristretto255.NewGeneratorElement()} {
		if _, ok := ristrettolizard.Decode(p); ok {
			t.Fatal("accepted invalid lizard point")
		}
	}
}

func FuzzLizard(f *testing.F) {
	f.Add(make([]byte, 32))
	f.Add([]byte("0123456789abcdef0123456789abcdef"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) != 32 {
			return
		}
		uuid := [16]byte(b[:16])
		if got, ok := ristrettolizard.Decode(ristrettolizard.Encode(uuid)); !ok || got != uuid {
			t.Fatal("lizard roundtrip")
		}
		input := [32]byte(b)
		input[0] &= 254
		input[31] &= 63
		p := ristrettolizard.Map(input)
		found := false
		for _, c := range ristrettolizard.Inverse(p) {
			if c.Valid == 0 {
				continue
			}
			if ristrettolizard.Map(c.Bytes).Equal(p) != 1 {
				t.Fatal("incorrect inverse")
			}
			found = found || c.Bytes == input
		}
		if !found {
			t.Fatal("missing inverse")
		}
	})
}
