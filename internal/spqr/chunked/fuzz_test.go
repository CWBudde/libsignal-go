// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package chunked

import (
	"testing"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/cwbudde/libsignal-go/proto"
)

// maxFuzzPoints bounds how many points a fuzzed encoder or decoder may hold
// before the target skips it. Lagrange interpolation is quadratic in the
// point count; a state a peer can influence holds at most a few dozen points
// per polynomial (1152-byte messages), so larger inputs only slow the fuzzer.
const maxFuzzPoints = 1024

// FuzzEncoderFromProto decodes arbitrary bytes as a PolynomialEncoder (the
// form the SPQR state stores its in-flight sends in), rebuilds the Encoder
// and draws chunks from it. It must never panic, and an accepted encoder must
// re-serialize to a proto that decodes to an encoder drawing the same chunks.
func FuzzEncoderFromProto(f *testing.F) {
	for _, n := range []int{0, 2, 64, 1152} {
		enc, err := NewEncoder(makeMsg(n))
		if err != nil {
			f.Fatal(err)
		}
		enc.NextChunk()
		addProto(f, EncoderToProto(enc))
		enc.ChunkAt(uint16(n)) // force the Points -> Polys switch
		addProto(f, EncoderToProto(enc))
	}
	f.Add([]byte{})
	f.Add([]byte{0x08, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		var pb proto.PolynomialEncoder
		if googleproto.Unmarshal(data, &pb) != nil || tooManyPoints(pb.GetPts(), pb.GetPolys()) {
			return
		}
		enc, err := EncoderFromProto(&pb)
		if err != nil {
			return
		}
		again, err := EncoderFromProto(EncoderToProto(enc))
		if err != nil {
			t.Fatalf("re-decode of a re-encoded encoder: %v", err)
		}
		for _, idx := range []uint16{0, 1, 17, 0xFFFF} {
			if a, b := enc.ChunkAt(idx), again.ChunkAt(idx); a != b {
				t.Fatalf("chunk %d differs after the proto round trip", idx)
			}
		}
		_ = enc.NextChunk()
	})
}

// FuzzDecoderFromProto decodes arbitrary bytes as a PolynomialDecoder (the
// form the SPQR state stores its in-flight receives in), rebuilds the Decoder,
// feeds it one more chunk and tries to decode. It must never panic.
func FuzzDecoderFromProto(f *testing.F) {
	for _, n := range []int{0, 2, 64, 1088} {
		msg := makeMsg(n)
		enc, err := NewEncoder(msg)
		if err != nil {
			f.Fatal(err)
		}
		dec, err := NewDecoder(n)
		if err != nil {
			f.Fatal(err)
		}
		addProto(f, DecoderToProto(dec))
		c := enc.ChunkAt(1)
		dec.AddChunk(&c)
		addProto(f, DecoderToProto(dec))
	}
	f.Add([]byte{})
	f.Add([]byte{0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F})

	f.Fuzz(func(t *testing.T, data []byte) {
		var pb proto.PolynomialDecoder
		if googleproto.Unmarshal(data, &pb) != nil || tooManyPoints(pb.GetPts(), nil) {
			return
		}
		dec, err := DecoderFromProto(&pb)
		if err != nil {
			return
		}
		if _, err := DecoderFromProto(DecoderToProto(dec)); err != nil {
			t.Fatalf("re-decode of a re-encoded decoder: %v", err)
		}
		c := Chunk{Index: uint16(len(data))}
		copy(c.Data[:], data)
		dec.AddChunk(&c)
		if msg := dec.DecodedMessage(); msg != nil && len(msg) != dec.pointsNeeded*2 {
			t.Fatalf("decoded %d bytes, want %d", len(msg), dec.pointsNeeded*2)
		}
	})
}

func addProto(f *testing.F, m googleproto.Message) {
	f.Helper()
	b, err := googleproto.Marshal(m)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
}

func tooManyPoints(lists ...[][]byte) bool {
	n := 0
	for _, l := range lists {
		for _, b := range l {
			n += len(b) / 2
		}
	}
	return n > maxFuzzPoints
}
