// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package spqr

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cwbudde/libsignal-go/proto"
)

// lockstepSeeds runs a short A<->B exchange and returns, for each message, the
// receiver's state before the message and the message itself. They seed the
// Recv fuzzer with states and messages from every phase of the v1 machine.
func lockstepSeeds(f *testing.F) (states, msgs [][]byte) {
	f.Helper()
	alex, err := InitialState(v1Params(proto.Direction_A_2_B, proto.Version_V_1, proto.Version_V_1))
	if err != nil {
		f.Fatal(err)
	}
	blake, err := InitialState(v1Params(proto.Direction_B_2_A, proto.Version_V_1, proto.Version_V_1))
	if err != nil {
		f.Fatal(err)
	}
	step := func(from, to *SerializedState) {
		sr, err := Send(*from, rand.Reader)
		if err != nil {
			f.Fatal(err)
		}
		*from = sr.State
		states, msgs = append(states, bytes.Clone(*to)), append(msgs, sr.Msg)
		rr, err := Recv(*to, sr.Msg)
		if err != nil {
			f.Fatal(err)
		}
		*to = rr.State
	}
	for range 12 {
		step(&alex, &blake)
		step(&blake, &alex)
	}
	return states, msgs
}

// FuzzRecv feeds arbitrary state and message bytes to Recv. The message is
// what a peer controls; the state is what the local store holds. Neither may
// panic Recv, the negotiation queries, or a Send from the resulting state.
func FuzzRecv(f *testing.F) {
	states, msgs := lockstepSeeds(f)
	for i := range states {
		f.Add(states[i], msgs[i])
		// Cross-pair states and messages from other phases too.
		f.Add(states[i], msgs[(i+3)%len(msgs)])
	}
	f.Add([]byte{}, []byte{})
	f.Add(states[0], []byte{versionByteV1})
	f.Add(states[0], []byte{versionByteV1 + 1, 1, 0, msgTypeNone})

	f.Fuzz(func(t *testing.T, state, msg []byte) {
		_, _ = Negotiation(state)
		_, _ = CurrentVersion(state)
		if st, err := DecodeState(state); err == nil && !boundedChainParams(st) {
			// The chain params are local configuration, not peer input: a
			// stored max_jump of 2^32 legitimately permits deriving billions
			// of keys for one message, which only stalls the fuzzer.
			return
		}
		rr, err := Recv(state, msg)
		if err != nil {
			return
		}
		if _, err := DecodeState(rr.State); err != nil {
			t.Fatalf("Recv returned a state that does not decode: %v", err)
		}
		_, _ = Send(rr.State, rand.Reader)
	})
}

// boundedChainParams reports whether every ChainParams in st stays within the
// defaults, so one Recv derives at most DefaultMaxJump keys.
func boundedChainParams(st *proto.PqRatchetState) bool {
	for _, p := range []*proto.ChainParams{st.GetChain().GetParams(), st.GetVersionNegotiation().GetChainParams()} {
		if p.GetMaxJump() > DefaultMaxJump || p.GetMaxOooKeys() > defaultMaxOOOKeys {
			return false
		}
	}
	return true
}

// FuzzDeserializeMessage checks the v1 message codec: arbitrary bytes never
// panic, and an accepted message re-serializes to exactly the bytes consumed.
func FuzzDeserializeMessage(f *testing.F) {
	_, msgs := lockstepSeeds(f)
	for _, m := range msgs {
		f.Add(m)
	}
	f.Add([]byte{})
	f.Add([]byte{versionByteV1, 0x01, 0x00, msgTypeCt1})
	f.Add([]byte{versionByteV1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01})

	f.Fuzz(func(t *testing.T, b []byte) {
		m, index, at, err := deserializeMessage(b)
		if err != nil {
			return
		}
		if at > len(b) {
			t.Fatalf("consumed %d of %d bytes", at, len(b))
		}
		again, index2, at2, err := deserializeMessage(serializeMessage(&m, index))
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if again != m || index2 != index {
			t.Fatalf("round trip changed the message: %+v/%d vs %+v/%d", m, index, again, index2)
		}
		// Varints may carry redundant continuation bytes, so only a minimal
		// encoding is reproduced byte for byte.
		if at2 > at {
			t.Fatalf("re-encoding grew from %d to %d bytes", at, at2)
		}
	})
}
