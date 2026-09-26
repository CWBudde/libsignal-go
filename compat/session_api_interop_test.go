// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build interop

// Interop for the address-aware session API (session.MessageEncrypt,
// MessageDecryptSignal, MessageDecryptPreKey) against upstream's
// message_encrypt / message_decrypt. Both sides use service-ID address names,
// so pre-key messages are bound to the sender and recipient addresses, as
// between real clients, and Go=Bob sets its session up from its pre-key stores
// the way upstream's process_prekey does.
package compat

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/protocol"
	"github.com/cwbudde/libsignal-go/session"
	"github.com/cwbudde/libsignal-go/stores/inmem"
)

const (
	apiAliceACI = "9d0652a3-dcc3-4d11-975f-74d61598733f"
	apiBobACI   = "796abedb-ca4e-4f18-8803-1fde5b921f9f"
)

func rustEncryptAs(t *testing.T, h *harness, handle, localName, remoteName string, plaintext []byte) ctMsg {
	t.Helper()
	var m ctMsg
	h.ok("session.encrypt", map[string]any{
		"handle":      handle,
		"local_name":  localName,
		"remote_name": remoteName,
		"plaintext":   hx(plaintext),
	}, &m)
	return m
}

func rustDecryptAs(t *testing.T, h *harness, handle, localName, remoteName string, m ctMsg) ([]byte, error) {
	t.Helper()
	resp := h.call("session.decrypt", map[string]any{
		"handle":      handle,
		"local_name":  localName,
		"remote_name": remoteName,
		"type":        m.Type,
		"serialized":  m.Serialized,
	})
	if !resp.Ok {
		return nil, errors.New(resp.Error)
	}
	var res struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("decode session.decrypt result: %v", err)
	}
	return mustDecodeHex(t, res.Plaintext), nil
}

// goParty is the Go side of an address-aware conversation.
type goParty struct {
	addr     address.ProtocolAddress
	identity *inmem.IdentityKeyStore
	sessions *inmem.SessionStore
	preKeys  *inmem.PreKeyStore
	signed   *inmem.SignedPreKeyStore
	kyber    *inmem.KyberPreKeyStore
}

func (p *goParty) encrypt(t *testing.T, remote address.ProtocolAddress, pt []byte) ctMsg {
	t.Helper()
	signal, preKey, err := session.MessageEncrypt(context.Background(), pt, remote, p.addr, p.sessions, p.identity,
		time.Now(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("Go MessageEncrypt: %v", err)
	}
	if preKey != nil {
		return ctMsg{Type: typePreKey, Serialized: hx(preKey.Serialize())}
	}
	return ctMsg{Type: typeWhisper, Serialized: hx(signal.Serialize())}
}

func (p *goParty) decrypt(t *testing.T, remote address.ProtocolAddress, m ctMsg) []byte {
	t.Helper()
	ctx := context.Background()
	raw := mustDecodeHex(t, m.Serialized)
	var (
		pt  []byte
		err error
	)
	if m.Type == typePreKey {
		var pk *protocol.PreKeySignalMessage
		if pk, err = protocol.DeserializePreKeySignalMessage(raw); err == nil {
			pt, err = session.MessageDecryptPreKey(ctx, pk, remote, p.addr, p.sessions, p.identity,
				p.preKeys, p.signed, p.kyber, cryptorand.Reader)
		}
	} else {
		var sm *protocol.SignalMessage
		if sm, err = protocol.DeserializeSignalMessage(raw); err == nil {
			pt, err = session.MessageDecryptSignal(ctx, sm, remote, p.addr, p.sessions, p.identity, cryptorand.Reader)
		}
	}
	if err != nil {
		t.Fatalf("Go decrypt (type %d): %v", m.Type, err)
	}
	return pt
}

// assertAddressBound checks that a pre-key message carries the addresses of
// its sender and recipient.
func assertAddressBound(t *testing.T, m ctMsg, sender, recipient address.ProtocolAddress) {
	t.Helper()
	pk, err := protocol.DeserializePreKeySignalMessage(mustDecodeHex(t, m.Serialized))
	if err != nil {
		t.Fatalf("DeserializePreKeySignalMessage: %v", err)
	}
	want, _ := protocol.SerializeAddresses(sender, recipient)
	if !bytes.Equal(pk.Message().Addresses(), want) {
		t.Fatalf("pre-key message addresses = %x, want %x", pk.Message().Addresses(), want)
	}
}

func TestSessionAPIInteropGoAliceRustBob(t *testing.T) {
	h := newHarness(t)
	aliceAddr := interopAddr(t, apiAliceACI)
	bobAddr := interopAddr(t, apiBobACI)
	const bobHandle = "api_bob"

	alice := &goParty{
		addr:     aliceAddr,
		identity: inmem.NewIdentityKeyStore(mustGenCurve(t), 1001),
		sessions: inmem.NewSessionStore(),
	}
	b := rustCreateBundle(t, h, bobHandle, true)
	err := session.ProcessPreKeyBundle(context.Background(), cryptorand.Reader, bobAddr, goBundleFromRust(t, b),
		alice.sessions, alice.identity, session.WithLocalAddress(aliceAddr))
	if err != nil {
		t.Fatalf("Go ProcessPreKeyBundle: %v", err)
	}

	first := alice.encrypt(t, bobAddr, []byte("alice msg 0"))
	if first.Type != typePreKey {
		t.Fatalf("first message type %d, want PreKey", first.Type)
	}
	assertAddressBound(t, first, aliceAddr, bobAddr)

	// Upstream rejects the message when it believes it came from someone else,
	// and accepts it from the right sender.
	if _, err := rustDecryptAs(t, h, bobHandle, apiBobACI, apiBobACI, first); err == nil {
		t.Fatal("Rust=Bob accepted a pre-key message bound to a different sender")
	}
	got, err := rustDecryptAs(t, h, bobHandle, apiBobACI, apiAliceACI, first)
	if err != nil || !bytes.Equal(got, []byte("alice msg 0")) {
		t.Fatalf("Rust=Bob decrypt msg 0: %q, %v", got, err)
	}

	reply := rustEncryptAs(t, h, bobHandle, apiBobACI, apiAliceACI, []byte("bob reply 0"))
	if got := alice.decrypt(t, bobAddr, reply); !bytes.Equal(got, []byte("bob reply 0")) {
		t.Fatalf("Go=Alice decrypt reply: %q", got)
	}

	runOutOfOrderExchange(t, 20,
		func(pt []byte) ctMsg { return alice.encrypt(t, bobAddr, pt) },
		func(m ctMsg) []byte {
			got, err := rustDecryptAs(t, h, bobHandle, apiBobACI, apiAliceACI, m)
			if err != nil {
				t.Fatalf("Rust=Bob decrypt: %v", err)
			}
			return got
		},
	)
}

func TestSessionAPIInteropRustAliceGoBob(t *testing.T) {
	for _, withOneTime := range []bool{true, false} {
		name := "without_one_time"
		if withOneTime {
			name = "with_one_time"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			aliceAddr := interopAddr(t, apiAliceACI)
			bobAddr := interopAddr(t, apiBobACI)
			aliceHandle := "api_alice_" + name

			// Go=Bob keeps its pre-keys as records in its stores, as a client does.
			keys := newGoBob(t, withOneTime)
			bundle := keys.bundle(t)
			bob := &goParty{
				addr:     bobAddr,
				identity: inmem.NewIdentityKeyStore(keys.identity, keys.regID),
				sessions: inmem.NewSessionStore(),
				preKeys:  inmem.NewPreKeyStore(),
				signed:   inmem.NewSignedPreKeyStore(),
				kyber:    inmem.NewKyberPreKeyStore(),
			}
			now := time.Now()
			save := func(err error) {
				if err != nil {
					t.Fatal(err)
				}
			}
			ser := func(r interface{ Serialize() ([]byte, error) }) []byte {
				b, err := r.Serialize()
				save(err)
				return b
			}
			save(bob.signed.SaveSignedPreKey(ctx, bundle.SignedPreKeyID, ser(session.NewSignedPreKeyRecord(
				bundle.SignedPreKeyID, now, keys.signedPre, mustDecodeHex(t, bundle.SignedPreKeySignature)))))
			save(bob.kyber.SaveKyberPreKey(ctx, bundle.KyberPreKeyID, ser(session.NewKyberPreKeyRecord(
				bundle.KyberPreKeyID, now, keys.kyber, mustDecodeHex(t, bundle.KyberPreKeySignature)))))
			if withOneTime {
				save(bob.preKeys.SavePreKey(ctx, *bundle.PreKeyID, ser(session.NewPreKeyRecord(*bundle.PreKeyID, *keys.oneTime))))
			}

			rustProcessBundleAsAlice(t, h, aliceHandle, apiBobACI, bundle)
			first := rustEncryptAs(t, h, aliceHandle, apiAliceACI, apiBobACI, []byte("alice msg 0"))
			if first.Type != typePreKey {
				t.Fatalf("first message type %d, want PreKey", first.Type)
			}
			assertAddressBound(t, first, aliceAddr, bobAddr)
			if got := bob.decrypt(t, aliceAddr, first); !bytes.Equal(got, []byte("alice msg 0")) {
				t.Fatalf("Go=Bob decrypt msg 0: %q", got)
			}
			if withOneTime {
				if _, err := bob.preKeys.GetPreKey(ctx, *bundle.PreKeyID); err == nil {
					t.Error("Go=Bob kept the one-time pre-key")
				}
			}

			reply := bob.encrypt(t, aliceAddr, []byte("bob reply 0"))
			got, err := rustDecryptAs(t, h, aliceHandle, apiAliceACI, apiBobACI, reply)
			if err != nil || !bytes.Equal(got, []byte("bob reply 0")) {
				t.Fatalf("Rust=Alice decrypt reply: %q, %v", got, err)
			}

			runOutOfOrderExchange(t, 20,
				func(pt []byte) ctMsg { return rustEncryptAs(t, h, aliceHandle, apiAliceACI, apiBobACI, pt) },
				func(m ctMsg) []byte { return bob.decrypt(t, aliceAddr, m) },
			)
		})
	}
}
