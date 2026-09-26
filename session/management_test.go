// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package session_test

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/kem"
	"github.com/cwbudde/libsignal-go/protocol"
	"github.com/cwbudde/libsignal-go/session"
	"github.com/cwbudde/libsignal-go/stores/inmem"
)

const (
	aliceACI = "9d0652a3-dcc3-4d11-975f-74d61598733f"
	bobACI   = "796abedb-ca4e-4f18-8803-1fde5b921f9f"
)

// party is one side of a conversation: all of its stores and its address.
type party struct {
	addr     address.ProtocolAddress
	identity *inmem.IdentityKeyStore
	sessions *inmem.SessionStore
	preKeys  *inmem.PreKeyStore
	signed   *inmem.SignedPreKeyStore
	kyber    *inmem.KyberPreKeyStore
}

func newParty(t *testing.T, name string, device uint32) *party {
	t.Helper()
	dev, err := address.NewDeviceID(device)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := curve.GenerateKeyPair(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newPartyWithIdentity(address.NewProtocolAddress(name, dev), kp)
}

func newPartyWithIdentity(addr address.ProtocolAddress, kp curve.KeyPair) *party {
	return &party{
		addr:     addr,
		identity: inmem.NewIdentityKeyStore(kp, 1000+addr.DeviceID().Value()),
		sessions: inmem.NewSessionStore(),
		preKeys:  inmem.NewPreKeyStore(),
		signed:   inmem.NewSignedPreKeyStore(),
		kyber:    inmem.NewKyberPreKeyStore(),
	}
}

// bundle generates pre-keys with the given ids, saves them as records, and
// returns the bundle a sender fetches. preKeyID 0 means no one-time pre-key.
func (p *party) bundle(t *testing.T, preKeyID, signedID, kyberID uint32) *session.PreKeyBundle {
	t.Helper()
	ctx := context.Background()
	ident, err := p.identity.GetIdentityKeyPair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := curve.GenerateKeyPair(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedSig, err := ident.PrivateKey.CalculateSignature(cryptorand.Reader, signed.PublicKey.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	kyber, err := kem.GenerateKeyPair(kem.KeyTypeKyber1024, cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kyberSig, err := ident.PrivateKey.CalculateSignature(cryptorand.Reader, kyber.PublicKey.Serialize())
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	mustSave(t, p.signed.SaveSignedPreKey(ctx, signedID, mustSerialize(t, session.NewSignedPreKeyRecord(signedID, now, signed, signedSig))))
	mustSave(t, p.kyber.SaveKyberPreKey(ctx, kyberID, mustSerialize(t, session.NewKyberPreKeyRecord(kyberID, now, kyber, kyberSig))))

	params := session.PreKeyBundleParams{
		RegistrationID:  1000 + p.addr.DeviceID().Value(),
		DeviceID:        p.addr.DeviceID().Value(),
		SignedPreKeyID:  signedID,
		SignedPreKey:    signed.PublicKey,
		SignedPreKeySig: signedSig,
		KyberPreKeyID:   kyberID,
		KyberPreKey:     kyber.PublicKey,
		KyberPreKeySig:  kyberSig,
		IdentityKey:     ident.PublicKey,
	}
	if preKeyID != 0 {
		oneTime, err := curve.GenerateKeyPair(cryptorand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		mustSave(t, p.preKeys.SavePreKey(ctx, preKeyID, mustSerialize(t, session.NewPreKeyRecord(preKeyID, oneTime))))
		id, pub := preKeyID, oneTime.PublicKey
		params.PreKeyID = &id
		params.PreKey = &pub
	}
	b, err := session.NewPreKeyBundle(params)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (p *party) encrypt(t *testing.T, to *party, plaintext string) (*protocol.SignalMessage, *protocol.PreKeySignalMessage) {
	t.Helper()
	signal, preKey, err := session.MessageEncrypt(context.Background(), []byte(plaintext), to.addr, p.addr,
		p.sessions, p.identity, time.Now(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("encrypt %q: %v", plaintext, err)
	}
	return signal, preKey
}

// decrypt decrypts either kind of message from the wire bytes, as a client
// would after receiving it.
func (p *party) decrypt(from *party, signal *protocol.SignalMessage, preKey *protocol.PreKeySignalMessage) ([]byte, error) {
	ctx := context.Background()
	if preKey != nil {
		m, err := protocol.DeserializePreKeySignalMessage(preKey.Serialize())
		if err != nil {
			return nil, err
		}
		return session.MessageDecryptPreKey(ctx, m, from.addr, p.addr, p.sessions, p.identity,
			p.preKeys, p.signed, p.kyber, cryptorand.Reader)
	}
	m, err := protocol.DeserializeSignalMessage(signal.Serialize())
	if err != nil {
		return nil, err
	}
	return session.MessageDecryptSignal(ctx, m, from.addr, p.addr, p.sessions, p.identity, cryptorand.Reader)
}

func (p *party) mustDecrypt(t *testing.T, from *party, signal *protocol.SignalMessage, preKey *protocol.PreKeySignalMessage, want string) {
	t.Helper()
	got, err := p.decrypt(from, signal, preKey)
	if err != nil || string(got) != want {
		t.Fatalf("decrypt: got %q, %v; want %q", got, err, want)
	}
}

func (p *party) processBundle(t *testing.T, to *party, b *session.PreKeyBundle) {
	t.Helper()
	err := session.ProcessPreKeyBundle(context.Background(), cryptorand.Reader, to.addr, b, p.sessions, p.identity,
		session.WithLocalAddress(p.addr))
	if err != nil {
		t.Fatalf("ProcessPreKeyBundle: %v", err)
	}
}

func mustSave(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustSerialize(t *testing.T, r interface{ Serialize() ([]byte, error) }) []byte {
	t.Helper()
	b, err := r.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMessageAPIConversation(t *testing.T) {
	for _, withOneTime := range []bool{true, false} {
		t.Run(fmt.Sprintf("one-time=%v", withOneTime), func(t *testing.T) {
			ctx := context.Background()
			alice, bob := newParty(t, aliceACI, 1), newParty(t, bobACI, 2)
			preKeyID := uint32(0)
			if withOneTime {
				preKeyID = 7
			}
			alice.processBundle(t, bob, bob.bundle(t, preKeyID, 8, 9))

			// Until Bob answers, Alice's messages are pre-key messages bound to
			// both addresses.
			_, pk1 := alice.encrypt(t, bob, "hello 1")
			_, pk2 := alice.encrypt(t, bob, "hello 2")
			if pk1 == nil || pk2 == nil {
				t.Fatal("expected pre-key messages before the first reply")
			}
			want, _ := protocol.SerializeAddresses(alice.addr, bob.addr)
			if !bytes.Equal(pk1.Message().Addresses(), want) {
				t.Errorf("pre-key message addresses = %x, want %x", pk1.Message().Addresses(), want)
			}

			// The second pre-key message arrives first; both share one session.
			bob.mustDecrypt(t, alice, nil, pk2, "hello 2")
			bob.mustDecrypt(t, alice, nil, pk1, "hello 1")

			// The one-time pre-key is used up; the Kyber pre-key stays (the
			// in-memory store keeps last-resort keys) but a replay is refused.
			if withOneTime {
				if _, err := bob.preKeys.GetPreKey(ctx, preKeyID); err == nil {
					t.Error("one-time pre-key was not removed")
				}
			}
			if _, err := bob.decrypt(alice, nil, pk1); !errors.Is(err, session.ErrDuplicateMessage) {
				t.Errorf("replayed pre-key message: %v, want ErrDuplicateMessage", err)
			}

			reply, pk := bob.encrypt(t, alice, "hi")
			if pk != nil || len(reply.Addresses()) != 0 {
				t.Fatal("reply must be a plain SignalMessage without addresses")
			}
			alice.mustDecrypt(t, bob, reply, nil, "hi")

			// Now acknowledged: plain messages, in both directions and out of order.
			var msgs []*protocol.SignalMessage
			for i := range 5 {
				m, pk := alice.encrypt(t, bob, fmt.Sprint("m", i))
				if pk != nil {
					t.Fatal("still sending pre-key messages after the reply")
				}
				msgs = append(msgs, m)
			}
			for _, i := range []int{3, 0, 4, 1, 2} {
				bob.mustDecrypt(t, alice, msgs[i], nil, fmt.Sprint("m", i))
			}
			if _, err := bob.decrypt(alice, msgs[2], nil); !errors.Is(err, session.ErrDuplicateMessage) {
				t.Errorf("duplicate: %v, want ErrDuplicateMessage", err)
			}
		})
	}
}

func TestMessageAPIRejectsWrongAddresses(t *testing.T) {
	alice, bob := newParty(t, aliceACI, 1), newParty(t, bobACI, 2)
	alice.processBundle(t, bob, bob.bundle(t, 7, 8, 9))
	_, pk := alice.encrypt(t, bob, "hello")

	// Bob believes the message came from another device of Alice's account.
	otherDevice := *alice
	dev, _ := address.NewDeviceID(3)
	otherDevice.addr = address.NewProtocolAddress(aliceACI, dev)
	if _, err := bob.decrypt(&otherDevice, nil, pk); !errors.Is(err, session.ErrInvalidMessage) {
		t.Fatalf("decrypt with the wrong sender address: %v, want ErrInvalidMessage", err)
	}
	// Nothing was consumed; the right address still works.
	bob.mustDecrypt(t, alice, nil, pk, "hello")
}

func TestMessageAPIArchivedSession(t *testing.T) {
	alice, bob := newParty(t, aliceACI, 1), newParty(t, bobACI, 2)
	alice.processBundle(t, bob, bob.bundle(t, 7, 8, 9))
	_, pk := alice.encrypt(t, bob, "first")
	bob.mustDecrypt(t, alice, nil, pk, "first")
	reply, _ := bob.encrypt(t, alice, "reply")
	alice.mustDecrypt(t, bob, reply, nil, "reply")
	late, _ := bob.encrypt(t, alice, "late")

	// Alice starts over with a new bundle; the old session is archived.
	alice.processBundle(t, bob, bob.bundle(t, 10, 11, 12))
	rec, err := alice.sessions.LoadSession(context.Background(), bob.addr)
	if err != nil || rec.PreviousSessionCount() != 1 {
		t.Fatalf("archived sessions = %d, %v; want 1", rec.PreviousSessionCount(), err)
	}

	// A message Bob sent on the old session still decrypts and promotes it.
	alice.mustDecrypt(t, bob, late, nil, "late")
	rec, _ = alice.sessions.LoadSession(context.Background(), bob.addr)
	if _, pending := rec.CurrentState().PendingPreKeyMessage(); pending {
		t.Error("the promoted old session should be current (it has no pending pre-key message)")
	}

	// A message nobody can decrypt fails as invalid, not as missing.
	stranger := newParty(t, bobACI, 2)
	stranger.processBundle(t, alice, alice.bundle(t, 20, 21, 22))
	_, strangerPK := stranger.encrypt(t, alice, "x")
	if _, err := alice.decrypt(bob, strangerPK.Message(), nil); !errors.Is(err, session.ErrInvalidMessage) {
		t.Errorf("undecryptable message: %v, want ErrInvalidMessage", err)
	}
}

func TestMessageAPIUntrustedIdentity(t *testing.T) {
	alice, bob := newParty(t, aliceACI, 1), newParty(t, bobACI, 2)
	alice.processBundle(t, bob, bob.bundle(t, 7, 8, 9))
	_, pk := alice.encrypt(t, bob, "hello")

	// Bob already knows a different identity for Alice.
	other, _ := curve.GenerateKeyPair(cryptorand.Reader)
	if _, err := bob.identity.SaveIdentity(context.Background(), alice.addr, other.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.decrypt(alice, nil, pk); !errors.Is(err, session.ErrUntrustedIdentity) {
		t.Fatalf("decrypt: %v, want ErrUntrustedIdentity", err)
	}
}

func TestMessageAPISelfSessionSkipsAhead(t *testing.T) {
	kp, _ := curve.GenerateKeyPair(cryptorand.Reader)
	dev1, _ := address.NewDeviceID(1)
	dev2, _ := address.NewDeviceID(2)
	primary := newPartyWithIdentity(address.NewProtocolAddress(aliceACI, dev1), kp)
	linked := newPartyWithIdentity(address.NewProtocolAddress(aliceACI, dev2), kp)

	primary.processBundle(t, linked, linked.bundle(t, 7, 8, 9))
	_, pk := primary.encrypt(t, linked, "hello")
	linked.mustDecrypt(t, primary, nil, pk, "hello")
	reply, _ := linked.encrypt(t, primary, "hi")
	primary.mustDecrypt(t, linked, reply, nil, "hi")

	// Between devices of one account a counter may skip further ahead than
	// MaxForwardJumps.
	var last *protocol.SignalMessage
	for range session.MaxForwardJumps + 2 {
		last, _ = primary.encrypt(t, linked, "far")
	}
	linked.mustDecrypt(t, primary, last, nil, "far")
}

func TestPreKeyRecordsRoundTrip(t *testing.T) {
	kp, _ := curve.GenerateKeyPair(cryptorand.Reader)
	kyber, _ := kem.GenerateKeyPair(kem.KeyTypeKyber1024, cryptorand.Reader)
	ts := time.UnixMilli(1_700_000_000_123)

	pre := session.NewPreKeyRecord(5, kp)
	pre2, err := session.DeserializePreKeyRecord(mustSerialize(t, pre))
	if err != nil || pre2.ID() != 5 {
		t.Fatalf("pre-key: %v", err)
	}
	if got, _ := pre2.KeyPair(); !got.PublicKey.Equal(kp.PublicKey) {
		t.Error("pre-key: key pair changed")
	}

	signed := session.NewSignedPreKeyRecord(6, ts, kp, []byte("sig"))
	signed2, err := session.DeserializeSignedPreKeyRecord(mustSerialize(t, signed))
	if err != nil || signed2.ID() != 6 || !signed2.Timestamp().Equal(ts) || string(signed2.Signature()) != "sig" {
		t.Fatalf("signed pre-key: %v", err)
	}

	kr := session.NewKyberPreKeyRecord(7, ts, kyber, []byte("ksig"))
	kr2, err := session.DeserializeKyberPreKeyRecord(mustSerialize(t, kr))
	if err != nil || kr2.ID() != 7 || !kr2.Timestamp().Equal(ts) {
		t.Fatalf("Kyber pre-key: %v", err)
	}
	if got, _ := kr2.PublicKey(); !got.Equal(kyber.PublicKey) {
		t.Error("Kyber pre-key: public key changed")
	}
	if !bytes.Equal(mustSerialize(t, kr2), mustSerialize(t, kr)) {
		t.Error("Kyber pre-key: serialization not stable")
	}

	if _, err := session.DeserializePreKeyRecord([]byte{0xff}); !errors.Is(err, session.ErrInvalidRecord) {
		t.Errorf("garbage: %v, want ErrInvalidRecord", err)
	}
}

func TestHasUsableSenderChain(t *testing.T) {
	ctx := context.Background()
	alice, bob := newParty(t, aliceACI, 1), newParty(t, bobACI, 2)
	if rec, _ := alice.sessions.LoadSession(ctx, bob.addr); rec != nil {
		t.Fatal("unexpected session")
	}
	if session.NewFreshSessionRecord().HasUsableSenderChain(time.Now()) {
		t.Error("a fresh record has a usable sender chain")
	}

	alice.processBundle(t, bob, bob.bundle(t, 7, 8, 9))
	rec, err := alice.sessions.LoadSession(ctx, bob.addr)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.HasUsableSenderChain(time.Now()) {
		t.Error("a new session is not usable")
	}
	// An unacknowledged session goes stale.
	if rec.HasUsableSenderChain(time.Now().Add(session.MaxUnacknowledgedSessionAge + time.Hour)) {
		t.Error("a stale unacknowledged session is usable")
	}

	// A clone is independent of the original.
	clone := rec.Clone()
	if err := clone.ArchiveCurrentState(); err != nil {
		t.Fatal(err)
	}
	if !rec.HasCurrentState() || clone.HasCurrentState() {
		t.Error("archiving the clone changed the original")
	}
}
