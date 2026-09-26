// Copyright 2020-2023 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkgroup

import (
	"encoding/binary"
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/internal/crypto/gcmsiv"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
)

// GroupMasterKey is the 32-byte group root secret.
type GroupMasterKey [32]byte

// GroupIdentifier is the public identifier derived from a group master key.
type GroupIdentifier [32]byte

// GroupSecretParams holds the group encryption secrets. Its encoding is confidential.
type GroupSecretParams struct {
	master  GroupMasterKey
	id      GroupIdentifier
	blob    [32]byte
	uid     zkcrypto.UIDKeyPair
	profile zkcrypto.ProfileKeyKeyPair
}

// GroupPublicParams holds the group identifier and public encryption keys.
type GroupPublicParams struct {
	id           GroupIdentifier
	uid, profile [32]byte
}

// UUIDCiphertext encrypts an ACI or PNI, including its identity kind.
type UUIDCiphertext struct{ inner zkcrypto.UIDCiphertext }

// ProfileKeyCiphertext encrypts a profile key bound to its ACI.
type ProfileKeyCiphertext struct{ inner zkcrypto.ProfileKeyCiphertext }

// GenerateGroupSecretParams derives a new master key and its group parameters from randomness.
func GenerateGroupSecretParams(randomness [32]byte) *GroupSecretParams {
	s := seeded("Signal_ZKGroup_20200424_Random_GroupSecretParams_Generate", randomness[:])
	return DeriveGroupSecretParams(GroupMasterKey(s.SqueezeAndRatchet(32)))
}

// DeriveGroupSecretParams deterministically expands an existing group master key.
func DeriveGroupSecretParams(master GroupMasterKey) *GroupSecretParams {
	s := seeded("Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey", master[:])
	return &GroupSecretParams{master, GroupIdentifier(s.SqueezeAndRatchet(32)), [32]byte(s.SqueezeAndRatchet(32)), zkcrypto.DeriveUIDKeyPair(s), zkcrypto.DeriveProfileKeyKeyPair(s)}
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (g *GroupSecretParams) Bytes() []byte {
	return join(0, g.master[:], g.id[:], g.blob[:], g.uid.Bytes(), g.profile.Bytes())
}

// ParseGroupSecretParams validates the exact encoding without authenticating its contents.
func ParseGroupSecretParams(b []byte) (*GroupSecretParams, error) {
	if len(b) != 289 {
		return nil, ErrEncoding
	}
	r := reader{b: b}
	r.version(0)
	g := &GroupSecretParams{master: GroupMasterKey(r.take(32)), id: GroupIdentifier(r.take(32)), blob: [32]byte(r.take(32))}
	g.uid = read(&r, 96, zkcrypto.ParseUIDKeyPair)
	g.profile = read(&r, 96, zkcrypto.ParseProfileKeyKeyPair)
	if e := r.done(); e != nil {
		return nil, e
	}
	return g, nil
}

// MasterKey returns a copy of the group root secret.
func (g *GroupSecretParams) MasterKey() GroupMasterKey { return g.master }

// Public returns the public parameters without their secret counterparts.
func (g *GroupSecretParams) Public() *GroupPublicParams {
	return &GroupPublicParams{g.id, [32]byte(g.uid.PublicKeyBytes()), [32]byte(g.profile.PublicKeyBytes())}
}

// Identifier returns the public group identifier.
func (g *GroupPublicParams) Identifier() GroupIdentifier { return g.id }

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (g *GroupPublicParams) Bytes() []byte { return join(0, g.id[:], g.uid[:], g.profile[:]) }

// ParseGroupPublicParams validates the exact encoding without authenticating its contents.
func ParseGroupPublicParams(b []byte) (*GroupPublicParams, error) {
	if len(b) != 97 {
		return nil, ErrEncoding
	}
	r := reader{b: b}
	r.version(0)
	g := &GroupPublicParams{id: GroupIdentifier(r.take(32))}
	p := read(&r, 32, point)
	q := read(&r, 32, point)
	if e := r.done(); e != nil {
		return nil, e
	}
	g.uid = [32]byte(p.Bytes())
	g.profile = [32]byte(q.Bytes())
	return g, nil
}

// EncryptServiceID deterministically encrypts an ACI or PNI.
func (g *GroupSecretParams) EncryptServiceID(id address.ServiceID) UUIDCiphertext {
	return UUIDCiphertext{g.uid.Encrypt(zkcrypto.NewUID(id))}
}

// DecryptServiceID authenticates and recovers an ACI or PNI.
func (g *GroupSecretParams) DecryptServiceID(c UUIDCiphertext) (address.ServiceID, error) {
	return g.uid.Decrypt(c.inner)
}

// EncryptProfileKey deterministically encrypts the profile key bound to aci.
func (g *GroupSecretParams) EncryptProfileKey(key ProfileKey, aci [16]byte) ProfileKeyCiphertext {
	return ProfileKeyCiphertext{g.profile.Encrypt(zkcrypto.NewProfileKey([32]byte(key), aci))}
}

// DecryptProfileKey authenticates the group key and ACI before returning the profile key.
func (g *GroupSecretParams) DecryptProfileKey(c ProfileKeyCiphertext, aci [16]byte) (ProfileKey, error) {
	k, e := g.profile.Decrypt(c.inner, aci)
	return ProfileKey(k), e
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (c UUIDCiphertext) Bytes() []byte { return join(0, c.inner.Bytes()) }

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (c ProfileKeyCiphertext) Bytes() []byte { return join(0, c.inner.Bytes()) }

// ParseUUIDCiphertext validates the exact encoding without authenticating its contents.
func ParseUUIDCiphertext(b []byte) (UUIDCiphertext, error) {
	if len(b) != 65 || b[0] != 0 {
		return UUIDCiphertext{}, ErrEncoding
	}
	c, e := zkcrypto.ParseUIDCiphertext(b[1:])
	return UUIDCiphertext{c}, e
}

// ParseProfileKeyCiphertext validates the exact encoding without authenticating its contents.
func ParseProfileKeyCiphertext(b []byte) (ProfileKeyCiphertext, error) {
	if len(b) != 65 || b[0] != 0 {
		return ProfileKeyCiphertext{}, ErrEncoding
	}
	c, e := zkcrypto.ParseProfileKeyCiphertext(b[1:])
	return ProfileKeyCiphertext{c}, e
}

// EncryptBlob encrypts an attribute with explicit zero padding and fresh randomness.
func (g *GroupSecretParams) EncryptBlob(randomness [32]byte, plaintext []byte, padding uint32) ([]byte, error) {
	// Check both Go's allocation limit and the AEAD limit before conversion/allocation.
	n := uint64(len(plaintext)) + uint64(padding) + 4
	if n > uint64(int(^uint(0)>>1)) || n > 1<<36-1 {
		return nil, ErrEncoding
	}
	padded := make([]byte, int(n))
	binary.BigEndian.PutUint32(padded, padding)
	copy(padded[4:], plaintext)
	nonce := seeded("Signal_ZKGroup_20200424_Random_GroupSecretParams_EncryptBlob", randomness[:]).SqueezeAndRatchet(12)
	b, e := gcmsiv.Seal(g.blob[:], nonce, padded, nil)
	if e != nil {
		return nil, e
	}
	return append(append(b, nonce...), 0), nil
}

// DecryptBlob authenticates and removes the blob padding before returning plaintext.
func (g *GroupSecretParams) DecryptBlob(b []byte) ([]byte, error) {
	if len(b) < 29 {
		return nil, ErrVerification
	}
	// Like Rust, the trailing reserved blob byte is ignored, not authenticated.
	end := len(b) - 13
	p, e := gcmsiv.Open(g.blob[:], b[end:end+12], b[:end], nil)
	if e != nil || len(p) < 4 {
		return nil, ErrVerification
	}
	n := uint64(binary.BigEndian.Uint32(p))
	if n > uint64(len(p)-4) { //nolint:gosec // len(p) >= 4 above.
		return nil, ErrVerification
	}
	return p[4 : len(p)-int(n)], nil //nolint:gosec // n is bounded by the slice length above.
}
