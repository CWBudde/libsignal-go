// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkgroup

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
)

// ProfileKey is the 32-byte profile secret.
type ProfileKey [32]byte

// ProfileKeyCommitment is the public commitment to a profile key and ACI.
type ProfileKeyCommitment [97]byte

// ProfileKeyVersion is the 64-byte lowercase hexadecimal identifier used in profile URLs.
type ProfileKeyVersion [64]byte

// Commitment commits to the profile key and ACI.
func (p ProfileKey) Commitment(aci [16]byte) ProfileKeyCommitment {
	return ProfileKeyCommitment(join(0, zkcrypto.NewProfileKeyCommitment([32]byte(p), aci).Public().Bytes()))
}

// Version derives the profile-key version for the given ACI.
func (p ProfileKey) Version(aci [16]byte) ProfileKeyVersion {
	s := seeded("Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_GetProfileKeyVersion", append(p[:], aci[:]...))
	var v ProfileKeyVersion
	hex.Encode(v[:], s.SqueezeAndRatchet(32))
	return v
}

// AccessKey derives the 16-byte unidentified access key.
func (p ProfileKey) AccessKey() [16]byte {
	b, _ := aes.NewCipher(p[:])
	var in, out [16]byte
	in[15] = 2
	b.Encrypt(out[:], in[:])
	return out
}

// ProfileKeyCredentialRequestContext retains the private blinding key, nonces, and request proof.
type ProfileKeyCredentialRequestContext struct {
	aci        [16]byte
	key        ProfileKey
	blinding   zkcrypto.ProfileRequestKeyPair
	ciphertext zkcrypto.ProfileRequestCiphertextWithNonce
	proof      zkcrypto.ProfileRequestProof
}

// ProfileKeyCredentialRequest contains the public blinded request and commitment proof.
type ProfileKeyCredentialRequest struct {
	public     zkcrypto.ProfileRequestPublicKey
	ciphertext zkcrypto.ProfileRequestCiphertext
	proof      zkcrypto.ProfileRequestProof
}

// ExpiringProfileKeyCredentialResponse contains a blinded credential and issuance proof.
type ExpiringProfileKeyCredentialResponse struct {
	blinded    zkcrypto.BlindedCredential
	expiration uint64
	proof      zkcrypto.ProfileIssuanceProof
}

// ExpiringProfileKeyCredential is an authenticated credential retained in confidential storage.
type ExpiringProfileKeyCredential struct {
	credential zkcrypto.Credential
	aci        [16]byte
	key        ProfileKey
	expiration uint64
}

// ProfileKeyCredentialPresentation is structurally parsed, not authenticated.
// Historical versions 1-3 are retained for ciphertext extraction only.
type ProfileKeyCredentialPresentation struct {
	encoded []byte
	uid     UUIDCiphertext
	profile ProfileKeyCiphertext
}

// CreateProfileKeyCredentialRequestContext creates a blinded request using fresh randomness.
func (s *ServerPublicParams) CreateProfileKeyCredentialRequestContext(randomness [32]byte, aci [16]byte, key ProfileKey) (*ProfileKeyCredentialRequestContext, error) {
	sho := seeded("Signal_ZKGroup_20200424_Random_ServerPublicParams_CreateProfileKeyCredentialRequestContext", randomness[:])
	k := zkcrypto.GenerateProfileRequestKeyPair(sho)
	c := k.Encrypt(zkcrypto.NewProfileKey([32]byte(key), aci), sho)
	p, e := zkcrypto.NewProfileRequestProof(k, c, zkcrypto.NewProfileKeyCommitment([32]byte(key), aci), sho)
	if e != nil {
		return nil, e
	}
	return &ProfileKeyCredentialRequestContext{aci, key, k, c, p}, nil
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (c *ProfileKeyCredentialRequestContext) Bytes() []byte {
	return join(0, c.aci[:], c.key[:], c.blinding.Bytes(), c.ciphertext.Bytes(), c.proof.Bytes())
}

// ParseProfileKeyCredentialRequestContext validates the exact encoding without authenticating its contents.
func ParseProfileKeyCredentialRequestContext(b []byte) (*ProfileKeyCredentialRequestContext, error) {
	if len(b) != 473 {
		return nil, ErrEncoding
	}
	r := reader{b: b}
	r.version(0)
	c := &ProfileKeyCredentialRequestContext{aci: [16]byte(r.take(16)), key: ProfileKey(r.take(32))}
	c.blinding = read(&r, 64, zkcrypto.ParseProfileRequestKeyPair)
	c.ciphertext = read(&r, 192, zkcrypto.ParseProfileRequestCiphertextWithNonce)
	c.proof = read(&r, len(r.b), zkcrypto.ParseProfileRequestProof)
	if e := r.done(); e != nil {
		return nil, e
	}
	return c, nil
}

// Request returns the public request without the blinding secrets.
func (c *ProfileKeyCredentialRequestContext) Request() *ProfileKeyCredentialRequest {
	return &ProfileKeyCredentialRequest{c.blinding.Public(), c.ciphertext.Public(), c.proof}
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (r *ProfileKeyCredentialRequest) Bytes() []byte {
	return join(0, r.public.Bytes(), r.ciphertext.Bytes(), r.proof.Bytes())
}

// ParseProfileKeyCredentialRequest validates the exact encoding without authenticating its contents.
func ParseProfileKeyCredentialRequest(b []byte) (*ProfileKeyCredentialRequest, error) {
	if len(b) != 329 {
		return nil, ErrEncoding
	}
	r := reader{b: b}
	r.version(0)
	c := &ProfileKeyCredentialRequest{public: read(&r, 32, zkcrypto.ParseProfileRequestPublicKey), ciphertext: read(&r, 128, zkcrypto.ParseProfileRequestCiphertext), proof: read(&r, len(r.b), zkcrypto.ParseProfileRequestProof)}
	if e := r.done(); e != nil {
		return nil, e
	}
	return c, nil
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (c *ExpiringProfileKeyCredentialResponse) Bytes() []byte {
	return join(0, c.blinded.Bytes(), zkcrypto.TimestampBytes(c.expiration), c.proof.Bytes())
}

// ParseExpiringProfileKeyCredentialResponse validates the exact encoding without authenticating its contents.
func ParseExpiringProfileKeyCredentialResponse(b []byte) (*ExpiringProfileKeyCredentialResponse, error) {
	if len(b) != 497 {
		return nil, ErrEncoding
	}
	r := reader{b: b}
	r.version(0)
	c := &ExpiringProfileKeyCredentialResponse{blinded: read(&r, 128, zkcrypto.ParseBlindedCredential), expiration: timestamp(r.take(8)), proof: read(&r, len(r.b), zkcrypto.ParseProfileIssuanceProof)}
	if e := r.done(); e != nil {
		return nil, e
	}
	return c, nil
}

// ReceiveExpiringProfileKeyCredential verifies issuance and the expiration policy before unblinding.
func (s *ServerPublicParams) ReceiveExpiringProfileKeyCredential(c *ProfileKeyCredentialRequestContext, response *ExpiringProfileKeyCredentialResponse, now uint64) (*ExpiringProfileKeyCredential, error) {
	if e := response.proof.Verify(s.profile, c.blinding.Public(), c.aci, c.ciphertext.Public(), response.blinded, response.expiration); e != nil {
		return nil, ErrVerification
	}
	exp := response.expiration
	if exp%SecondsPerDay != 0 || exp < now {
		return nil, ErrVerification
	}
	days := (exp - now) / SecondsPerDay
	if days == 0 || days > 7 {
		return nil, ErrVerification
	}
	return &ExpiringProfileKeyCredential{c.blinding.Unblind(response.blinded), c.aci, c.key, exp}, nil
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (c *ExpiringProfileKeyCredential) Bytes() []byte {
	return join(0, c.credential.Bytes(), c.aci[:], c.key[:], zkcrypto.TimestampBytes(c.expiration))
}

// Expiration returns the expiration time in Unix seconds.
func (c *ExpiringProfileKeyCredential) Expiration() uint64 { return c.expiration }

// ParseExpiringProfileKeyCredential validates the exact encoding without authenticating its contents.
func ParseExpiringProfileKeyCredential(b []byte) (*ExpiringProfileKeyCredential, error) {
	if len(b) != 153 {
		return nil, ErrEncoding
	}
	r := reader{b: b}
	r.version(0)
	c := &ExpiringProfileKeyCredential{credential: read(&r, 96, zkcrypto.ParseCredential), aci: [16]byte(r.take(16)), key: ProfileKey(r.take(32)), expiration: timestamp(r.take(8))}
	if e := r.done(); e != nil {
		return nil, e
	}
	return c, nil
}

// CreateExpiringProfileKeyCredentialPresentation creates a fresh V4 presentation (wire version byte 3).
func (s *ServerPublicParams) CreateExpiringProfileKeyCredentialPresentation(randomness [32]byte, g *GroupSecretParams, c *ExpiringProfileKeyCredential) (*ProfileKeyCredentialPresentation, error) {
	sho := seeded("Signal_ZKGroup_20220508_Random_ServerPublicParams_CreateExpiringProfileKeyCredentialPresentation", randomness[:])
	u := g.uid.Encrypt(uidACI(c.aci))
	p := g.profile.Encrypt(zkcrypto.NewProfileKey([32]byte(c.key), c.aci))
	proof, e := zkcrypto.NewProfilePresentationProof(g.uid, g.profile, s.profile, c.credential, u, p, c.aci, [32]byte(c.key), sho)
	if e != nil {
		return nil, e
	}
	return &ProfileKeyCredentialPresentation{join(3, proof.Bytes(), u.Bytes(), p.Bytes(), zkcrypto.TimestampBytes(c.expiration)), UUIDCiphertext{u}, ProfileKeyCiphertext{p}}, nil
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (p *ProfileKeyCredentialPresentation) Bytes() []byte { return bytes.Clone(p.encoded) }

// UUIDCiphertext encrypts an ACI or PNI, including its identity kind.
func (p *ProfileKeyCredentialPresentation) UUIDCiphertext() UUIDCiphertext { return p.uid }

// ProfileKeyCiphertext encrypts a profile key bound to its ACI.
func (p *ProfileKeyCredentialPresentation) ProfileKeyCiphertext() ProfileKeyCiphertext {
	return p.profile
}

// ParseProfileKeyCredentialPresentation validates the exact encoding without authenticating its contents.
func ParseProfileKeyCredentialPresentation(b []byte) (*ProfileKeyCredentialPresentation, error) {
	if len(b) == 0 || b[0] > 3 {
		return nil, ErrEncoding
	}
	tail := 128
	if b[0] >= 2 {
		tail += 8
	}
	if len(b) < 1+264+tail {
		return nil, ErrEncoding
	}
	end := len(b) - tail
	var e error
	switch b[0] {
	case 0:
		_, e = zkcrypto.ParseProfilePresentationProofV1(b[1:end])
	case 1:
		_, e = zkcrypto.ParseProfilePresentationProofV2(b[1:end])
	default:
		_, e = zkcrypto.ParseProfilePresentationProof(b[1:end])
	}
	if e != nil {
		return nil, ErrEncoding
	}
	u, e := zkcrypto.ParseUIDCiphertext(b[end : end+64])
	if e != nil {
		return nil, ErrEncoding
	}
	p, e := zkcrypto.ParseProfileKeyCiphertext(b[end+64 : end+128])
	if e != nil {
		return nil, ErrEncoding
	}
	return &ProfileKeyCredentialPresentation{bytes.Clone(b), UUIDCiphertext{u}, ProfileKeyCiphertext{p}}, nil
}
