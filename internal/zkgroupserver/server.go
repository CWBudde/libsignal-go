// Copyright 2020-2024 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package zkgroupserver supplies server operations for compatibility tests only.
package zkgroupserver

import (
	"encoding/binary"
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/cwbudde/libsignal-go/zkcredential"
	"github.com/cwbudde/libsignal-go/zkgroup"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
	"github.com/gtank/ristretto255"
)

// Server holds test-only issuing keys.
type Server struct {
	public       *zkgroup.ServerPublicParams
	profile      zkcrypto.CredentialKeyPair
	signature    zkcrypto.SignatureKeyPair
	generic      *zkcredential.CredentialKeyPair
	endorsements *zkcredential.ServerRootKeyPair
}

func sho(label string, randomness [32]byte) *poksho.ShoHmacSha256 {
	s := poksho.NewShoHmacSha256([]byte(label))
	s.AbsorbAndRatchet(randomness[:])
	return s
}

// Generate derives the test issuer with the exact upstream SHO transcript.
func Generate(randomness [32]byte) (*Server, error) {
	s := sho("Signal_ZKGroup_20200424_Random_ServerSecretParams_Generate", randomness)
	server := &Server{}
	public := []byte{0}
	for i, kind := range []zkcrypto.CredentialKind{zkcrypto.AuthCredentialKind, zkcrypto.ProfileCredentialKind, zkcrypto.ReceiptCredentialKind, zkcrypto.PNICredentialKind, zkcrypto.ExpiringProfileCredentialKind, zkcrypto.AuthWithPNICredentialKind} {
		if i == 2 {
			server.signature = zkcrypto.GenerateSignatureKeyPair(s)
			public = append(public, server.signature.Public().Bytes()...)
		}
		key, e := zkcrypto.GenerateCredentialKeyPair(kind, s)
		if e != nil {
			return nil, e
		}
		public = append(public, key.Public().Bytes()...)
		if kind == zkcrypto.ExpiringProfileCredentialKind {
			server.profile = key
		}
	}
	var e error
	server.generic, e = zkcredential.GenerateCredentialKeyPair(zkcredential.LegacyMode, randomness)
	if e != nil {
		return nil, e
	}
	public = append(public, server.generic.Public().Bytes()...)
	server.endorsements = zkcredential.GenerateServerRootKeyPair(randomness)
	public = append(public, server.endorsements.Public().Bytes()...)
	server.public, e = zkgroup.ParseServerPublicParams(public)
	return server, e
}

// Public returns the public parameters without their secret counterparts.
func (s *Server) Public() *zkgroup.ServerPublicParams { return s.public }

// Sign signs a test message using explicit randomness.
func (s *Server) Sign(randomness [32]byte, message []byte) (zkgroup.NotarySignature, error) {
	b, e := s.signature.Sign(message, sho("Signal_ZKGroup_20200424_Random_ServerSecretParams_Sign", randomness))
	if e != nil {
		return zkgroup.NotarySignature{}, e
	}
	return zkgroup.NotarySignature(b), nil
}

// IssueProfile verifies the request commitment proof and issues a blinded test credential.
func (s *Server) IssueProfile(randomness [32]byte, request *zkgroup.ProfileKeyCredentialRequest, aci [16]byte, commitment zkgroup.ProfileKeyCommitment, expiration uint64) (*zkgroup.ExpiringProfileKeyCredentialResponse, error) {
	b := request.Bytes()
	key, e := zkcrypto.ParseProfileRequestPublicKey(b[1:33])
	if e != nil {
		return nil, e
	}
	c, e := zkcrypto.ParseProfileRequestCiphertext(b[33:161])
	if e != nil {
		return nil, e
	}
	p, e := zkcrypto.ParseProfileRequestProof(b[161:])
	if e != nil {
		return nil, e
	}
	if commitment[0] != 0 {
		return nil, zkgroup.ErrEncoding
	}
	j, e := zkcrypto.ParseProfileKeyCommitment(commitment[1:])
	if e != nil {
		return nil, e
	}
	if e = p.Verify(key, c, j); e != nil {
		return nil, e
	}
	r := sho("Signal_ZKGroup_20220508_Random_ServerSecretParams_IssueExpiringProfileKeyCredential", randomness)
	u := zkcrypto.NewUID(address.NewACI(aci))
	blinded, e := s.profile.IssueProfile(u, key, c, expiration, r)
	if e != nil {
		return nil, e
	}
	proof, e := zkcrypto.NewProfileIssuanceProof(s.profile, key, c, blinded, u, expiration, r)
	if e != nil {
		return nil, e
	}
	out := append([]byte{0}, blinded.Public().Bytes()...)
	out = append(out, zkcrypto.TimestampBytes(expiration)...)
	out = append(out, proof.Bytes()...)
	return zkgroup.ParseExpiringProfileKeyCredentialResponse(out)
}

// VerifyProfile verifies a V4 profile presentation and its expiration.
func (s *Server) VerifyProfile(group *zkgroup.GroupPublicParams, p *zkgroup.ProfileKeyCredentialPresentation, now uint64) error {
	b := p.Bytes()
	if b[0] != 3 {
		return zkgroup.ErrVerification
	}
	end := len(b) - 136
	proof, e := zkcrypto.ParseProfilePresentationProof(b[1:end])
	if e != nil {
		return e
	}
	u, e := zkcrypto.ParseUIDCiphertext(b[end : end+64])
	if e != nil {
		return e
	}
	k, e := zkcrypto.ParseProfileKeyCiphertext(b[end+64 : end+128])
	if e != nil {
		return e
	}
	expiration := binary.LittleEndian.Uint64(b[len(b)-8:])
	if expiration <= now {
		return zkgroup.ErrVerification
	}
	g := group.Bytes()
	return proof.Verify(s.profile, u, g[33:65], k, g[65:97], expiration)
}
func attr(uid zkcrypto.UID) *zkcredential.Attribute {
	p := uid.Points()
	return zkcredential.NewAttribute(p[0], p[1])
}

// IssueAuth issues a test authentication response for the two identities and timestamp.
func (s *Server) IssueAuth(randomness [32]byte, aci, pni [16]byte, redemption uint64) (*zkgroup.AuthCredentialWithPniResponse, error) {
	p, e := zkcredential.NewIssuanceBuilder([]byte("20240222_Signal_AuthCredentialZkc"), nil).AddAttribute(attr(zkcrypto.NewUID(address.NewACI(aci)))).AddAttribute(attr(zkcrypto.NewUID(address.NewPNI(pni)))).AddPublicAttribute(zkcredential.PublicUint64(redemption)).Issue(s.generic, randomness)
	if e != nil {
		return nil, e
	}
	return zkgroup.ParseAuthCredentialWithPniResponse(append([]byte{3}, p.Bytes()...))
}

// VerifyAuth verifies a V4 auth presentation and its redemption window.
func (s *Server) VerifyAuth(group *zkgroup.GroupPublicParams, p *zkgroup.AuthCredentialPresentation, now uint64) error {
	b := p.Bytes()
	end := len(b) - 136
	redemption := binary.LittleEndian.Uint64(b[len(b)-8:])
	if redemption < zkgroup.SecondsPerDay || redemption > ^uint64(0)-2*zkgroup.SecondsPerDay || now < redemption-zkgroup.SecondsPerDay || now > redemption+2*zkgroup.SecondsPerDay {
		return zkgroup.ErrVerification
	}
	proof, e := zkcredential.ParsePresentationProof(b[1:end])
	if e != nil {
		return e
	}
	a, e := zkcredential.ParseAttribute(b[end : end+64])
	if e != nil {
		return e
	}
	pn, e := zkcredential.ParseAttribute(b[end+64 : end+128])
	if e != nil {
		return e
	}
	generators := zkcrypto.UIDEncryptionSystemParams()
	g1, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(generators[:32])
	g2, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(generators[32:])
	domain := zkcredential.NewDomainWithGenerators("Signal_ZKGroup_20230419_UidEncryption", g1, g2)
	key, e := zkcredential.ParseEncryptionPublicKey(domain, group.Bytes()[33:65])
	if e != nil {
		return e
	}
	return zkcredential.NewPresentationVerifier([]byte("20240222_Signal_AuthCredentialZkc"), nil).AddAttribute(a, key).AddAttribute(pn, key).AddPublicAttribute(zkcredential.PublicUint64(redemption)).Verify(s.generic, proof)
}
