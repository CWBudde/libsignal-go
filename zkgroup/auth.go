// Copyright 2024 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkgroup

import (
	"bytes"
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/zkcredential"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
)

const authLabel = "20240222_Signal_AuthCredentialZkc"

var uidDomain = func() *zkcredential.Domain {
	b := zkcrypto.UIDEncryptionSystemParams()
	a, _ := point(b[:32])
	c, _ := point(b[32:])
	return zkcredential.NewDomainWithGenerators("Signal_ZKGroup_20230419_UidEncryption", a, c)
}()

func uidACI(aci [16]byte) zkcrypto.UID { return zkcrypto.NewUID(address.NewACI(aci)) }
func attribute(uid zkcrypto.UID) *zkcredential.Attribute {
	p := uid.Points()
	return zkcredential.NewAttribute(p[0], p[1])
}

// AuthCredentialWithPniResponse contains the version 3 generic issuance proof.
type AuthCredentialWithPniResponse struct{ proof *zkcredential.IssuanceProof }

// AuthCredentialWithPni is a received credential binding an ACI, PNI and redemption time.
type AuthCredentialWithPni struct {
	credential *zkcredential.Credential
	aci, pni   zkcrypto.UID
	redemption uint64
}

// AuthCredentialPresentation contains a V4 authentication presentation (wire version byte 3).
type AuthCredentialPresentation struct{ encoded []byte }

// ParseAuthCredentialWithPniResponse validates the exact encoding without authenticating its contents.
func ParseAuthCredentialWithPniResponse(b []byte) (*AuthCredentialWithPniResponse, error) {
	if len(b) != 425 || b[0] != 3 {
		return nil, ErrEncoding
	}
	p, e := zkcredential.ParseIssuanceProof(b[1:])
	if e != nil {
		return nil, ErrEncoding
	}
	return &AuthCredentialWithPniResponse{p}, nil
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (r *AuthCredentialWithPniResponse) Bytes() []byte { return join(3, r.proof.Bytes()) }

// ReceiveAuthCredentialWithPni verifies the response and day-aligned redemption timestamp.
func (s *ServerPublicParams) ReceiveAuthCredentialWithPni(aci, pni [16]byte, redemption uint64, response *AuthCredentialWithPniResponse) (*AuthCredentialWithPni, error) {
	if redemption%SecondsPerDay != 0 {
		return nil, ErrVerification
	}
	a, p := uidACI(aci), zkcrypto.NewUID(address.NewPNI(pni))
	c, e := zkcredential.NewIssuanceBuilder([]byte(authLabel), nil).AddAttribute(attribute(a)).AddAttribute(attribute(p)).AddPublicAttribute(zkcredential.PublicUint64(redemption)).Verify(s.generic, response.proof)
	if e != nil {
		return nil, ErrVerification
	}
	return &AuthCredentialWithPni{c, a, p, redemption}, nil
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (c *AuthCredentialWithPni) Bytes() []byte {
	return join(3, c.credential.Bytes(), c.aci.Bytes(), c.pni.Bytes(), zkcrypto.TimestampBytes(c.redemption))
}

// ParseAuthCredentialWithPni validates the exact encoding without authenticating its contents.
func ParseAuthCredentialWithPni(b []byte) (*AuthCredentialWithPni, error) {
	if len(b) != 265 {
		return nil, ErrEncoding
	}
	r := reader{b: b}
	r.version(3)
	c := &AuthCredentialWithPni{credential: read(&r, 96, zkcredential.ParseCredential), aci: read(&r, 80, zkcrypto.ParseUID), pni: read(&r, 80, zkcrypto.ParseUID), redemption: timestamp(r.take(8))}
	if e := r.done(); e != nil {
		return nil, e
	}
	return c, nil
}

// CreateAuthCredentialPresentation creates a fresh presentation under the group encryption key.
func (s *ServerPublicParams) CreateAuthCredentialPresentation(randomness [32]byte, g *GroupSecretParams, c *AuthCredentialWithPni) (*AuthCredentialPresentation, error) {
	k, e := zkcredential.ParseEncryptionKeyPair(uidDomain, g.uid.Bytes())
	if e != nil {
		return nil, e
	}
	p, e := zkcredential.NewPresentationBuilder([]byte(authLabel), nil).AddAttribute(attribute(c.aci), k).AddAttribute(attribute(c.pni), k).Present(zkcredential.LegacyMode, s.generic, c.credential, randomness)
	if e != nil {
		return nil, e
	}
	return &AuthCredentialPresentation{join(3, p.Bytes(), g.uid.Encrypt(c.aci).Bytes(), g.uid.Encrypt(c.pni).Bytes(), zkcrypto.TimestampBytes(c.redemption))}, nil
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (p *AuthCredentialPresentation) Bytes() []byte { return bytes.Clone(p.encoded) }

// ParseAuthCredentialPresentation validates the exact encoding without authenticating its contents.
func ParseAuthCredentialPresentation(b []byte) (*AuthCredentialPresentation, error) {
	if len(b) < 1+112+136 || b[0] != 3 {
		return nil, ErrEncoding
	}
	end := len(b) - 136
	if _, e := zkcredential.ParsePresentationProof(b[1:end]); e != nil {
		return nil, ErrEncoding
	}
	if _, e := zkcrypto.ParseUIDCiphertext(b[end : end+64]); e != nil {
		return nil, ErrEncoding
	}
	if _, e := zkcrypto.ParseUIDCiphertext(b[end+64 : end+128]); e != nil {
		return nil, ErrEncoding
	}
	return &AuthCredentialPresentation{bytes.Clone(b)}, nil
}
