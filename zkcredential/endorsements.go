// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcredential

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

// ServerRootKeyPair derives tag-specific endorsement keys.
type ServerRootKeyPair struct {
	sk     *scalar
	public *ServerRootPublicKey
}

// ServerRootPublicKey derives tag-specific endorsement public keys.
type ServerRootPublicKey struct{ pk *point }

// ServerDerivedKeyPair issues endorsements and verifies tokens. Knowledge of
// this private key and its tag information also reveals the root private key.
type ServerDerivedKeyPair struct {
	sk     *scalar
	public *ServerDerivedPublicKey
}

// ServerDerivedPublicKey verifies honest endorsement issuance.
type ServerDerivedPublicKey struct{ pk *point }

// ClientDecryptionKey converts endorsements of hidden points into bearer tokens.
type ClientDecryptionKey struct{ inverse *scalar }

// GenerateServerRootKeyPair derives an endorsement root key from random bytes.
func GenerateServerRootKeyPair(randomness [32]byte) *ServerRootKeyPair {
	return ServerRootKeyPairFromScalar(sget(seeded("Signal_ZKCredential_Endorsements_ServerRootKeyPair_generate_20240207", randomness)))
}

// ServerRootKeyPairFromScalar copies existing root key material.
func ServerRootKeyPairFromScalar(s *ristretto255.Scalar) *ServerRootKeyPair {
	return &ServerRootKeyPair{new(scalar).Set(s), &ServerRootPublicKey{base(s)}}
}

// ServerRootPublicKeyFromPoint copies an existing public key point.
func ServerRootPublicKeyFromPoint(p *ristretto255.Element) *ServerRootPublicKey {
	return &ServerRootPublicKey{pointCopy(p)}
}

// Public returns the immutable public key.
func (k *ServerRootKeyPair) Public() *ServerRootPublicKey { return k.public }

// Public returns the immutable public key.
func (k *ServerDerivedKeyPair) Public() *ServerDerivedPublicKey { return k.public }

// DeriveKey consumes one scalar from tagInfo. Its transcript must include a
// protocol-specific domain separator and all public endorsement attributes.
func (k *ServerRootKeyPair) DeriveKey(tagInfo poksho.SHO) *ServerDerivedKeyPair {
	t := sget(tagInfo)
	return &ServerDerivedKeyPair{sinv(ristrettoScalarAdd(k.sk, t)), &ServerDerivedPublicKey{add(k.public.pk, base(t))}}
}

// DeriveKey consumes the same tag transcript as the issuing server.
func (k *ServerRootPublicKey) DeriveKey(tagInfo poksho.SHO) *ServerDerivedPublicKey {
	return &ServerDerivedPublicKey{add(k.pk, base(sget(tagInfo)))}
}

// ClientDecryptionKeyFromScalar inverts the scalar used to hide endorsement points.
func ClientDecryptionKeyFromScalar(s *ristretto255.Scalar) *ClientDecryptionKey {
	return &ClientDecryptionKey{sinv(s)}
}

// ClientDecryptionKeyForAttribute derives a key for the FIRST ciphertext point.
func ClientDecryptionKeyForAttribute(k *EncryptionKeyPair) *ClientDecryptionKey {
	return ClientDecryptionKeyFromScalar(k.a1)
}

// Bytes serializes root secret material.
func (k *ServerRootKeyPair) Bytes() []byte { return k.sk.Bytes() }

// Bytes serializes the root public key.
func (k *ServerRootPublicKey) Bytes() []byte { return k.pk.Bytes() }

// Bytes serializes derived secret and public material.
func (k *ServerDerivedKeyPair) Bytes() []byte { return append(k.sk.Bytes(), k.public.Bytes()...) }

// Bytes serializes the derived public key.
func (k *ServerDerivedPublicKey) Bytes() []byte { return k.pk.Bytes() }

// Bytes serializes the client's inverse scalar.
func (k *ClientDecryptionKey) Bytes() []byte { return k.inverse.Bytes() }

// ParseServerRootKeyPair reads a canonical root scalar.
func ParseServerRootKeyPair(b []byte) (*ServerRootKeyPair, error) {
	r := reader{b: b}
	k := ServerRootKeyPairFromScalar(r.scalar())
	return k, r.done()
}

// ParseServerRootPublicKey reads a canonical point.
func ParseServerRootPublicKey(b []byte) (*ServerRootPublicKey, error) {
	r := reader{b: b}
	k := &ServerRootPublicKey{r.point()}
	return k, r.done()
}

// ParseServerDerivedKeyPair reads derived secret and public material.
func ParseServerDerivedKeyPair(b []byte) (*ServerDerivedKeyPair, error) {
	r := reader{b: b}
	k := &ServerDerivedKeyPair{r.scalar(), &ServerDerivedPublicKey{r.point()}}
	return k, r.done()
}

// ParseServerDerivedPublicKey reads a canonical point.
func ParseServerDerivedPublicKey(b []byte) (*ServerDerivedPublicKey, error) {
	r := reader{b: b}
	k := &ServerDerivedPublicKey{r.point()}
	return k, r.done()
}

// ParseClientDecryptionKey reads a canonical inverse scalar.
func ParseClientDecryptionKey(b []byte) (*ClientDecryptionKey, error) {
	r := reader{b: b}
	k := &ClientDecryptionKey{r.scalar()}
	return k, r.done()
}

// EndorsementResponse contains compressed endorsements and a batch proof.
// Individual points are decompressed only after parsing, during Receive.
type EndorsementResponse struct {
	rs    [][32]byte
	proof []byte
}

// Endorsement is a verified endorsement point. The zero value is the identity
// for CombineEndorsements and Remove. It is not a valid token for a nonempty set.
type Endorsement struct{ r *point }

func (e *Endorsement) point() *point {
	if e.r == nil {
		return zero()
	}
	return e.r
}
func endorsementStatement() *poksho.Statement {
	s := poksho.NewStatement()
	equation(s, "weighted_sum(R)", term("sk_prime", "weighted_sum(E)"))
	equation(s, "G", term("sk_prime", "PK_prime"))
	return s
}
func endorsementWeights(k *ServerDerivedPublicKey, ps []*point, rs [][32]byte) []*scalar {
	s := poksho.NewShoHmacSha256([]byte("Signal_ZKCredential_Endorsements_EndorsementResponse_ProofWeights_20240207"))
	s.Absorb(k.pk.Bytes())
	for _, p := range ps {
		s.Absorb(add(p, p).Bytes())
	}
	for _, r := range rs {
		s.Absorb(r[:])
	}
	s.Ratchet()
	raw := s.SqueezeAndRatchet((len(ps) - 1) * 16)
	weights := make([]*scalar, len(ps)-1)
	for i := range weights {
		var b [32]byte
		copy(b[:16], raw[i*16:(i+1)*16])
		b[15] &= 127
		var e error
		weights[i], e = new(scalar).SetCanonicalBytes(b[:])
		if e != nil {
			panic(e)
		}
	}
	return weights
}
func weightedSum(ps []*point, weights []*scalar) *point {
	sum := pointCopy(ps[0])
	for i, w := range weights {
		sum = add(sum, mul(w, ps[i+1]))
	}
	return sum
}

// IssueEndorsements creates one endorsement per hidden point and a batch proof.
// Empty inputs are rejected; the upstream implementation panics on empty batches.
func IssueEndorsements(ps []*ristretto255.Element, k *ServerDerivedKeyPair, randomness [32]byte) (*EndorsementResponse, error) {
	if len(ps) == 0 {
		return nil, ErrArguments
	}
	r := &EndorsementResponse{rs: make([][32]byte, len(ps))}
	for i, p := range ps {
		if p == nil {
			return nil, ErrArguments
		}
		r.rs[i] = [32]byte(mul(k.sk, p).Bytes())
	}
	sum := weightedSum(ps, endorsementWeights(k.public, ps, r.rs))
	var e error
	r.proof, e = endorsementStatement().Prove(poksho.ScalarArgs{"sk_prime": k.sk}, poksho.PointArgs{"weighted_sum(E)": sum, "weighted_sum(R)": mul(k.sk, sum), "PK_prime": k.public.pk}, nil, randomness)
	if e != nil {
		return nil, proofOK(e)
	}
	return r, nil
}

// Receive verifies the batch proof and returns immutable endorsements in input order.
func (r *EndorsementResponse) Receive(ps []*ristretto255.Element, k *ServerDerivedPublicKey) ([]*Endorsement, error) {
	if len(ps) == 0 || len(ps) != len(r.rs) {
		return nil, ErrVerification
	}
	for _, p := range ps {
		if p == nil {
			return nil, ErrArguments
		}
	}
	out := make([]*Endorsement, len(ps))
	rs := make([]*point, len(ps))
	for i, b := range r.rs {
		p, e := zero().SetCanonicalBytes(b[:])
		if e != nil {
			return nil, ErrVerification
		}
		rs[i] = p
		out[i] = &Endorsement{p}
	}
	w := endorsementWeights(k, ps, r.rs)
	e := endorsementStatement().VerifyProof(r.proof, poksho.PointArgs{"weighted_sum(E)": weightedSum(ps, w), "weighted_sum(R)": weightedSum(rs, w), "PK_prime": k.pk}, nil)
	if e != nil {
		return nil, ErrVerification
	}
	return out, nil
}

// Bytes serializes the compressed point vector and proof vector.
func (r *EndorsementResponse) Bytes() []byte {
	b := binary.LittleEndian.AppendUint64(nil, uint64(len(r.rs)))
	for _, p := range r.rs {
		b = append(b, p[:]...)
	}
	return vector(b, r.proof)
}

// ParseEndorsementResponse bounds lengths by available input before allocating.
// Compressed endorsements are intentionally opaque until Receive.
func ParseEndorsementResponse(b []byte) (*EndorsementResponse, error) {
	r := reader{b: b}
	n := binary.LittleEndian.Uint64(r.take(8))
	if n > uint64(len(r.b)/32) {
		return nil, ErrEncoding
	}
	out := &EndorsementResponse{rs: make([][32]byte, int(n))} //nolint:gosec // n is bounded by the int-sized input above.
	for i := range out.rs {
		copy(out.rs[i][:], r.take(32))
	}
	out.proof = r.vector()
	return out, r.done()
}

// Bytes returns the compressed endorsement point.
func (e *Endorsement) Bytes() []byte { return e.point().Bytes() }

// ParseEndorsement parses a canonical point. Stored endorsements must already
// have been authenticated by Receive; parsing does not verify issuance.
func ParseEndorsement(b []byte) (*Endorsement, error) {
	r := reader{b: b}
	e := &Endorsement{r.point()}
	return e, r.done()
}

// CombineEndorsements adds endorsements issued with the same server and client
// keys. It preserves multiplicity; it does not deduplicate repeated inputs.
func CombineEndorsements(es ...*Endorsement) *Endorsement {
	sum := zero()
	for _, e := range es {
		sum = add(sum, e.point())
	}
	return &Endorsement{sum}
}

// Remove subtracts an endorsement issued under the same server and client keys.
func (e *Endorsement) Remove(other *Endorsement) *Endorsement {
	return &Endorsement{sub(e.point(), other.point())}
}
func token(p *point) [16]byte { h := sha256.Sum256(p.Bytes()); return [16]byte(h[:16]) }

// Token generates a 16-byte bearer token for the endorsed point or combined set.
func (e *Endorsement) Token(k *ClientDecryptionKey) [16]byte { return token(mul(k.inverse, e.point())) }

// VerifyToken authenticates a token against a plaintext point or sum of points.
func (k *ServerDerivedKeyPair) VerifyToken(p *ristretto255.Element, t []byte) error {
	want := token(mul(k.sk, p))
	if subtle.ConstantTimeCompare(want[:], t) != 1 {
		return ErrVerification
	}
	return nil
}
