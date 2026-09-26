// Package identity holds the identity-key operations of
// rust/protocol/src/identity_key.rs that go beyond a plain curve key pair: the
// IdentityKeyPairStructure serialization, alternate-identity (PNI) signatures,
// and the same-account check the session layer uses for note-to-self sessions.
// Identity keys themselves are curve.PublicKey / curve.KeyPair values.
package identity

import (
	"errors"
	"fmt"
	"io"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/proto"
)

// ErrInvalidKeyPair is returned when a serialized identity key pair does not
// decode or holds invalid keys.
var ErrInvalidKeyPair = errors.New("identity: invalid identity key pair")

// alternateIdentityPrefix1 and alternateIdentityPrefix2 precede the other
// identity key in an alternate-identity signature
// (ALTERNATE_IDENTITY_SIGNATURE_PREFIX_{1,2} in identity_key.rs).
var (
	alternateIdentityPrefix1 = [32]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}
	alternateIdentityPrefix2 = []byte("Signal_PNI_Signature")
)

// SerializeKeyPair encodes an identity key pair as an IdentityKeyPairStructure
// (IdentityKeyPair::serialize): the serialized public key and the raw private
// key.
func SerializeKeyPair(kp curve.KeyPair) []byte {
	out, err := googleproto.Marshal(&proto.IdentityKeyPairStructure{
		PublicKey:  kp.PublicKey.Serialize(),
		PrivateKey: kp.PrivateKey.Serialize(),
	})
	if err != nil {
		// Marshaling a message of two byte fields cannot fail.
		panic(fmt.Sprintf("identity: marshaling key pair: %v", err))
	}
	return out
}

// DeserializeKeyPair decodes an IdentityKeyPairStructure
// (IdentityKeyPair::try_from(&[u8])).
func DeserializeKeyPair(b []byte) (curve.KeyPair, error) {
	var s proto.IdentityKeyPairStructure
	if err := googleproto.Unmarshal(b, &s); err != nil {
		return curve.KeyPair{}, fmt.Errorf("%w: %v", ErrInvalidKeyPair, err)
	}
	public, err := curve.DeserializePublicKey(s.GetPublicKey())
	if err != nil {
		return curve.KeyPair{}, fmt.Errorf("%w: public key: %v", ErrInvalidKeyPair, err)
	}
	private, err := curve.DeserializePrivateKey(s.GetPrivateKey())
	if err != nil {
		return curve.KeyPair{}, fmt.Errorf("%w: private key: %v", ErrInvalidKeyPair, err)
	}
	return curve.NewKeyPair(public, private), nil
}

// SignAlternateIdentity signs other (typically the PNI identity key) with the
// identity private key, so that other can be shown to belong to the same
// account (IdentityKeyPair::sign_alternate_identity). rng must be a CSPRNG.
func SignAlternateIdentity(identity curve.PrivateKey, other curve.PublicKey, rng io.Reader) ([]byte, error) {
	sig, err := identity.CalculateSignature(rng, alternateIdentityPrefix1[:], alternateIdentityPrefix2, other.Serialize())
	if err != nil {
		return nil, fmt.Errorf("identity: signing alternate identity: %w", err)
	}
	return sig, nil
}

// VerifyAlternateIdentity checks a signature from SignAlternateIdentity
// (IdentityKey::verify_alternate_identity).
func VerifyAlternateIdentity(identity, other curve.PublicKey, signature []byte) bool {
	return identity.VerifySignature(signature, alternateIdentityPrefix1[:], alternateIdentityPrefix2, other.Serialize())
}

// IsSameAccount reports whether two (identity key, address) pairs belong to the
// same account: the keys are equal and both address names are the same service
// ID. Names that are not service ID strings never match
// (IdentityKey::is_same_account).
func IsSameAccount(selfKey curve.PublicKey, selfAddress address.ProtocolAddress, otherKey curve.PublicKey, otherAddress address.ProtocolAddress) bool {
	if !selfKey.Equal(otherKey) {
		return false
	}
	selfID, err := address.ParseServiceIDString(selfAddress.Name())
	if err != nil {
		return false
	}
	otherID, err := address.ParseServiceIDString(otherAddress.Name())
	if err != nil {
		return false
	}
	return selfID.Compare(otherID) == 0
}
