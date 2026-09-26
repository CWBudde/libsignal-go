package session

import (
	"errors"
	"fmt"
	"time"

	googleproto "google.golang.org/protobuf/proto"

	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/kem"
	"github.com/cwbudde/libsignal-go/proto"
)

// ErrInvalidRecord is returned when a serialized pre-key record does not
// decode.
var ErrInvalidRecord = errors.New("session: invalid pre-key record")

// unmarshalRecord decodes a storage record the way prost does: unknown fields
// are dropped, so that re-serializing gives the bytes upstream would produce.
func unmarshalRecord(b []byte, m googleproto.Message) error {
	if err := (googleproto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, m); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	return nil
}

func marshalRecord(m googleproto.Message) ([]byte, error) {
	out, err := googleproto.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("session: encoding record: %w", err)
	}
	return out, nil
}

// PreKeyRecord is a one-time EC pre-key with its private key, as kept in a
// PreKeyStore. It serializes to a PreKeyRecordStructure (state/prekey.rs).
type PreKeyRecord struct {
	s *proto.PreKeyRecordStructure
}

// NewPreKeyRecord builds a record for id and the key pair (PreKeyRecord::new).
func NewPreKeyRecord(id uint32, kp curve.KeyPair) *PreKeyRecord {
	return &PreKeyRecord{s: &proto.PreKeyRecordStructure{
		Id:         id,
		PublicKey:  kp.PublicKey.Serialize(),
		PrivateKey: kp.PrivateKey.Serialize(),
	}}
}

// DeserializePreKeyRecord decodes a PreKeyRecordStructure. Like upstream it does
// not validate the keys; KeyPair, PublicKey and PrivateKey do.
func DeserializePreKeyRecord(b []byte) (*PreKeyRecord, error) {
	s := &proto.PreKeyRecordStructure{}
	if err := unmarshalRecord(b, s); err != nil {
		return nil, err
	}
	return &PreKeyRecord{s: s}, nil
}

// ID returns the pre-key id.
func (r *PreKeyRecord) ID() uint32 { return r.s.GetId() }

// PublicKey returns the pre-key's public key.
func (r *PreKeyRecord) PublicKey() (curve.PublicKey, error) {
	return curve.DeserializePublicKey(r.s.GetPublicKey())
}

// PrivateKey returns the pre-key's private key.
func (r *PreKeyRecord) PrivateKey() (curve.PrivateKey, error) {
	return curve.DeserializePrivateKey(r.s.GetPrivateKey())
}

// KeyPair returns the pre-key pair.
func (r *PreKeyRecord) KeyPair() (curve.KeyPair, error) {
	return curve.KeyPairFromPublicAndPrivate(r.s.GetPublicKey(), r.s.GetPrivateKey())
}

// Serialize encodes the record (PreKeyRecord::serialize).
func (r *PreKeyRecord) Serialize() ([]byte, error) { return marshalRecord(r.s) }

// signedRecord is the SignedPreKeyRecordStructure shared by signed EC pre-keys
// and Kyber pre-keys (GenericSignedPreKey in state/signed_prekey.rs).
type signedRecord struct {
	s *proto.SignedPreKeyRecordStructure
}

func newSignedRecord(id uint32, timestamp time.Time, public, private, signature []byte) signedRecord {
	return signedRecord{s: &proto.SignedPreKeyRecordStructure{
		Id:         id,
		Timestamp:  uint64(timestamp.UnixMilli()), //nolint:gosec // G115: pre-keys are not dated before 1970
		PublicKey:  public,
		PrivateKey: private,
		Signature:  append([]byte(nil), signature...),
	}}
}

func deserializeSignedRecord(b []byte) (signedRecord, error) {
	s := &proto.SignedPreKeyRecordStructure{}
	if err := unmarshalRecord(b, s); err != nil {
		return signedRecord{}, err
	}
	return signedRecord{s: s}, nil
}

// ID returns the pre-key id.
func (r signedRecord) ID() uint32 { return r.s.GetId() }

// Timestamp returns when the pre-key was generated (millisecond precision).
func (r signedRecord) Timestamp() time.Time {
	return time.UnixMilli(int64(r.s.GetTimestamp())) //nolint:gosec // G115: milliseconds since 1970 fit in an int64
}

// Signature returns the identity key's signature over the serialized public key.
func (r signedRecord) Signature() []byte { return r.s.GetSignature() }

// Serialize encodes the record as a SignedPreKeyRecordStructure.
func (r signedRecord) Serialize() ([]byte, error) { return marshalRecord(r.s) }

// SignedPreKeyRecord is a signed EC pre-key with its private key, as kept in a
// SignedPreKeyStore (state/signed_prekey.rs).
type SignedPreKeyRecord struct {
	signedRecord
}

// NewSignedPreKeyRecord builds a record for id (GenericSignedPreKey::new).
// signature is the identity key's signature over the serialized public key.
func NewSignedPreKeyRecord(id uint32, timestamp time.Time, kp curve.KeyPair, signature []byte) *SignedPreKeyRecord {
	return &SignedPreKeyRecord{newSignedRecord(id, timestamp, kp.PublicKey.Serialize(), kp.PrivateKey.Serialize(), signature)}
}

// DeserializeSignedPreKeyRecord decodes a SignedPreKeyRecordStructure.
func DeserializeSignedPreKeyRecord(b []byte) (*SignedPreKeyRecord, error) {
	r, err := deserializeSignedRecord(b)
	if err != nil {
		return nil, err
	}
	return &SignedPreKeyRecord{r}, nil
}

// PublicKey returns the signed pre-key's public key.
func (r *SignedPreKeyRecord) PublicKey() (curve.PublicKey, error) {
	return curve.DeserializePublicKey(r.s.GetPublicKey())
}

// PrivateKey returns the signed pre-key's private key.
func (r *SignedPreKeyRecord) PrivateKey() (curve.PrivateKey, error) {
	return curve.DeserializePrivateKey(r.s.GetPrivateKey())
}

// KeyPair returns the signed pre-key pair.
func (r *SignedPreKeyRecord) KeyPair() (curve.KeyPair, error) {
	return curve.KeyPairFromPublicAndPrivate(r.s.GetPublicKey(), r.s.GetPrivateKey())
}

// KyberPreKeyRecord is a signed Kyber pre-key with its secret key, as kept in a
// KyberPreKeyStore (state/kyber_prekey.rs). It uses the same storage structure
// as a signed EC pre-key.
type KyberPreKeyRecord struct {
	signedRecord
}

// NewKyberPreKeyRecord builds a record for id (GenericSignedPreKey::new).
// signature is the identity key's signature over the serialized public key.
func NewKyberPreKeyRecord(id uint32, timestamp time.Time, kp kem.KeyPair, signature []byte) *KyberPreKeyRecord {
	return &KyberPreKeyRecord{newSignedRecord(id, timestamp, kp.PublicKey.Serialize(), kp.SecretKey.Serialize(), signature)}
}

// DeserializeKyberPreKeyRecord decodes a SignedPreKeyRecordStructure holding a
// Kyber key pair.
func DeserializeKyberPreKeyRecord(b []byte) (*KyberPreKeyRecord, error) {
	r, err := deserializeSignedRecord(b)
	if err != nil {
		return nil, err
	}
	return &KyberPreKeyRecord{r}, nil
}

// PublicKey returns the Kyber public key.
func (r *KyberPreKeyRecord) PublicKey() (kem.PublicKey, error) {
	return kem.DeserializePublicKey(r.s.GetPublicKey())
}

// SecretKey returns the Kyber secret key.
func (r *KyberPreKeyRecord) SecretKey() (kem.SecretKey, error) {
	return kem.DeserializeSecretKey(r.s.GetPrivateKey())
}

// KeyPair returns the Kyber key pair.
func (r *KyberPreKeyRecord) KeyPair() (kem.KeyPair, error) {
	return kem.KeyPairFromPublicAndSecret(r.s.GetPublicKey(), r.s.GetPrivateKey())
}
