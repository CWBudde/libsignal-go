package protocol

import (
	"errors"
	"fmt"

	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/proto"
	googleproto "google.golang.org/protobuf/proto"
)

// DecryptionErrorMessage reports a failed decryption back to the sender. Its
// wire form is the bare protobuf encoding (no version byte).
type DecryptionErrorMessage struct {
	ratchetKey *curve.PublicKey
	timestamp  uint64
	deviceID   uint32
	serialized []byte
}

// NewDecryptionErrorMessage builds a DecryptionErrorMessage. ratchetKey is the
// public ratchet key from the message that failed to decrypt, or nil when the
// original message type carries none (e.g. a sender-key message).
func NewDecryptionErrorMessage(
	ratchetKey *curve.PublicKey,
	timestamp uint64,
	deviceID uint32,
) (*DecryptionErrorMessage, error) {
	protoMessage := &proto.DecryptionErrorMessage{
		Timestamp: googleproto.Uint64(timestamp),
		DeviceId:  googleproto.Uint32(deviceID),
	}
	if ratchetKey != nil {
		protoMessage.RatchetKey = ratchetKey.Serialize()
	}
	serialized, err := googleproto.Marshal(protoMessage)
	if err != nil {
		return nil, err
	}
	return &DecryptionErrorMessage{
		ratchetKey: ratchetKey,
		timestamp:  timestamp,
		deviceID:   deviceID,
		serialized: serialized,
	}, nil
}

// DeserializeDecryptionErrorMessage parses the protobuf wire form. The timestamp
// field is required; ratchet_key is optional and device_id defaults to 0.
func DeserializeDecryptionErrorMessage(value []byte) (*DecryptionErrorMessage, error) {
	var protoMessage proto.DecryptionErrorMessage
	if err := googleproto.Unmarshal(value, &protoMessage); err != nil {
		return nil, ErrInvalidProtobuf
	}
	if protoMessage.Timestamp == nil {
		return nil, ErrInvalidProtobuf
	}

	var ratchetKey *curve.PublicKey
	if rk := protoMessage.GetRatchetKey(); rk != nil {
		pk, err := curve.DeserializePublicKey(rk)
		if err != nil {
			return nil, fmt.Errorf("%w: ratchet key: %v", ErrInvalidProtobuf, err)
		}
		ratchetKey = &pk
	}

	return &DecryptionErrorMessage{
		ratchetKey: ratchetKey,
		timestamp:  protoMessage.GetTimestamp(),
		deviceID:   protoMessage.GetDeviceId(),
		serialized: append([]byte(nil), value...),
	}, nil
}

// Timestamp returns the original message timestamp (epoch milliseconds).
func (m *DecryptionErrorMessage) Timestamp() uint64 { return m.timestamp }

// RatchetKey returns the ratchet public key, or nil if the message carries none.
func (m *DecryptionErrorMessage) RatchetKey() *curve.PublicKey { return m.ratchetKey }

// DeviceID returns the original sender device ID.
func (m *DecryptionErrorMessage) DeviceID() uint32 { return m.deviceID }

// Serialized returns the protobuf wire encoding.
func (m *DecryptionErrorMessage) Serialized() []byte { return m.serialized }

// ErrNoDecryptionErrorMessage is returned when a Content message holds no
// decryption error message.
var ErrNoDecryptionErrorMessage = errors.New("protocol: content does not contain a decryption error message")

// DecryptionErrorMessageForOriginal builds the DecryptionErrorMessage for a
// message of type originalType (MessageTypeWhisper, MessageTypePreKey or
// MessageTypeSenderKey) that failed to decrypt, taking the ratchet key from
// the original bytes where the type has one (DecryptionErrorMessage::for_original).
func DecryptionErrorMessageForOriginal(originalBytes []byte, originalType uint8, timestamp uint64, deviceID uint32) (*DecryptionErrorMessage, error) {
	var ratchetKey *curve.PublicKey
	switch originalType {
	case MessageTypeWhisper:
		m, err := DeserializeSignalMessage(originalBytes)
		if err != nil {
			return nil, err
		}
		key := m.SenderRatchetKey()
		ratchetKey = &key
	case MessageTypePreKey:
		m, err := DeserializePreKeySignalMessage(originalBytes)
		if err != nil {
			return nil, err
		}
		key := m.Message().SenderRatchetKey()
		ratchetKey = &key
	case MessageTypeSenderKey:
	case MessageTypePlaintext:
		return nil, fmt.Errorf("%w: plaintext content is not encrypted", ErrInvalidArgument)
	default:
		return nil, fmt.Errorf("%w: unknown message type %d", ErrInvalidArgument, originalType)
	}
	return NewDecryptionErrorMessage(ratchetKey, timestamp, deviceID)
}

// ExtractDecryptionErrorMessageFromSerializedContent returns the decryption
// error message in a serialized Content message that ends with the padding
// boundary byte, as a decrypted PlaintextContent body does
// (extract_decryption_error_message_from_serialized_content).
func ExtractDecryptionErrorMessageFromSerializedContent(content []byte) (*DecryptionErrorMessage, error) {
	if len(content) == 0 || content[len(content)-1] != paddingBoundaryByte {
		return nil, ErrInvalidProtobuf
	}
	var c proto.Content
	if err := googleproto.Unmarshal(content[:len(content)-1], &c); err != nil {
		return nil, ErrInvalidProtobuf
	}
	if c.DecryptionErrorMessage == nil {
		return nil, ErrNoDecryptionErrorMessage
	}
	return DeserializeDecryptionErrorMessage(c.DecryptionErrorMessage)
}
