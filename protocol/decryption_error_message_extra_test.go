package protocol

import (
	cryptorand "crypto/rand"
	"errors"
	"testing"

	"github.com/cwbudde/libsignal-go/curve"
)

func TestDecryptionErrorMessageForOriginal(t *testing.T) {
	ratchet, err := curve.GenerateKeyPair(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ident, err := curve.GenerateKeyPair(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	macKey := make([]byte, 32)
	signal, err := NewSignalMessage(CurrentVersion, macKey, ratchet.PublicKey, 1, 0, []byte("ciphertext"),
		ident.PublicKey, ident.PublicKey, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	dem, err := DecryptionErrorMessageForOriginal(signal.Serialize(), MessageTypeWhisper, 1234, 5)
	if err != nil {
		t.Fatal(err)
	}
	if dem.RatchetKey() == nil || !dem.RatchetKey().Equal(ratchet.PublicKey) || dem.Timestamp() != 1234 || dem.DeviceID() != 5 {
		t.Fatalf("unexpected message: ratchet %v, timestamp %d, device %d", dem.RatchetKey(), dem.Timestamp(), dem.DeviceID())
	}

	senderKey, err := DecryptionErrorMessageForOriginal([]byte("whatever"), MessageTypeSenderKey, 1, 2)
	if err != nil || senderKey.RatchetKey() != nil {
		t.Errorf("sender key message: %v, ratchet %v", err, senderKey.RatchetKey())
	}
	if _, err := DecryptionErrorMessageForOriginal(nil, MessageTypePlaintext, 1, 2); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("plaintext: %v, want ErrInvalidArgument", err)
	}
	if _, err := DecryptionErrorMessageForOriginal([]byte{1}, MessageTypeWhisper, 1, 2); err == nil {
		t.Error("garbage whisper message accepted")
	}

	// The body of a PlaintextContent made from the message yields it back.
	content, err := NewPlaintextContentFromDecryptionError(dem)
	if err != nil {
		t.Fatal(err)
	}
	extracted, err := ExtractDecryptionErrorMessageFromSerializedContent(content.Body())
	if err != nil {
		t.Fatal(err)
	}
	if string(extracted.Serialized()) != string(dem.Serialized()) {
		t.Error("extracted message differs")
	}
	if _, err := ExtractDecryptionErrorMessageFromSerializedContent([]byte{0x80}); !errors.Is(err, ErrNoDecryptionErrorMessage) {
		t.Errorf("empty content: %v, want ErrNoDecryptionErrorMessage", err)
	}
	if _, err := ExtractDecryptionErrorMessageFromSerializedContent([]byte{0x01}); !errors.Is(err, ErrInvalidProtobuf) {
		t.Errorf("no padding boundary: %v, want ErrInvalidProtobuf", err)
	}
}
