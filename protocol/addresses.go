package protocol

import (
	"crypto/subtle"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/curve"
)

// addressesLength is the size of the encoded sender/recipient address pair:
// two fixed-width service IDs, each followed by a device id byte.
const addressesLength = 2 * (address.ServiceIDFixedWidthBinaryLen + 1)

// SerializeAddresses encodes the sender and recipient addresses for the
// SignalMessage addresses field: each address's fixed-width service ID followed
// by its device id byte, sender first. It reports false when either name is not
// a service ID string, in which case the message carries no addresses. Mirrors
// SignalMessage::serialize_addresses in protocol.rs.
func SerializeAddresses(sender, recipient address.ProtocolAddress) ([]byte, bool) {
	senderID, err := address.ParseServiceIDString(sender.Name())
	if err != nil {
		return nil, false
	}
	recipientID, err := address.ParseServiceIDString(recipient.Name())
	if err != nil {
		return nil, false
	}

	out := make([]byte, 0, addressesLength)
	senderFixed := senderID.ServiceIDFixedWidthBinary()
	out = append(out, senderFixed[:]...)
	out = append(out, byte(sender.DeviceID().Value())) //nolint:gosec // G115: device ids are at most 127
	recipientFixed := recipientID.ServiceIDFixedWidthBinary()
	out = append(out, recipientFixed[:]...)
	out = append(out, byte(recipient.DeviceID().Value())) //nolint:gosec // G115: device ids are at most 127
	return out, true
}

// Addresses returns the encoded sender/recipient addresses the message is bound
// to, or nil when it carries none.
func (m *SignalMessage) Addresses() []byte { return m.addresses }

// VerifyMACWithAddresses checks the MAC like VerifyMAC and, when the message
// carries addresses, that they name senderAddress and recipientAddress. A
// message without addresses is accepted (older senders do not include them).
// Mirrors SignalMessage::verify_mac_with_addresses.
func (m *SignalMessage) VerifyMACWithAddresses(
	senderAddress, recipientAddress address.ProtocolAddress,
	senderIdentityKey, receiverIdentityKey curve.PublicKey,
	macKey []byte,
) (bool, error) {
	ok, err := m.VerifyMAC(senderIdentityKey, receiverIdentityKey, macKey)
	if err != nil || !ok {
		return false, err
	}
	// An absent field means an older sender; a present but empty one fails
	// the comparison below, as upstream's Option does.
	if m.addresses == nil {
		return true, nil
	}
	expected, valid := SerializeAddresses(senderAddress, recipientAddress)
	if !valid {
		return false, nil
	}
	return subtle.ConstantTimeCompare(expected, m.addresses) == 1, nil
}
