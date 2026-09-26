// Package aes256gcmsiv exposes the module's AES-256-GCM-SIV (RFC 8452), the
// AEAD sealed sender v2 uses, for callers outside the module such as
// libsignal's Aes256GcmSiv binding.
package aes256gcmsiv

import (
	"errors"

	"github.com/cwbudde/libsignal-go/internal/crypto/gcmsiv"
)

// KeySize and NonceSize are the key and nonce lengths in bytes.
const (
	KeySize   = 32
	NonceSize = 12
)

// ErrInvalidKeySize is returned for a key that is not KeySize bytes long.
var ErrInvalidKeySize = errors.New("aes256gcmsiv: invalid key size")

// Cipher is AES-256-GCM-SIV under one key.
type Cipher struct {
	key [KeySize]byte
}

// New returns the cipher for key.
func New(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	c := &Cipher{}
	copy(c.key[:], key)
	return c, nil
}

// Encrypt returns the ciphertext followed by the 16-byte tag.
func (c *Cipher) Encrypt(plaintext, nonce, associatedData []byte) ([]byte, error) {
	return gcmsiv.Seal(c.key[:], nonce, plaintext, associatedData)
}

// Decrypt authenticates and decrypts ciphertext followed by its tag.
func (c *Cipher) Decrypt(ciphertext, nonce, associatedData []byte) ([]byte, error) {
	return gcmsiv.Open(c.key[:], nonce, ciphertext, associatedData)
}
