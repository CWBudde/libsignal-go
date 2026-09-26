// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package noise

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

const hashSize = sha256.Size

// cipherState is the Noise CipherState for ChaChaPoly. The zero value has no
// key and must not be used to encrypt.
type cipherState struct {
	aead cipher.AEAD
	n    uint64
}

func newCipherState(key []byte) cipherState {
	aead, err := chacha20poly1305.New(key[:chacha20poly1305.KeySize])
	if err != nil {
		panic(fmt.Sprintf("noise: ChaCha20-Poly1305 key: %v", err)) // the key size is fixed
	}
	return cipherState{aead: aead}
}

func (c *cipherState) hasKey() bool { return c.aead != nil }

// nonce encodes n as in snow: four zero bytes, then n little-endian.
func (c *cipherState) nonce() []byte {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], c.n)
	return nonce[:]
}

func (c *cipherState) encrypt(dst, ad, plaintext []byte) ([]byte, error) {
	if c.n == math.MaxUint64 {
		return nil, ErrNonceExhausted
	}
	out := c.aead.Seal(dst, c.nonce(), plaintext, ad)
	c.n++
	return out, nil
}

// decrypt leaves the nonce unchanged on failure.
func (c *cipherState) decrypt(dst, ad, ciphertext []byte) ([]byte, error) {
	if c.n == math.MaxUint64 {
		return nil, ErrNonceExhausted
	}
	if len(ciphertext) < TagSize {
		return nil, ErrDecrypt
	}
	out, err := c.aead.Open(dst, c.nonce(), ciphertext, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	c.n++
	return out, nil
}

// symmetricState is the Noise SymmetricState over SHA-256.
type symmetricState struct {
	ck, h [hashSize]byte
	cs    cipherState
}

func (s *symmetricState) initialize(name string) {
	if len(name) <= hashSize {
		copy(s.h[:], name)
	} else {
		s.h = sha256.Sum256([]byte(name))
	}
	s.ck = s.h
}

func (s *symmetricState) mixHash(data []byte) {
	d := sha256.New()
	d.Write(s.h[:])
	d.Write(data)
	d.Sum(s.h[:0])
}

func (s *symmetricState) mixKey(ikm []byte) {
	ck, key := hkdf2(s.ck[:], ikm)
	s.ck = ck
	s.cs = newCipherState(key[:])
}

// encryptAndHash appends the (encrypted, once a key is set) plaintext to dst.
func (s *symmetricState) encryptAndHash(dst, plaintext []byte) []byte {
	start := len(dst)
	if s.cs.hasKey() {
		var err error
		if dst, err = s.cs.encrypt(dst, s.h[:], plaintext); err != nil {
			// A handshake uses at most three nonces per key.
			panic(err)
		}
	} else {
		dst = append(dst, plaintext...)
	}
	s.mixHash(dst[start:])
	return dst
}

func (s *symmetricState) decryptAndHash(data []byte) ([]byte, error) {
	var plaintext []byte
	if s.cs.hasKey() {
		var err error
		if plaintext, err = s.cs.decrypt(nil, s.h[:], data); err != nil {
			return nil, err
		}
	} else {
		plaintext = append([]byte(nil), data...)
	}
	s.mixHash(data)
	return plaintext, nil
}

func (s *symmetricState) split() (c1, c2 cipherState) {
	k1, k2 := hkdf2(s.ck[:], nil)
	return newCipherState(k1[:]), newCipherState(k2[:])
}

// hkdf2 is Noise's HKDF with two outputs (snow types.rs Hash::hkdf).
func hkdf2(chainingKey, ikm []byte) (out1, out2 [hashSize]byte) {
	m := hmac.New(sha256.New, chainingKey)
	m.Write(ikm)
	temp := m.Sum(nil)

	m = hmac.New(sha256.New, temp)
	m.Write([]byte{1})
	m.Sum(out1[:0])

	m.Reset()
	m.Write(out1[:])
	m.Write([]byte{2})
	m.Sum(out2[:0])
	return out1, out2
}
