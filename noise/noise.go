// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package noise implements the two Noise handshakes libsignal uses to open an
// encrypted channel to an SGX enclave (CDSI, SVR2), compatible with
// rust/attest/src/client_connection.rs at libsignal v0.102.2, which drives the
// snow 0.10.0 crate:
//
//	Noise_NK_25519_ChaChaPoly_SHA256
//	Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256
//
// Only these two patterns are supported. The "Kyber1024" KEM is ML-KEM-1024
// (FIPS 203), as in libsignal's snow resolver, not the round-3 Kyber1024 of
// the kem package. The prologue is empty and no PSKs are used.
package noise

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Pattern selects one of the two supported handshakes.
type Pattern uint8

const (
	// NK is Noise_NK_25519_ChaChaPoly_SHA256:
	//
	//	<- s
	//	...
	//	-> e, es
	//	<- e, ee
	NK Pattern = iota + 1
	// NKhfs is Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256. snow places e1
	// after the DH of the first message, so the KEM public key is encrypted:
	//
	//	<- s
	//	...
	//	-> e, es, e1
	//	<- e, ee, ekem1
	NKhfs
)

// Sizes of the wire elements.
const (
	// KeySize is the size of X25519 private and public keys.
	KeySize = 32
	// TagSize is the size of a ChaCha20-Poly1305 tag.
	TagSize = 16
	// MaxMessageSize is the largest Noise message, handshake or transport.
	MaxMessageSize = 65535
	// MaxPayloadSize is the largest plaintext in one transport message.
	MaxPayloadSize = MaxMessageSize - TagSize
	// KEMPublicKeySize is the size of an ML-KEM-1024 encapsulation key.
	KEMPublicKeySize = mlkem.EncapsulationKeySize1024
	// KEMCiphertextSize is the size of an ML-KEM-1024 ciphertext.
	KEMCiphertextSize = mlkem.CiphertextSize1024
)

const (
	nkName    = "Noise_NK_25519_ChaChaPoly_SHA256"
	nkhfsName = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256"
	// kemSeedSize is the d‖z seed of an ML-KEM key pair.
	kemSeedSize = mlkem.SeedSize
)

// Errors returned by the handshake and transport. Decryption failures wrap
// ErrDecrypt; a failed handshake additionally leaves the state unusable
// (ErrFailed).
var (
	ErrInvalidPattern   = errors.New("noise: unsupported pattern")
	ErrInvalidKey       = errors.New("noise: invalid key")
	ErrNotYourTurn      = errors.New("noise: not this side's turn")
	ErrHandshakeDone    = errors.New("noise: handshake already finished")
	ErrHandshakePending = errors.New("noise: handshake not finished")
	ErrFailed           = errors.New("noise: handshake failed earlier")
	ErrMessageSize      = errors.New("noise: message size out of range")
	ErrDecrypt          = errors.New("noise: decryption failed")
	ErrNonceExhausted   = errors.New("noise: nonce exhausted")
	ErrRandom           = errors.New("noise: reading randomness")
)

// Name returns the Noise protocol name.
func (p Pattern) Name() string {
	switch p {
	case NK:
		return nkName
	case NKhfs:
		return nkhfsName
	default:
		return fmt.Sprintf("Pattern(%d)", uint8(p))
	}
}

func (p Pattern) valid() bool { return p == NK || p == NKhfs }

// overhead returns the non-payload bytes of handshake message i.
func (p Pattern) overhead(i int) int {
	n := KeySize + TagSize // e, then the payload tag (a key is set after es/ee)
	if p == NKhfs {
		if i == 0 {
			n += KEMPublicKeySize + TagSize // e1
		} else {
			n += KEMCiphertextSize + TagSize // ekem1
		}
	}
	return n
}

// HandshakeState runs one side of a handshake. Messages alternate: the
// initiator writes message 0, the responder writes message 1, after which
// Transport returns the channel. It is not safe for concurrent use.
type HandshakeState struct {
	pattern   Pattern
	initiator bool
	rand      io.Reader
	ss        symmetricState
	next      int // index of the next message, 0 or 1
	failed    bool

	s  *ecdh.PrivateKey // responder's static key
	rs *ecdh.PublicKey  // initiator's copy of the responder's static key
	e  *ecdh.PrivateKey
	re *ecdh.PublicKey

	kemKey    *mlkem.DecapsulationKey1024 // initiator (e1)
	kemRemote *mlkem.EncapsulationKey1024 // responder (from e1)

	// encapsulate is replaced by tests with a derandomized version.
	encapsulate func(ek *mlkem.EncapsulationKey1024, rand io.Reader) (sharedKey, ciphertext []byte, err error)
}

// NewInitiator starts the client side, which knows the responder's static
// X25519 public key in advance. A nil rand uses crypto/rand.
func NewInitiator(p Pattern, remoteStatic []byte, rand io.Reader) (*HandshakeState, error) {
	if !p.valid() {
		return nil, ErrInvalidPattern
	}
	rs, err := ecdh.X25519().NewPublicKey(remoteStatic)
	if err != nil {
		return nil, fmt.Errorf("%w: remote static key: %w", ErrInvalidKey, err)
	}
	hs := newState(p, true, rand)
	hs.rs = rs
	hs.ss.mixHash(rs.Bytes()) // pre-message <- s
	return hs, nil
}

// NewResponder starts the server side with its static X25519 private key.
// A nil rand uses crypto/rand.
func NewResponder(p Pattern, staticPrivate []byte, rand io.Reader) (*HandshakeState, error) {
	if !p.valid() {
		return nil, ErrInvalidPattern
	}
	s, err := ecdh.X25519().NewPrivateKey(staticPrivate)
	if err != nil {
		return nil, fmt.Errorf("%w: static key: %w", ErrInvalidKey, err)
	}
	hs := newState(p, false, rand)
	hs.s = s
	hs.ss.mixHash(s.PublicKey().Bytes()) // pre-message <- s
	return hs, nil
}

func newState(p Pattern, initiator bool, r io.Reader) *HandshakeState {
	if r == nil {
		r = rand.Reader
	}
	hs := &HandshakeState{pattern: p, initiator: initiator, rand: r, encapsulate: encapsulate}
	hs.ss.initialize(p.Name())
	hs.ss.mixHash(nil) // empty prologue
	return hs
}

func encapsulate(ek *mlkem.EncapsulationKey1024, _ io.Reader) (sharedKey, ciphertext []byte, err error) {
	sharedKey, ciphertext = ek.Encapsulate()
	return sharedKey, ciphertext, nil
}

// Finished reports whether both handshake messages have been processed.
func (hs *HandshakeState) Finished() bool { return hs.next == 2 }

func (hs *HandshakeState) check(writing bool) error {
	switch {
	case hs.failed:
		return ErrFailed
	case hs.Finished():
		return ErrHandshakeDone
	case writing != (hs.initiator == (hs.next == 0)):
		return ErrNotYourTurn
	}
	return nil
}

// WriteMessage returns the next handshake message carrying payload.
func (hs *HandshakeState) WriteMessage(payload []byte) ([]byte, error) {
	if err := hs.check(true); err != nil {
		return nil, err
	}
	overhead := hs.pattern.overhead(hs.next)
	if len(payload) > MaxMessageSize-overhead {
		return nil, ErrMessageSize
	}
	msg, err := hs.writeTokens(make([]byte, 0, overhead+len(payload)))
	if err != nil {
		hs.failed = true
		return nil, err
	}
	msg = hs.ss.encryptAndHash(msg, payload)
	hs.next++
	return msg, nil
}

func (hs *HandshakeState) writeTokens(msg []byte) ([]byte, error) {
	// e
	var seed [KeySize]byte
	if _, err := io.ReadFull(hs.rand, seed[:]); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRandom, err)
	}
	e, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %w", ErrInvalidKey, err)
	}
	hs.e = e
	msg = append(msg, e.PublicKey().Bytes()...)
	hs.ss.mixHash(e.PublicKey().Bytes())

	if hs.next == 0 {
		// es (initiator side: DH(e, rs))
		if err := hs.mixDH(hs.e, hs.rs); err != nil {
			return nil, err
		}
		if hs.pattern == NKhfs {
			// e1
			var kemSeed [kemSeedSize]byte
			if _, err := io.ReadFull(hs.rand, kemSeed[:]); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrRandom, err)
			}
			dk, err := mlkem.NewDecapsulationKey1024(kemSeed[:])
			if err != nil {
				return nil, fmt.Errorf("%w: KEM key: %w", ErrInvalidKey, err)
			}
			hs.kemKey = dk
			msg = hs.ss.encryptAndHash(msg, dk.EncapsulationKey().Bytes())
		}
		return msg, nil
	}

	// ee
	if err := hs.mixDH(hs.e, hs.re); err != nil {
		return nil, err
	}
	if hs.pattern == NKhfs {
		// ekem1
		shared, ct, err := hs.encapsulate(hs.kemRemote, hs.rand)
		if err != nil {
			return nil, fmt.Errorf("%w: KEM encapsulation: %w", ErrRandom, err)
		}
		msg = hs.ss.encryptAndHash(msg, ct)
		hs.ss.mixKey(shared)
	}
	return msg, nil
}

// ReadMessage processes the peer's next handshake message and returns its
// payload. Any failure leaves the handshake unusable.
func (hs *HandshakeState) ReadMessage(msg []byte) ([]byte, error) {
	if err := hs.check(false); err != nil {
		return nil, err
	}
	if len(msg) > MaxMessageSize || len(msg) < hs.pattern.overhead(hs.next) {
		hs.failed = true
		return nil, ErrMessageSize
	}
	payload, err := hs.readTokens(msg)
	if err != nil {
		hs.failed = true
		return nil, err
	}
	hs.next++
	return payload, nil
}

func (hs *HandshakeState) readTokens(msg []byte) ([]byte, error) {
	// e
	re, err := ecdh.X25519().NewPublicKey(msg[:KeySize])
	if err != nil {
		return nil, fmt.Errorf("%w: remote ephemeral key: %w", ErrInvalidKey, err)
	}
	hs.re = re
	hs.ss.mixHash(msg[:KeySize])
	msg = msg[KeySize:]

	if hs.next == 0 {
		// es (responder side: DH(s, re))
		if err := hs.mixDH(hs.s, hs.re); err != nil {
			return nil, err
		}
		if hs.pattern == NKhfs {
			// e1
			n := KEMPublicKeySize + TagSize
			raw, err := hs.ss.decryptAndHash(msg[:n])
			if err != nil {
				return nil, err
			}
			ek, err := mlkem.NewEncapsulationKey1024(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: KEM public key: %w", ErrInvalidKey, err)
			}
			hs.kemRemote = ek
			msg = msg[n:]
		}
	} else {
		// ee
		if err := hs.mixDH(hs.e, hs.re); err != nil {
			return nil, err
		}
		if hs.pattern == NKhfs {
			// ekem1
			n := KEMCiphertextSize + TagSize
			ct, err := hs.ss.decryptAndHash(msg[:n])
			if err != nil {
				return nil, err
			}
			shared, err := hs.kemKey.Decapsulate(ct)
			if err != nil {
				return nil, fmt.Errorf("%w: KEM ciphertext: %w", ErrInvalidKey, err)
			}
			hs.ss.mixKey(shared)
			msg = msg[n:]
		}
	}
	return hs.ss.decryptAndHash(msg)
}

// mixDH mixes an X25519 agreement into the chaining key. An all-zero result
// (a low-order peer key) is rejected; snow would accept it.
func (hs *HandshakeState) mixDH(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) error {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return fmt.Errorf("%w: X25519: %w", ErrInvalidKey, err)
	}
	hs.ss.mixKey(shared)
	return nil
}

// Transport returns the established channel once the handshake has finished.
// The handshake's secrets are dropped; call it once.
func (hs *HandshakeState) Transport() (*Transport, error) {
	if hs.failed {
		return nil, ErrFailed
	}
	if !hs.Finished() {
		return nil, ErrHandshakePending
	}
	c1, c2 := hs.ss.split()
	t := &Transport{hash: append([]byte(nil), hs.ss.h[:]...)}
	if hs.initiator {
		t.send, t.recv = c1, c2
	} else {
		t.send, t.recv = c2, c1
	}
	hs.e, hs.s, hs.kemKey, hs.ss = nil, nil, nil, symmetricState{}
	hs.failed = true // the state is spent
	return t, nil
}

// Transport is an established channel. Send and Recv split long input into
// several Noise messages like libsignal's ClientConnection. It is not safe
// for concurrent use.
type Transport struct {
	send, recv cipherState
	hash       []byte
}

// HandshakeHash returns the final handshake hash h, which both sides share.
func (t *Transport) HandshakeHash() []byte { return append([]byte(nil), t.hash...) }

// Send encrypts plaintext in chunks of at most MaxPayloadSize bytes and
// returns the concatenated messages. Empty plaintext gives empty output.
func (t *Transport) Send(plaintext []byte) ([]byte, error) {
	chunks := (len(plaintext) + MaxPayloadSize - 1) / MaxPayloadSize
	out := make([]byte, 0, len(plaintext)+chunks*TagSize)
	for len(plaintext) > 0 {
		n := min(len(plaintext), MaxPayloadSize)
		var err error
		if out, err = t.send.encrypt(out, nil, plaintext[:n]); err != nil {
			return nil, err
		}
		plaintext = plaintext[n:]
	}
	return out, nil
}

// Recv decrypts ciphertext split into chunks of MaxMessageSize bytes, the
// inverse of Send. Chunks decrypted before a failure have consumed their
// nonces, as in libsignal.
func (t *Transport) Recv(ciphertext []byte) ([]byte, error) {
	out := make([]byte, 0, len(ciphertext))
	for len(ciphertext) > 0 {
		n := min(len(ciphertext), MaxMessageSize)
		var err error
		if out, err = t.recv.decrypt(out, nil, ciphertext[:n]); err != nil {
			return nil, err
		}
		ciphertext = ciphertext[n:]
	}
	return out, nil
}
