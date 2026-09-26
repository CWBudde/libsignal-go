package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/identity"
	"github.com/cwbudde/libsignal-go/internal/crypto"
	"github.com/cwbudde/libsignal-go/protocol"
	"github.com/cwbudde/libsignal-go/stores"
)

// This file ports the public 1:1 API of rust/protocol/src/session_management.rs
// and session.rs (process_prekey): message_encrypt, message_decrypt_signal and
// message_decrypt_prekey, including Sesame's trial decryption across the
// current and archived sessions. Unlike the older Encrypt / Decrypt, these take
// our own address, bind pre-key messages to both addresses, check the remote
// identity on receive, and set up the recipient session from the pre-key
// stores.

// preKeyMessageVersionX3DH is the pre-Kyber ciphertext version
// (CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION); upstream no longer accepts X3DH
// sessions.
const preKeyMessageVersionX3DH = 3

// MessageEncrypt encrypts plaintext for remoteAddress with the stored session
// (message_encrypt). While the session's pre-key message is unacknowledged it
// returns a PreKeySignalMessage whose inner message is bound to localAddress and
// remoteAddress; otherwise a SignalMessage. The session is updated only when
// the remote identity is trusted for sending.
func MessageEncrypt(
	ctx context.Context,
	plaintext []byte,
	remoteAddress, localAddress address.ProtocolAddress,
	sessionStore Store,
	identityStore stores.IdentityKeyStore,
	now time.Time,
	rng io.Reader,
) (*protocol.SignalMessage, *protocol.PreKeySignalMessage, error) {
	record, err := sessionStore.LoadSession(ctx, remoteAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("session: load session: %w", err)
	}
	if record == nil || !record.HasCurrentState() {
		return nil, nil, fmt.Errorf("%w: %s", ErrSessionNotFound, remoteAddress.String())
	}
	// Work on a copy: nothing may change unless the whole send succeeds.
	state := record.CurrentState().Clone()

	localID, err := curve.DeserializePublicKey(state.LocalIdentityPublic())
	if err != nil {
		return nil, nil, fmt.Errorf("session: local identity: %w", err)
	}
	remoteID, err := curve.DeserializePublicKey(state.RemoteIdentityPublic())
	if err != nil {
		return nil, nil, fmt.Errorf("session: remote identity: %w", err)
	}

	pending, isPreKey := state.PendingPreKeyMessage()
	if isPreKey && isStaleUnacked(pending.UnixSeconds, func() time.Time { return now }) {
		return nil, nil, fmt.Errorf("%w: stale unacknowledged session for %s", ErrSessionNotFound, remoteAddress.String())
	}

	chainKey, err := state.SenderChainKey()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSessionNotFound, err)
	}
	ratchetKey, err := state.SenderRatchetKey()
	if err != nil {
		return nil, nil, fmt.Errorf("session: sender ratchet key: %w", err)
	}
	pqrMsg, pqrKey, err := state.PQRatchetSend(rng)
	if err != nil {
		return nil, nil, err
	}
	mk, err := chainKey.MessageKeys().GenerateKeys(pqrKey)
	if err != nil {
		return nil, nil, fmt.Errorf("session: deriving message keys: %w", err)
	}
	ctext, err := crypto.EncryptCBC(plaintext, mk.CipherKey(), mk.IV())
	if err != nil {
		return nil, nil, fmt.Errorf("session: AES-CBC encrypt: %w", err)
	}

	// Only the pre-key form is bound to the addresses (OutgoingTripleRatchet
	// encrypt gets the local address only for pre-key messages).
	var addresses []byte
	if isPreKey {
		addresses, _ = protocol.SerializeAddresses(localAddress, remoteAddress)
	}
	version := uint8(state.SessionVersion()) //nolint:gosec // G115: the session version is 3 or 4
	signal, err := protocol.NewSignalMessage(
		version, mk.MACKey(), ratchetKey, chainKey.Index(), state.PreviousCounter(),
		ctext, localID, remoteID, pqrMsg, addresses,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("session: building SignalMessage: %w", err)
	}

	var preKey *protocol.PreKeySignalMessage
	if isPreKey {
		base, err := curve.DeserializePublicKey(pending.BaseKey)
		if err != nil {
			return nil, nil, fmt.Errorf("session: pending base key: %w", err)
		}
		preKey, err = protocol.NewPreKeySignalMessage(
			version, state.LocalRegistrationID(), pending.PreKeyID, pending.SignedPreKeyID,
			pending.KyberPreKeyID, pending.KyberCiphertext, base, localID, signal,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("session: building PreKeySignalMessage: %w", err)
		}
		signal = nil
	}

	trusted, err := identityStore.IsTrustedIdentity(ctx, remoteAddress, remoteID, stores.Sending)
	if err != nil {
		return nil, nil, fmt.Errorf("session: trust check: %w", err)
	}
	if !trusted {
		return nil, nil, fmt.Errorf("%w: %s", ErrUntrustedIdentity, remoteAddress.String())
	}
	if _, err := identityStore.SaveIdentity(ctx, remoteAddress, remoteID); err != nil {
		return nil, nil, fmt.Errorf("session: save identity: %w", err)
	}

	if err := state.SetSenderChainKey(chainKey.Next()); err != nil {
		return nil, nil, fmt.Errorf("session: advancing sender chain: %w", err)
	}
	record.SetCurrentState(state)
	if err := sessionStore.StoreSession(ctx, remoteAddress, record); err != nil {
		return nil, nil, fmt.Errorf("session: store session: %w", err)
	}
	return signal, preKey, nil
}

// MessageDecryptSignal decrypts a SignalMessage from remoteAddress
// (message_decrypt_signal). It tries the current session and then the archived
// ones, promoting an archived session that decrypts. After decryption the
// remote identity must be trusted for receiving; only then is the session
// stored.
func MessageDecryptSignal(
	ctx context.Context,
	ciphertext *protocol.SignalMessage,
	remoteAddress, localAddress address.ProtocolAddress,
	sessionStore Store,
	identityStore stores.IdentityKeyStore,
	rng io.Reader,
) ([]byte, error) {
	record, err := sessionStore.LoadSession(ctx, remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("session: load session: %w", err)
	}
	if record == nil {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, remoteAddress.String())
	}

	ptext, err := tryDecryptFromRecord(record, remoteAddress, localAddress, ciphertext, false, rng)
	if err != nil {
		return nil, err
	}

	// Decryption succeeded, so the current session has a remote identity.
	remoteID, err := curve.DeserializePublicKey(record.CurrentState().RemoteIdentityPublic())
	if err != nil {
		return nil, fmt.Errorf("session: remote identity: %w", err)
	}
	trusted, err := identityStore.IsTrustedIdentity(ctx, remoteAddress, remoteID, stores.Receiving)
	if err != nil {
		return nil, fmt.Errorf("session: trust check: %w", err)
	}
	if !trusted {
		return nil, fmt.Errorf("%w: %s", ErrUntrustedIdentity, remoteAddress.String())
	}
	if _, err := identityStore.SaveIdentity(ctx, remoteAddress, remoteID); err != nil {
		return nil, fmt.Errorf("session: save identity: %w", err)
	}
	if err := sessionStore.StoreSession(ctx, remoteAddress, record); err != nil {
		return nil, fmt.Errorf("session: store session: %w", err)
	}
	return ptext, nil
}

// MessageDecryptPreKey decrypts a PreKeySignalMessage from remoteAddress
// (message_decrypt_prekey). Unless the message belongs to a session that is
// already set up, it sets up the recipient session from our pre-keys (the
// one-time pre-key is optional, the signed and Kyber pre-keys are required),
// then decrypts the inner message. On success it saves the sender's identity,
// marks the Kyber pre-key used, removes the one-time pre-key, and stores the
// session.
func MessageDecryptPreKey(
	ctx context.Context,
	ciphertext *protocol.PreKeySignalMessage,
	remoteAddress, localAddress address.ProtocolAddress,
	sessionStore Store,
	identityStore stores.IdentityKeyStore,
	preKeyStore stores.PreKeyStore,
	signedPreKeyStore stores.SignedPreKeyStore,
	kyberPreKeyStore stores.KyberPreKeyStore,
	rng io.Reader,
) ([]byte, error) {
	record, err := sessionStore.LoadSession(ctx, remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("session: load session: %w", err)
	}
	if record == nil {
		record = NewFreshSessionRecord()
	}

	used, err := processPreKey(ctx, ciphertext, remoteAddress, localAddress, record,
		identityStore, preKeyStore, signedPreKeyStore, kyberPreKeyStore)
	if err != nil {
		return nil, err
	}

	ptext, err := tryDecryptFromRecord(record, remoteAddress, localAddress, ciphertext.Message(), true, rng)
	if err != nil {
		return nil, err
	}

	if _, err := identityStore.SaveIdentity(ctx, remoteAddress, ciphertext.IdentityKey()); err != nil {
		return nil, fmt.Errorf("session: save identity: %w", err)
	}
	if used != nil {
		if used.kyberPreKeyID != nil {
			err := kyberPreKeyStore.MarkKyberPreKeyUsed(ctx, *used.kyberPreKeyID, used.signedPreKeyID, ciphertext.BaseKey())
			if err != nil {
				return nil, fmt.Errorf("session: mark Kyber pre-key used: %w", err)
			}
		}
		if used.oneTimePreKeyID != nil {
			if err := preKeyStore.RemovePreKey(ctx, *used.oneTimePreKeyID); err != nil {
				return nil, fmt.Errorf("session: remove pre-key: %w", err)
			}
		}
	}
	if err := sessionStore.StoreSession(ctx, remoteAddress, record); err != nil {
		return nil, fmt.Errorf("session: store session: %w", err)
	}
	return ptext, nil
}

// preKeysUsed names the pre-keys a pre-key message consumed (PreKeysUsed).
type preKeysUsed struct {
	oneTimePreKeyID *uint32
	signedPreKeyID  uint32
	kyberPreKeyID   *uint32
}

// processPreKey sets up the recipient session for a pre-key message in record
// (session::process_prekey). It returns nil when record already holds the
// session the message belongs to.
func processPreKey(
	ctx context.Context,
	message *protocol.PreKeySignalMessage,
	remoteAddress, localAddress address.ProtocolAddress,
	record *SessionRecord,
	identityStore stores.IdentityKeyStore,
	preKeyStore stores.PreKeyStore,
	signedPreKeyStore stores.SignedPreKeyStore,
	kyberPreKeyStore stores.KyberPreKeyStore,
) (*preKeysUsed, error) {
	theirIdentity := message.IdentityKey()
	trusted, err := identityStore.IsTrustedIdentity(ctx, remoteAddress, theirIdentity, stores.Receiving)
	if err != nil {
		return nil, fmt.Errorf("session: trust check: %w", err)
	}
	if !trusted {
		return nil, fmt.Errorf("%w: %s", ErrUntrustedIdentity, remoteAddress.String())
	}

	matched, err := record.PromoteMatchingSession(uint32(message.MessageVersion()), message.BaseKey().Serialize())
	if err != nil {
		return nil, err
	}
	if matched {
		return nil, nil
	}
	// Checked after looking for an existing session, like upstream: a session
	// that already exists was set up before X3DH was dropped.
	if message.MessageVersion() == preKeyMessageVersionX3DH {
		return nil, fmt.Errorf("%w: X3DH no longer supported", ErrInvalidMessage)
	}

	signedBytes, err := signedPreKeyStore.GetSignedPreKey(ctx, message.SignedPreKeyID())
	if err != nil {
		return nil, fmt.Errorf("session: load signed pre-key %d: %w", message.SignedPreKeyID(), err)
	}
	signedRecord, err := DeserializeSignedPreKeyRecord(signedBytes)
	if err != nil {
		return nil, err
	}
	ourSignedPre, err := signedRecord.KeyPair()
	if err != nil {
		return nil, fmt.Errorf("%w: signed pre-key: %v", ErrInvalidKey, err)
	}

	kyberID := message.KyberPreKeyID()
	if kyberID == nil {
		return nil, fmt.Errorf("%w: missing pq pre-key ID", ErrInvalidMessage)
	}
	kyberBytes, err := kyberPreKeyStore.GetKyberPreKey(ctx, *kyberID)
	if err != nil {
		return nil, fmt.Errorf("session: load Kyber pre-key %d: %w", *kyberID, err)
	}
	kyberRecord, err := DeserializeKyberPreKeyRecord(kyberBytes)
	if err != nil {
		return nil, err
	}
	ourKyber, err := kyberRecord.KeyPair()
	if err != nil {
		return nil, fmt.Errorf("%w: Kyber pre-key: %v", ErrInvalidKey, err)
	}
	if len(message.KyberCiphertext()) == 0 {
		return nil, fmt.Errorf("%w: missing pq ciphertext", ErrInvalidMessage)
	}

	var ourOneTime *curve.KeyPair
	if id := message.PreKeyID(); id != nil {
		b, err := preKeyStore.GetPreKey(ctx, *id)
		if err != nil {
			return nil, fmt.Errorf("session: load pre-key %d: %w", *id, err)
		}
		r, err := DeserializePreKeyRecord(b)
		if err != nil {
			return nil, err
		}
		kp, err := r.KeyPair()
		if err != nil {
			return nil, fmt.Errorf("%w: one-time pre-key: %v", ErrInvalidKey, err)
		}
		ourOneTime = &kp
	}

	ourIdentity, err := identityStore.GetIdentityKeyPair(ctx)
	if err != nil {
		return nil, fmt.Errorf("session: identity key pair: %w", err)
	}
	state, err := initializeBobSession(BobParams{
		OurIdentity:   ourIdentity,
		OurSignedPre:  ourSignedPre,
		OurOneTime:    ourOneTime,
		OurKyber:      ourKyber,
		TheirIdentity: theirIdentity,
		TheirBaseKey:  message.BaseKey(),
		KyberCipher:   message.KyberCiphertext(),
	}, identity.IsSameAccount(ourIdentity.PublicKey, localAddress, theirIdentity, remoteAddress))
	if err != nil {
		return nil, err
	}
	localRegistrationID, err := identityStore.GetLocalRegistrationID(ctx)
	if err != nil {
		return nil, fmt.Errorf("session: local registration id: %w", err)
	}
	state.SetLocalRegistrationID(localRegistrationID)
	state.SetRemoteRegistrationID(message.RegistrationID())
	if err := record.PromoteState(state); err != nil {
		return nil, err
	}

	return &preKeysUsed{
		oneTimePreKeyID: message.PreKeyID(),
		signedPreKeyID:  message.SignedPreKeyID(),
		kyberPreKeyID:   kyberID,
	}, nil
}

// tryDecryptFromRecord decrypts ciphertext with the current session of record
// or, for a SignalMessage, with an archived one, which is then promoted
// (try_decrypt_from_record). The inner message of a pre-key message only tries
// the current session, which processPreKey just set up or matched. A
// duplicate message fails at once; other failures are collected and reported as
// ErrInvalidMessage once every session has been tried. record changes only on
// success.
func tryDecryptFromRecord(
	record *SessionRecord,
	remoteAddress, localAddress address.ProtocolAddress,
	ciphertext *protocol.SignalMessage,
	isPreKey bool,
	rng io.Reader,
) ([]byte, error) {
	var errs []error

	if record.HasCurrentState() {
		state := record.CurrentState().Clone()
		ptext, err := tryDecryptWithState(state, remoteAddress, localAddress, ciphertext, rng)
		switch {
		case err == nil:
			record.SetCurrentState(state)
			return ptext, nil
		case errors.Is(err, ErrDuplicateMessage):
			return nil, err
		case isPreKey:
			return nil, fmt.Errorf("%w: decryption failed (%v)", ErrInvalidMessage, err)
		}
		errs = append(errs, fmt.Errorf("current session: %w", err))
	}

	for i := range record.previousSessions {
		state, err := record.previousState(i)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ptext, err := tryDecryptWithState(state, remoteAddress, localAddress, ciphertext, rng)
		switch {
		case err == nil:
			if err := record.promoteOldSessionWithState(i, state); err != nil {
				return nil, err
			}
			return ptext, nil
		case errors.Is(err, ErrDuplicateMessage):
			return nil, err
		}
		errs = append(errs, fmt.Errorf("previous session %d: %w", i, err))
	}

	if len(errs) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, remoteAddress.String())
	}
	return nil, fmt.Errorf("%w: decryption failed (%v)", ErrInvalidMessage, errors.Join(errs...))
}

// tryDecryptWithState decrypts ciphertext with state, which the caller owns
// and discards on failure (try_decrypt_with_state). A self-session has no limit
// on how far a counter may skip ahead.
func tryDecryptWithState(
	state *SessionState,
	remoteAddress, localAddress address.ProtocolAddress,
	ciphertext *protocol.SignalMessage,
	rng io.Reader,
) ([]byte, error) {
	maxJumps := uint32(MaxForwardJumps)
	localID, errLocal := curve.DeserializePublicKey(state.LocalIdentityPublic())
	remoteID, errRemote := curve.DeserializePublicKey(state.RemoteIdentityPublic())
	if errLocal == nil && errRemote == nil && identity.IsSameAccount(localID, localAddress, remoteID, remoteAddress) {
		maxJumps = math.MaxUint32
	}
	return decryptWithState(state, ciphertext, rng, decryptParams{
		maxForwardJumps: maxJumps,
		sender:          &remoteAddress,
		recipient:       &localAddress,
	})
}
