package session

import (
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/identity"
)

// Option adjusts ProcessPreKeyBundle.
type Option func(*options)

type options struct {
	localAddress *address.ProtocolAddress
	clock        Clock
}

// WithLocalAddress sets our own address. A session counts as a self-session
// (another device of our own account, which lifts the SPQR jump limit) when the
// identity keys match and both addresses name the same service ID, as upstream
// decides it. Without it, matching identity keys are enough.
func WithLocalAddress(local address.ProtocolAddress) Option {
	return func(o *options) { o.localAddress = &local }
}

// WithClock sets the clock whose time is recorded for an unacknowledged pre-key
// message.
func WithClock(clock Clock) Option {
	return func(o *options) { o.clock = clock }
}

func applyOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func (o options) selfSession(ourIdentity, theirIdentity curve.PublicKey, remote address.ProtocolAddress) bool {
	if o.localAddress == nil {
		return ourIdentity.Equal(theirIdentity)
	}
	return identity.IsSameAccount(ourIdentity, *o.localAddress, theirIdentity, remote)
}

func (o options) unixSeconds() uint64 {
	if o.clock == nil {
		return nowUnixSeconds()
	}
	return uint64(o.clock().Unix()) //nolint:gosec // G115: a clock before 1970 is not supported, as upstream
}
