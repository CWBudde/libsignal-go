// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package testhook holds the test-only switches of the attest packages, the
// counterpart of upstream's cfg(any(test, feature = "test-util")). Being
// internal, it can be imported only under attest/, and only test files set
// it; production code never does.
package testhook

import "sync/atomic"

var veryExpiredEvalNumber atomic.Bool

// AcceptVeryExpiredEvalNumber reports whether TCB info and QE identities
// with upstream's very expired test evaluation data number are accepted.
func AcceptVeryExpiredEvalNumber() bool { return veryExpiredEvalNumber.Load() }

// SetAcceptVeryExpiredEvalNumber switches that exception and returns the
// previous setting.
func SetAcceptVeryExpiredEvalNumber(on bool) (was bool) { return veryExpiredEvalNumber.Swap(on) }
