// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package enclave

import "github.com/cwbudde/libsignal-go/attest/internal/testhook"

// VeryExpiredTestEvalNumberDefault is the setting of the test-only
// evaluation number exception before this file turned it on, for the
// recorded cds2_test blob, as upstream's tests run with test-util.
var VeryExpiredTestEvalNumberDefault = testhook.SetAcceptVeryExpiredEvalNumber(true)
