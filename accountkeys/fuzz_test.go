// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package accountkeys

import (
	"strings"
	"testing"
)

// FuzzParseAccountEntropyPool parses arbitrary strings as an account entropy
// pool. It must never panic, an accepted pool must print back to the input,
// and the key derivations must not panic.
func FuzzParseAccountEntropyPool(f *testing.F) {
	f.Add(strings.Repeat("a1", accountEntropyPoolLen/2))
	f.Add(strings.Repeat("z", accountEntropyPoolLen))
	f.Add(strings.Repeat("A", accountEntropyPoolLen))
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseAccountEntropyPool(s)
		if err != nil {
			return
		}
		if p.String() != s {
			t.Fatalf("pool %q printed as %q", s, p.String())
		}
		_ = p.DeriveSVRKey()
	})
}

// knownPHC is the PHC string of TestLocalPINHashKnownPHCString.
const knownPHC = "$argon2i$v=19$m=512,t=64,p=1$ICEiIyQlJicoKSorLC0uLw$NeZzhiNv4cRmRMct9scf7d838bzmHJvrZtU/0BH0v/U"

// FuzzParsePHC parses arbitrary strings as a stored local PIN hash. It fuzzes
// parsePHC directly, because every string VerifyLocalPINHash accepts costs an
// Argon2 run (tens of milliseconds), which would starve the fuzzer; the
// target calls VerifyLocalPINHash only for strings that must fail before it.
func FuzzParsePHC(f *testing.F) {
	f.Add(knownPHC)
	f.Add(strings.Replace(knownPHC, "t=64", "t=65", 1))
	f.Add("$argon2i$v=19$m=512$$")
	f.Add("$$$$$")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		// parsePHC checks the encoded lengths only (base64 skips CR/LF, so
		// the decoded ones can differ); VerifyLocalPINHash checks the rest.
		params, salt, hash, err := parsePHC(s)
		supported := err == nil && params.alg == "argon2i" && params.version == 19 && params.memory == 512 &&
			params.time == 64 && params.parallelism == 1 && len(salt) == localPINSaltLen && len(hash) == localPINHashLen
		if supported {
			return
		}
		if _, verr := VerifyLocalPINHash(s, []byte("apassword")); verr == nil {
			t.Fatalf("VerifyLocalPINHash accepted unsupported PHC string %q", s)
		}
	})
}
