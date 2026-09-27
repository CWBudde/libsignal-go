// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package usernames

import (
	"bytes"
	"testing"
)

// FuzzParse parses arbitrary strings as usernames. It must never panic; an
// accepted username must re-parse from its String form to the same parts, and
// its reservation hash must match the string-based hash API.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"signal.42", "Signal_Official.01", "a.1", "abc.00", "abc.123456789012345678901", "", ".", "_x.12", "héllo.12", "x.y.12"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := Parse(s)
		if err != nil {
			if _, herr := Hash(s); herr == nil {
				t.Fatalf("Hash accepted %q, which Parse rejects", s)
			}
			return
		}
		again, err := Parse(u.String())
		if err != nil {
			t.Fatalf("re-parse of %q: %v", u.String(), err)
		}
		if again.Nickname() != u.Nickname() || again.Discriminator() != u.Discriminator() {
			t.Fatalf("round trip changed %q to %q", s, again.String())
		}
		h1, err := u.Hash()
		if err != nil {
			return // a hard nickname limit, not a parse property
		}
		h2, err := Hash(s)
		if err != nil || h1 != h2 {
			t.Fatalf("Hash(%q) = %x, %v; want %x", s, h2, err, h1)
		}
	})
}

// FuzzParseLinkBuffer parses arbitrary bytes as a username link buffer
// (entropy ‖ encrypted username) and tries to decrypt it. Neither may panic;
// an accepted buffer must round-trip, and the seeded link must decrypt.
func FuzzParseLinkBuffer(f *testing.F) {
	entropy := [LinkEntropySize]byte{1, 2, 3}
	link, err := CreateLinkFromReader(bytes.NewReader(bytes.Repeat([]byte{7}, 64)), "signal.42", &entropy)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(link.Buffer())
	f.Add(make([]byte, LinkEntropySize))
	f.Add(make([]byte, LinkEntropySize+linkIVSize+linkHMACLen+16))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseLinkBuffer(b)
		if err != nil {
			return
		}
		if !bytes.Equal(l.Buffer(), b) {
			t.Fatal("link buffer does not round-trip")
		}
		name, err := DecryptUsername(l.Entropy, l.EncryptedUsername)
		if bytes.Equal(b, link.Buffer()) && (err != nil || name != "signal.42") {
			t.Fatalf("seeded link decrypted to %q, %v", name, err)
		}
	})
}

// FuzzDecodeUsernameData parses arbitrary bytes as the decrypted payload of a
// username link. DecryptUsername reaches it only past an HMAC check, so the
// fuzzer calls it directly. It must never panic, and must read back what
// encodeUsernameData wrote.
func FuzzDecodeUsernameData(f *testing.F) {
	f.Add(encodeUsernameData("signal.42", nil))
	f.Add(encodeUsernameData("signal.42", make([]byte, 20)))
	f.Add([]byte{0x0a, 0xFF})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		name, err := decodeUsernameData(b)
		if err != nil {
			return
		}
		back, err := decodeUsernameData(encodeUsernameData(name, []byte{0}))
		if err != nil || back != name {
			t.Fatalf("re-decode = %q, %v; want %q", back, err, name)
		}
	})
}
