package aes256gcmsiv_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/cwbudde/libsignal-go/aes256gcmsiv"
)

// TestRFC8452Vector checks the first AEAD_AES_256_GCM_SIV vector with a
// plaintext from RFC 8452, appendix C.2.
func TestRFC8452Vector(t *testing.T) {
	key, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	nonce, _ := hex.DecodeString("030000000000000000000000")
	plaintext, _ := hex.DecodeString("0100000000000000")
	want, _ := hex.DecodeString("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28")

	c, err := aes256gcmsiv.New(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Encrypt(plaintext, nonce, nil)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Encrypt = %x, %v; want %x", got, err, want)
	}
	back, err := c.Decrypt(got, nonce, nil)
	if err != nil || !bytes.Equal(back, plaintext) {
		t.Fatalf("Decrypt = %x, %v", back, err)
	}
	got[0] ^= 1
	if _, err := c.Decrypt(got, nonce, nil); err == nil {
		t.Error("Decrypt accepted a modified ciphertext")
	}
	if _, err := aes256gcmsiv.New(key[:16]); err == nil {
		t.Error("New accepted a 16-byte key")
	}
}
