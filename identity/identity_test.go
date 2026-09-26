package identity_test

import (
	"bytes"
	cryptorand "crypto/rand"
	"errors"
	"testing"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/identity"
)

func genKeyPair(t *testing.T) curve.KeyPair {
	t.Helper()
	kp, err := curve.GenerateKeyPair(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestKeyPairRoundTrip(t *testing.T) {
	kp := genKeyPair(t)
	serialized := identity.SerializeKeyPair(kp)
	back, err := identity.DeserializeKeyPair(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if !back.PublicKey.Equal(kp.PublicKey) || !bytes.Equal(back.PrivateKey.Serialize(), kp.PrivateKey.Serialize()) {
		t.Fatal("key pair changed in the round trip")
	}
	if _, err := identity.DeserializeKeyPair([]byte{0x0a, 0x01, 0x05}); !errors.Is(err, identity.ErrInvalidKeyPair) {
		t.Errorf("truncated public key: %v, want ErrInvalidKeyPair", err)
	}
}

func TestAlternateIdentity(t *testing.T) {
	aci, pni := genKeyPair(t), genKeyPair(t)
	sig, err := identity.SignAlternateIdentity(aci.PrivateKey, pni.PublicKey, cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.VerifyAlternateIdentity(aci.PublicKey, pni.PublicKey, sig) {
		t.Error("signature does not verify")
	}
	if identity.VerifyAlternateIdentity(pni.PublicKey, aci.PublicKey, sig) {
		t.Error("signature verifies with the roles swapped")
	}
	// A plain signature over the key is not an alternate-identity signature.
	plain, err := aci.PrivateKey.CalculateSignature(cryptorand.Reader, pni.PublicKey.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	if identity.VerifyAlternateIdentity(aci.PublicKey, pni.PublicKey, plain) {
		t.Error("a plain signature verifies as an alternate-identity signature")
	}
}

func TestIsSameAccount(t *testing.T) {
	kp, other := genKeyPair(t), genKeyPair(t)
	dev1, _ := address.NewDeviceID(1)
	dev2, _ := address.NewDeviceID(2)
	const aci = "9d0652a3-dcc3-4d11-975f-74d61598733f"
	a1 := address.NewProtocolAddress(aci, dev1)
	a2 := address.NewProtocolAddress(aci, dev2)
	pni := address.NewProtocolAddress("PNI:"+aci, dev2)
	name := address.NewProtocolAddress("alice", dev2)

	for _, c := range []struct {
		name        string
		key         curve.PublicKey
		addr        address.ProtocolAddress
		sameAccount bool
	}{
		{"other device", kp.PublicKey, a2, true},
		{"other key", other.PublicKey, a2, false},
		{"PNI of the same UUID", kp.PublicKey, pni, false},
		{"not a service ID", kp.PublicKey, name, false},
	} {
		if got := identity.IsSameAccount(kp.PublicKey, a1, c.key, c.addr); got != c.sameAccount {
			t.Errorf("%s: IsSameAccount = %v", c.name, got)
		}
	}
}
