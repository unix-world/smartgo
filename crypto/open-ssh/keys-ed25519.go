
package openssh

import (
	"fmt"
	"errors"

	"crypto"
	"crypto/ed25519"
)

const (
	KeyAlgoED25519   string = "ssh-ed25519"
	KeyAlgoSKED25519 string = "sk-ssh-ed25519@openssh.com"
)


type openSSHEd25519PrivateKey struct {
	Pub     []byte
	Priv    []byte
	Comment string
	Pad     []byte `ssh:"rest"`
}


type ed25519PublicKey ed25519.PublicKey


func (k ed25519PublicKey) Type() string {
	return KeyAlgoED25519
}


func (k ed25519PublicKey) Marshal() []byte {
	w := struct {
		Name     string
		KeyBytes []byte
	}{
		KeyAlgoED25519,
		[]byte(k),
	}
	return Marshal(&w)
}


func (k ed25519PublicKey) Verify(b []byte, sig *Signature) error {
	if sig.Format != k.Type() {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}
	if l := len(k); l != ed25519.PublicKeySize {
		return fmt.Errorf("ssh: invalid size %d for Ed25519 public key", l)
	}

	if ok := ed25519.Verify(ed25519.PublicKey(k), b, sig.Blob); !ok {
		return errors.New("ssh: signature did not verify")
	}

	return nil
}


func (k ed25519PublicKey) CryptoPublicKey() crypto.PublicKey {
	return ed25519.PublicKey(k)
}


func parseED25519(in []byte) (out PublicKey, rest []byte, err error) {
	var w struct {
		KeyBytes []byte
		Rest     []byte `ssh:"rest"`
	}

	if err := Unmarshal(in, &w); err != nil {
		return nil, nil, err
	}

	if l := len(w.KeyBytes); l != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("invalid size %d for Ed25519 public key", l)
	}

	return ed25519PublicKey(w.KeyBytes), w.Rest, nil
}


//#end
