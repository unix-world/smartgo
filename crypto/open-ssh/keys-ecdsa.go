
package openssh

import (
	"fmt"
	"errors"

	"math/big"

	"crypto"
	"crypto/elliptic"
	"crypto/ecdsa"
)

const (
//	KeyAlgoECDSA256   string = "ecdsa-sha2-nistp256"
//	KeyAlgoSKECDSA256 string = "sk-ecdsa-sha2-nistp256@openssh.com"
	KeyAlgoECDSA384   string = "ecdsa-sha2-nistp384"
	KeyAlgoECDSA521   string = "ecdsa-sha2-nistp521"
)


type openSSHECDSAPrivateKey struct {
	Curve   string
	Pub     []byte
	D       *big.Int
	Comment string
	Pad     []byte `ssh:"rest"`
}


type ecdsaPublicKey ecdsa.PublicKey


func (k *ecdsaPublicKey) Type() string {
	return "ecdsa-sha2-" + k.nistID()
}


func (k *ecdsaPublicKey) nistID() string {
	switch k.Params().BitSize {
	//	case 256:
	//		return "nistp256"
		case 384:
			return "nistp384"
		case 521:
			return "nistp521"
	}
	panic("ssh: unsupported ecdsa key size")
}


func (k *ecdsaPublicKey) Marshal() []byte {
	// See RFC 5656, section 3.1.
	keyBytes := elliptic.Marshal(k.Curve, k.X, k.Y)
	// ECDSA publickey struct layout should match the struct used by
	// parseECDSACert in the x/crypto/ssh/agent package.
	w := struct {
		Name string
		ID   string
		Key  []byte
	}{
		k.Type(),
		k.nistID(),
		keyBytes,
	}

	return Marshal(&w)
}


func (k *ecdsaPublicKey) Verify(data []byte, sig *Signature) error {
	if sig.Format != k.Type() {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}

	h := hashFuncs[sig.Format].New()
	h.Write(data)
	digest := h.Sum(nil)

	// Per RFC 5656, section 3.1.2,
	// The ecdsa_signature_blob value has the following specific encoding:
	//    mpint    r
	//    mpint    s
	var ecSig struct {
		R *big.Int
		S *big.Int
	}

	if err := Unmarshal(sig.Blob, &ecSig); err != nil {
		return err
	}

	if ecdsa.Verify((*ecdsa.PublicKey)(k), digest, ecSig.R, ecSig.S) {
		return nil
	}
	return errors.New("ssh: signature did not verify")
}


func (k *ecdsaPublicKey) CryptoPublicKey() crypto.PublicKey {
	return (*ecdsa.PublicKey)(k)
}


func supportedEllipticCurve(curve elliptic.Curve) bool {
	return curve == elliptic.P256() || curve == elliptic.P384() || curve == elliptic.P521()
}


// parseECDSA parses an ECDSA key according to RFC 5656, section 3.1.
func parseECDSA(in []byte) (out PublicKey, rest []byte, err error) {
	var w struct {
		Curve    string
		KeyBytes []byte
		Rest     []byte `ssh:"rest"`
	}

	if err := Unmarshal(in, &w); err != nil {
		return nil, nil, err
	}

	key := new(ecdsa.PublicKey)

	switch w.Curve {
	//	case "nistp256":
	//		key.Curve = elliptic.P256()
		case "nistp384":
			key.Curve = elliptic.P384()
		case "nistp521":
			key.Curve = elliptic.P521()
		default:
			return nil, nil, errors.New("ssh: unsupported curve")
	}

	key.X, key.Y = elliptic.Unmarshal(key.Curve, w.KeyBytes)
	if key.X == nil || key.Y == nil {
		return nil, nil, errors.New("ssh: invalid curve point")
	}
	return (*ecdsaPublicKey)(key), w.Rest, nil
}


//#end
