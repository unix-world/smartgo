package jwt

// added by unixman r.20250107

import (
	"errors"

	"crypto"
	crand "crypto/rand"

	edx448 "github.com/unix-world/smartgo/crypto/eddsa/edx448"
)

const (
	Edx448Context string = ""
)

var (
	ErrEdx448Verification error = errors.New("edx448: verification error")
)

// SigningMethodEdx448 implements the EdDSA family.
// Expects edx448.PrivateKey for signing and edx448.PublicKey for verification
type SigningMethodEdx448 struct{}

// Specific instance for EdDSA
var (
	SigningMethodEdzxDSA *SigningMethodEdx448
)

func init() {
	SigningMethodEdzxDSA = &SigningMethodEdx448{}
	RegisterSigningMethod(SigningMethodEdzxDSA.Alg(), func() SigningMethod {
		return SigningMethodEdzxDSA
	})
}

func (m *SigningMethodEdx448) Alg() string {
//	return "EdDSA"
	return "Edx448"
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an edx448.PublicKey
func (m *SigningMethodEdx448) Verify(signingString, signature string, key interface{}) error {
	var err error
	var edx448Key edx448.PublicKey
	var ok bool

	if edx448Key, ok = key.(edx448.PublicKey); !ok {
		return ErrInvalidKeyType
	}

	if len(edx448Key) != edx448.PublicKeySize {
		return ErrInvalidKey
	}

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	// Verify the signature
	if !edx448.Verify(edx448Key, []byte(signingString), sig, Edx448Context) {
		return ErrEdx448Verification
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an edx448.PrivateKey
func (m *SigningMethodEdx448) Sign(signingString string, key interface{}) (string, error) {
	var edx448Key crypto.Signer
	var ok bool

	if edx448Key, ok = key.(crypto.Signer); !ok {
		return "", ErrInvalidKeyType
	}

	if _, ok := edx448Key.Public().(edx448.PublicKey); !ok {
		return "", ErrInvalidKey
	}

	// Sign the string and return the encoded result
	// edx448 performs a two-pass hash as part of its algorithm. Therefore, we need to pass a non-prehashed message into the Sign function, as indicated by crypto.Hash(0)
	sig, err := edx448Key.Sign(crand.Reader, []byte(signingString), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	return EncodeSegment(sig), nil
}

