package jwt

import (
	"errors"

	"crypto"
	crand "crypto/rand"

	ed448 "github.com/unix-world/smartgo/crypto/eddsa/ed448"
)

const (
	Ed448Context string = ""
)

var (
	ErrEd448Verification error = errors.New("ed448: verification error")
)

// SigningMethodEd448 implements the EdDSA family.
// Expects ed448.PrivateKey for signing and ed448.PublicKey for verification
type SigningMethodEd448 struct{}

// Specific instance for EdDSA
var (
	SigningMethodEdzDSA *SigningMethodEd448
)

func init() {
	SigningMethodEdzDSA = &SigningMethodEd448{}
	RegisterSigningMethod(SigningMethodEdzDSA.Alg(), func() SigningMethod {
		return SigningMethodEdzDSA
	})
}

func (m *SigningMethodEd448) Alg() string {
//	return "EdDSA"
	return "Ed448"
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an ed448.PublicKey
func (m *SigningMethodEd448) Verify(signingString, signature string, key interface{}) error {
	var err error
	var ed448Key ed448.PublicKey
	var ok bool

	if ed448Key, ok = key.(ed448.PublicKey); !ok {
		return ErrInvalidKeyType
	}

	if len(ed448Key) != ed448.PublicKeySize {
		return ErrInvalidKey
	}

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	// Verify the signature
	if !ed448.Verify(ed448Key, []byte(signingString), sig, Ed448Context) {
		return ErrEd448Verification
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an ed448.PrivateKey
func (m *SigningMethodEd448) Sign(signingString string, key interface{}) (string, error) {
	var ed448Key crypto.Signer
	var ok bool

	if ed448Key, ok = key.(crypto.Signer); !ok {
		return "", ErrInvalidKeyType
	}

	if _, ok := ed448Key.Public().(ed448.PublicKey); !ok {
		return "", ErrInvalidKey
	}

	// Sign the string and return the encoded result
	// ed448 performs a two-pass hash as part of its algorithm. Therefore, we need to pass a non-prehashed message into the Sign function, as indicated by crypto.Hash(0)
	sig, err := ed448Key.Sign(crand.Reader, []byte(signingString), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	return EncodeSegment(sig), nil
}

