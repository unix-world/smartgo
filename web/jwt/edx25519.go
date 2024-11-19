package jwt

import (
	"errors"

	"crypto"
	crand "crypto/rand"
	edx25519 "github.com/unix-world/smartgo/crypto/eddsa/ed25519-sha3"
)

var (
	ErrEdx25519Verification error = errors.New("edx25519: verification error")
)

// SigningMethodEdx25519 implements the EdxDSA family.
// Expects edx25519.PrivateKey for signing and edx25519.PublicKey for verification
type SigningMethodEdx25519 struct{}

// Specific instance for EdxDSA
var (
	SigningMethodEdxDSA *SigningMethodEdx25519
)

func init() {
	SigningMethodEdxDSA = &SigningMethodEdx25519{}
	RegisterSigningMethod(SigningMethodEdxDSA.Alg(), func() SigningMethod {
		return SigningMethodEdxDSA
	})
}

func (m *SigningMethodEdx25519) Alg() string {
//	return "EdxDSA"
	return "Edx25519"
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an edx25519.PublicKey
func (m *SigningMethodEdx25519) Verify(signingString, signature string, key interface{}) error {
	var err error
	var edx25519Key edx25519.PublicKey
	var ok bool

	if edx25519Key, ok = key.(edx25519.PublicKey); !ok {
		return ErrInvalidKeyType
	}

	if len(edx25519Key) != edx25519.PublicKeySize {
		return ErrInvalidKey
	}

	// Decode the signature
	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	// Verify the signature
	if !edx25519.Verify(edx25519Key, []byte(signingString), sig) {
		return ErrEdx25519Verification
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an edx25519.PrivateKey
func (m *SigningMethodEdx25519) Sign(signingString string, key interface{}) (string, error) {
	var edx25519Key crypto.Signer
	var ok bool

	if edx25519Key, ok = key.(crypto.Signer); !ok {
		return "", ErrInvalidKeyType
	}

	if _, ok := edx25519Key.Public().(edx25519.PublicKey); !ok {
		return "", ErrInvalidKey
	}

	// Sign the string and return the encoded result
	// edx25519 performs a two-pass hash as part of its algorithm. Therefore, we need to pass a non-prehashed message into the Sign function, as indicated by crypto.Hash(0)
	sig, err := edx25519Key.Sign(crand.Reader, []byte(signingString), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	return EncodeSegment(sig), nil
}

