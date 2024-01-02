package jwt

// modified by unixman: added SHA-3 based hash signatures
// r.20240102.2114

import (
	"errors"

	"crypto"
	"crypto/hmac"

//	_ "golang.org/x/crypto/sha3"
	"github.com/unix-world/smartgo/crypto/sha3"
)

// SigningMethodHMAC implements the HMAC-SHA family of signing methods.
// Expects key type of []byte for both signing and validation
type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash
}

// Specific instances for HS256 and company
var (
	SigningMethodHS224   *SigningMethodHMAC
	SigningMethodHS256   *SigningMethodHMAC
	SigningMethodHS384   *SigningMethodHMAC
	SigningMethodHS512   *SigningMethodHMAC

	SigningMethodH3S224  *SigningMethodHMAC
	SigningMethodH3S256  *SigningMethodHMAC
	SigningMethodH3S384  *SigningMethodHMAC
	SigningMethodH3S512  *SigningMethodHMAC

	ErrSignatureInvalid = errors.New("signature is invalid")
)

func init() {

	//-- by unixman
	// HS224
	SigningMethodHS224 = &SigningMethodHMAC{"HS224", crypto.SHA224}
	RegisterSigningMethod(SigningMethodHS224.Alg(), func() SigningMethod {
		return SigningMethodHS224
	})
	//-- #end

	// HS256
	SigningMethodHS256 = &SigningMethodHMAC{"HS256", crypto.SHA256}
	RegisterSigningMethod(SigningMethodHS256.Alg(), func() SigningMethod {
		return SigningMethodHS256
	})

	// HS384
	SigningMethodHS384 = &SigningMethodHMAC{"HS384", crypto.SHA384}
	RegisterSigningMethod(SigningMethodHS384.Alg(), func() SigningMethod {
		return SigningMethodHS384
	})

	// HS512
	SigningMethodHS512 = &SigningMethodHMAC{"HS512", crypto.SHA512}
	RegisterSigningMethod(SigningMethodHS512.Alg(), func() SigningMethod {
		return SigningMethodHS512
	})


	//-- fix by unixman
	// the original sha3 available in golang.org/x/crypto/sha3 (which is slower than cloudflare circle version used here, does not require specific registration)
	//--
	crypto.RegisterHash(crypto.SHA3_224, sha3.New224)
	crypto.RegisterHash(crypto.SHA3_256, sha3.New256)
	crypto.RegisterHash(crypto.SHA3_384, sha3.New384)
	crypto.RegisterHash(crypto.SHA3_512, sha3.New512)
	//--
	// H3S224 (SHA3-224)
	SigningMethodH3S224 = &SigningMethodHMAC{"H3S224", crypto.SHA3_224}
	RegisterSigningMethod(SigningMethodH3S224.Alg(), func() SigningMethod {
		return SigningMethodH3S224
	})
	//--
	// H3S256 (SHA3-256)
	SigningMethodH3S256 = &SigningMethodHMAC{"H3S256", crypto.SHA3_256}
	RegisterSigningMethod(SigningMethodH3S256.Alg(), func() SigningMethod {
		return SigningMethodH3S256
	})
	//--
	// H3S384 (SHA3-384)
	SigningMethodH3S384 = &SigningMethodHMAC{"H3S384", crypto.SHA3_384}
	RegisterSigningMethod(SigningMethodH3S384.Alg(), func() SigningMethod {
		return SigningMethodH3S384
	})
	//--
	// H3S512 (SHA3-512)
	SigningMethodH3S512 = &SigningMethodHMAC{"H3S512", crypto.SHA3_512}
	RegisterSigningMethod(SigningMethodH3S512.Alg(), func() SigningMethod {
		return SigningMethodH3S512
	})
	//-- #end fix

}

func (m *SigningMethodHMAC) Alg() string {
	return m.Name
}

// Verify implements token verification for the SigningMethod. Returns nil if the signature is valid.
func (m *SigningMethodHMAC) Verify(signingString, signature string, key interface{}) error {
	// Verify the key is the right type
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrInvalidKeyType
	}

	// Decode signature, for comparison
	sig, err := DecodeSegment(signature)
	if err != nil {
		return err
	}

	// Can we use the specified hashing method?
	if !m.Hash.Available() {
		return ErrHashUnavailable
	}

	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	hasher := hmac.New(m.Hash.New, keyBytes)
	hasher.Write([]byte(signingString))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrSignatureInvalid
	}

	// No validation errors.  Signature is good.
	return nil
}

// Sign implements token signing for the SigningMethod.
// Key must be []byte
func (m *SigningMethodHMAC) Sign(signingString string, key interface{}) (string, error) {
	if keyBytes, ok := key.([]byte); ok {
		if !m.Hash.Available() {
			return "", ErrHashUnavailable
		}

		hasher := hmac.New(m.Hash.New, keyBytes)
		hasher.Write([]byte(signingString))

		return EncodeSegment(hasher.Sum(nil)), nil
	}

	return "", ErrInvalidKeyType
}
