
// Package slh_dsa implements the SLH-DSA signature scheme, which is specified
// in FIPS 205. SLH-DSA is a post-quantum digital signature algorithm that is
// resistant to attacks from quantum computers. It is a stateless hash-based
// signature scheme.
//
// This implementation was developed with reference to FIPS 205, the standards
// document for SLH-DSA. These parameter sets specified in FIPS 205 are
// supported (standard SHA2 and SHAKE, and SHA3 by unixman):
//
//   - SLH-DSA-SHA2-128f
//   - SLH-DSA-SHA2-128s
//   - SLH-DSA-SHA2-192f
//   - SLH-DSA-SHA2-192s
//   - SLH-DSA-SHA2-256f
//   - SLH-DSA-SHA2-256s
//   - SLH-DSA-SHAKE-128f
//   - SLH-DSA-SHAKE-128s
//   - SLH-DSA-SHAKE-192f
//   - SLH-DSA-SHAKE-192s
//   - SLH-DSA-SHAKE-256f
//   - SLH-DSA-SHAKE-256s
//   - SLH-DSA-SHA3-128f
//   - SLH-DSA-SHA3-128s
//   - SLH-DSA-SHA3-192f
//   - SLH-DSA-SHA3-192s
//   - SLH-DSA-SHA3-256f
//   - SLH-DSA-SHA3-256s
//
// # Usage
//
// To generate a key pair, first select a parameter set, then call SLHKeygen:
//
//	params, err := slh_dsa.GetParamSet("SLH-DSA-SHA2-128f")
//	if err != nil {
//		// handle error
//	}
//	sk, pk, err := slh_dsa.SLHKeygen(params)
//	if err != nil {
//		// handle error
//	}
//
// To sign a message, use the SLHSign function. The SecretKey type also
// implements the crypto.Signer interface, which may be more convenient.
//
//	message := []byte("message to be signed")
//	// The simple case:
//	sig, err := slh_dsa.SLHSign(rand.Reader, message, nil, sk)
//
//	// Using the crypto.Signer interface:
//	sigBytes, err := sk.Sign(rand.Reader, message, nil)
//
// The context string `ctx` is optional and may be nil.
//
// To verify a signature, use the SLHVerify function:
//
//	ok := slh_dsa.SLHVerify(message, sig, nil, pk)
//	if ok {
//		// signature is valid
//	}

package slh_dsa

import (
	"errors"
	"io"

	"crypto"
	"crypto/rand"

	options "github.com/unix-world/smartgo/crypto/slhdsa/options"
	"github.com/unix-world/smartgo/crypto/slhdsa/internal"
)


// SecretKey represents a SLH-DSA secret key.
type SecretKey struct {
	params internal.ParamSet
	sk     internal.SLHSecretKey
	pk     PublicKey
}

// PublicKey represents a SLH-DSA public key.
type PublicKey struct {
	params internal.ParamSet
	pk     internal.SLHPublicKey
}

// Signature represents a SLH-DSA signature.
type Signature struct {
	params internal.ParamSet
	sig    internal.SLHSignature
}


// Bytes returns the byte representation of the public key.
func (k PublicKey) Bytes() []byte {
	return k.pk.Bytes()
}

// InternalPublicKey returns the internal representation of the public key. This
// is not intended for use by external clients.
func (k PublicKey) InternalPublicKey() internal.SLHPublicKey {
	return k.pk
}

// Verify is a helper method for verifying a signature on a message M with the
// given public key. The ctx argument is an optional context string. In most
// cases, it can be nil. This is a wrapper around SLHVerify.
func (pk PublicKey) Verify(sig Signature, M, ctx []byte) bool {
	return SLHVerify(M, sig, ctx, pk)
}


// Bytes returns the byte representation of the secret key.
func (k SecretKey) Bytes() []byte {
	return k.sk.Bytes()
}

// InternalSecretKey returns the internal representation of the secret key. This
// is not intended for use by external clients.
func (k SecretKey) InternalSecretKey() internal.SLHSecretKey {
	return k.sk
}

// Public returns the public key corresponding to the secret key.
func (sk *SecretKey) Public() crypto.PublicKey {
	return &sk.pk
}

// Sign signs a message digest. This method, along with Public(), makes the
// SecretKey type an implementation of the crypto.Signer interface. The rand
// and opts arguments are ignored. The SLH-DSA signature algorithm is defined
// on a message, not a digest, so the digest argument is treated as the message.
func (sk *SecretKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var h crypto.Hash
	var ctx []byte
	if opts != nil {
		h = opts.HashFunc()
		ops, ok := opts.(*options.Options)
		if ok {
			ctx = []byte(ops.Context)
		}
	}
	if h != 0 {
		return nil, errors.New("opts.HashFunc() must be zero for pure SLH-DSA")
	}

	sig, err := SLHSign(rand, digest, ctx, *sk)
	if err != nil {
		return nil, err
	}
	return sig.Bytes(), nil
}


// Bytes returns the byte representation of the signature.
func (s Signature) Bytes() []byte {
	return s.sig.Bytes()
}

// InternalSignature returns the internal representation of the signature. This
// is not intended for use by external clients.
func (s Signature) InternalSignature() internal.SLHSignature {
	return s.sig
}


// LoadPublicKey deserializes a public key from a byte slice. It is the
// inverse of the Bytes() method on the PublicKey type.
func LoadPublicKey(params internal.ParamSet, b []byte) (PublicKey, error) {
	pk, err := internal.LoadPublicKey(params, b)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{
		params: params,
		pk:     pk,
	}, nil
}


// LoadSecretKey deserializes a secret key from a byte slice. It is the
// inverse of the Bytes() method on the SecretKey type.
func LoadSecretKey(params internal.ParamSet, b []byte) (SecretKey, error) {
	sk, err := internal.LoadSecretKey(params, b)
	if err != nil {
		return SecretKey{}, err
	}
	// Re-create the public key
	pk, err := internal.LoadPublicKey(params, sk.PublicKey().Bytes())
	if err != nil {
		return SecretKey{}, err
	}
	return SecretKey{
		params: params,
		sk:     sk,
		pk: PublicKey{
			params: params,
			pk:     pk,
		},
	}, nil
}


// LoadSignature deserializes a signature from a byte slice. It is the inverse
// of the Bytes() method on the Signature type.
func LoadSignature(params internal.ParamSet, b []byte) (Signature, error) {
	internalSig, err := internal.LoadSignature(params, b)
	if err != nil {
		return Signature{}, err
	}
	return Signature{params: params, sig: internalSig}, nil
}


// SLHKeygen generates a new SLH-DSA keypair for the given parameter set.
// This is Algorithm 21 in FIPS 205.
func SLHKeygen(params internal.ParamSet) (SecretKey, PublicKey, error) {
	n := uint32(params.N)
	skseed := make([]byte, n)
	_, err := rand.Read(skseed)
	if err != nil {
		return SecretKey{}, PublicKey{}, err
	}
	skprf := make([]byte, n)
	_, err = rand.Read(skprf)
	if err != nil {
		return SecretKey{}, PublicKey{}, err
	}
	pkseed := make([]byte, n)
	_, err = rand.Read(pkseed)
	if err != nil {
		return SecretKey{}, PublicKey{}, err
	}
	sk, pk := internal.SLHKeygenInternal(params, skseed, skprf, pkseed)
	pkOut := PublicKey{
		params: params,
		pk:     pk,
	}
	return SecretKey{
		params: params,
		sk:     sk,
		pk:     pkOut,
	}, pkOut, nil
}


// MakeMPrime constructs the input to the signing and verification algorithms.
// This is Algorithm 22 in FIPS 205.
func MakeMPrime(M, ctx []byte) []byte {
	ctxLen := uint32(len(ctx))
	Mprime := internal.ToByte(uint32(0), uint8(1))
	Mprime = append(Mprime, internal.ToByte(ctxLen, 1)...)
	Mprime = append(Mprime, ctx...)
	Mprime = append(Mprime, M...)
	return Mprime
}


// SLHSign signs a message M with the given secret key. The rand argument is a
// source of randomness for the randomized signing variants. If it is nil,
// deterministic signing is used. The ctx argument is an optional context
// string. In most cases, it can be nil.
// This is Algorithm 23 in FIPS 205.
func SLHSign(rand io.Reader, M, ctx []byte, sk SecretKey) (Signature, error) {
	n := uint32(sk.params.N)
	ctxLen := uint32(len(ctx))
	if ctxLen > 255 {
		return Signature{}, errors.New("context string is too long")
	}
	addrnd := make([]byte, n)
	_, err := rand.Read(addrnd)
	if err != nil {
		return Signature{}, err
	}

	Mprime := MakeMPrime(M, ctx)
	sig := internal.SLHSignInternal(sk.params, Mprime, sk.sk, addrnd)
	return Signature{
		params: sk.params,
		sig:    sig,
	}, nil
}


// SLHSignDeterministic signs a message M with the given secret key, but does so
// deterministically. The ctx argument is an optional context string.
// In most cases, it can be nil.
// This is a variant of Algorithm 23 in FIPS 205.
func SLHSignDeterministic(M, ctx []byte, sk SecretKey) (Signature, error) {
	ctxLen := uint32(len(ctx))
	if ctxLen > 255 {
		return Signature{}, errors.New("context string is too long")
	}
	Mprime := MakeMPrime(M, ctx)
	sig := internal.SLHSignInternalDeterministic(sk.params, Mprime, sk.sk)
	return Signature{
		params: sk.params,
		sig:    sig,
	}, nil
}


// SLHVerify verifies a signature on a message M with the given public key. The
// ctx argument is an optional context string. In most cases, it can be nil.
// This is Algorithm 24 in FIPS 205.
func SLHVerify(M []byte, sig Signature, ctx []byte, pk PublicKey) bool {
	ctxLen := uint32(len(ctx))
	if ctxLen > 255 {
		return false
	}
	Mprime := MakeMPrime(M, ctx)
	return internal.SLHVerifyInternal(pk.params, Mprime, sig.sig, pk.pk)
}


// #end
