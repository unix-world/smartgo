package jwt

import (
	"errors"

	crand "crypto/rand"

	ed448 "github.com/unix-world/smartgo/crypto/eddsa/ed448"
)

var (
	ErrNotEdzPrivateKey error = errors.New("key is not a valid Ed448 private key")
	ErrNotEdzPublicKey  error = errors.New("key is not a valid Ed448 public key")
)


//-- unixman

func GenerateEdzPrivateAndPublicKeys(secret []byte) (ed448.PrivateKey, []byte, error) {
	pK, errK := GenerateEdzPrivateKey(secret)
	if(errK != nil) {
		return nil, nil, errK
	}
	if(pK == nil) {
		return nil, nil, errors.New("Private Key is NULL")
	}
	pbKey := GetEdzPublicKeyFromPrivateKeyToBytes(pK)
	if(pbKey == nil) {
		return nil, nil, errors.New("Public Key is NULL")
	}
	return pK, pbKey, nil
}

func GenerateEdzPrivateKey(secret []byte) (ed448.PrivateKey, error) {
	var privKey ed448.PrivateKey = nil
	var errKey error = nil
	if(secret != nil) {
		if(len(secret) != ed448.SeedSize) {
			return nil, errors.New("Secret Key Size must be 57 bytes")
		}
		privKey = ed448.NewKeyFromSeed([]byte(secret))
	} else {
		_, privKey, errKey = ed448.GenerateKey(crand.Reader)
	}
	if(errKey != nil) {
		return nil, errKey
	}
	if(privKey == nil) {
		return nil, errors.New("Failed to generate a Private Key")
	}
	return privKey, nil
}

func GetEdzPublicKeyFromPrivateKeyToBytes(privateKey ed448.PrivateKey) []byte {
	publicKey := privateKey.Public()
	return []byte(publicKey.(ed448.PublicKey))
}

func GetEdzPublicKeyFromBytes(pKey []byte) ed448.PublicKey {
	return ed448.PublicKey(pKey)
}

//-- #

