package jwt

import (
	"errors"

	crand "crypto/rand"

	ed25519 "crypto/ed25519"
)

var (
	ErrNotEdPrivateKey error = errors.New("key is not a valid Ed25519 private key")
	ErrNotEdPublicKey  error = errors.New("key is not a valid Ed25519 public key")
)


//-- unixman

func GenerateEdPrivateAndPublicKeys(secret []byte) (ed25519.PrivateKey, []byte, error) {
	pK, errK := GenerateEdPrivateKey(secret)
	if(errK != nil) {
		return nil, nil, errK
	}
	if(pK == nil) {
		return nil, nil, errors.New("Private Key is NULL")
	}
	pbKey := GetEdPublicKeyFromPrivateKeyToBytes(pK)
	if(pbKey == nil) {
		return nil, nil, errors.New("Public Key is NULL")
	}
	return pK, pbKey, nil
}

func GenerateEdPrivateKey(secret []byte) (ed25519.PrivateKey, error) {
	var privKey ed25519.PrivateKey = nil
	var errKey error = nil
	if(secret != nil) {
		if(len(secret) != ed25519.SeedSize) {
			return nil, errors.New("Secret Key Size must be 32 bytes")
		}
		privKey = ed25519.NewKeyFromSeed([]byte(secret))
	} else {
		_, privKey, errKey = ed25519.GenerateKey(crand.Reader)
	}
	if(errKey != nil) {
		return nil, errKey
	}
	if(privKey == nil) {
		return nil, errors.New("Failed to generate a Private Key")
	}
	return privKey, nil
}

func GetEdPublicKeyFromPrivateKeyToBytes(privateKey ed25519.PrivateKey) []byte {
	publicKey := privateKey.Public()
	return []byte(publicKey.(ed25519.PublicKey))
}

func GetEdPublicKeyFromBytes(pKey []byte) ed25519.PublicKey {
	return ed25519.PublicKey(pKey)
}

//-- #

