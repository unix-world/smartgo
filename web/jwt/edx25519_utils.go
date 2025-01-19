package jwt

// added by unixman r.20250107

import (
	"errors"

	crand "crypto/rand"

	edx25519 "github.com/unix-world/smartgo/crypto/eddsa/edx25519"
)

var (
	ErrNotEdxPrivateKey error = errors.New("key is not a valid Edx25519 private key")
	ErrNotEdxPublicKey  error = errors.New("key is not a valid Edx25519 public key")
)


//-- unixman

func GenerateEdxPrivateAndPublicKeys(secret []byte) (edx25519.PrivateKey, []byte, error) {
	pK, errK := GenerateEdxPrivateKey(secret)
	if(errK != nil) {
		return nil, nil, errK
	}
	if(pK == nil) {
		return nil, nil, errors.New("Private Key is NULL")
	}
	pbKey := GetEdxPublicKeyFromPrivateKeyToBytes(pK)
	if(pbKey == nil) {
		return nil, nil, errors.New("Public Key is NULL")
	}
	return pK, pbKey, nil
}

func GenerateEdxPrivateKey(secret []byte) (edx25519.PrivateKey, error) {
	var privKey edx25519.PrivateKey = nil
	var errKey error = nil
	if(secret != nil) {
		if(len(secret) != edx25519.SeedSize) {
			return nil, errors.New("Secret Key Size must be 32 bytes")
		}
		privKey = edx25519.NewKeyFromSeed([]byte(secret))
	} else {
		_, privKey, errKey = edx25519.GenerateKey(crand.Reader)
	}
	if(errKey != nil) {
		return nil, errKey
	}
	if(privKey == nil) {
		return nil, errors.New("Failed to generate a Private Key")
	}
	return privKey, nil
}

func GetEdxPublicKeyFromPrivateKeyToBytes(privateKey edx25519.PrivateKey) []byte {
	publicKey := privateKey.Public()
	return []byte(publicKey.(edx25519.PublicKey))
}

func GetEdxPublicKeyFromBytes(pKey []byte) edx25519.PublicKey {
	return edx25519.PublicKey(pKey)
}

//-- #

