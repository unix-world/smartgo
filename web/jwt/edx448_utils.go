package jwt

// added by unixman r.20250107

import (
	"errors"

	crand "crypto/rand"

	edx448 "github.com/unix-world/smartgo/crypto/eddsa/edx448"
)

var (
	ErrNotEdzxPrivateKey error = errors.New("key is not a valid Edx448 private key")
	ErrNotEdzxPublicKey  error = errors.New("key is not a valid Edx448 public key")
)


//-- unixman

func GenerateEdzxPrivateAndPublicKeys(secret []byte) (edx448.PrivateKey, []byte, error) {
	pK, errK := GenerateEdzxPrivateKey(secret)
	if(errK != nil) {
		return nil, nil, errK
	}
	if(pK == nil) {
		return nil, nil, errors.New("Private Key is NULL")
	}
	pbKey := GetEdzxPublicKeyFromPrivateKeyToBytes(pK)
	if(pbKey == nil) {
		return nil, nil, errors.New("Public Key is NULL")
	}
	return pK, pbKey, nil
}

func GenerateEdzxPrivateKey(secret []byte) (edx448.PrivateKey, error) {
	var privKey edx448.PrivateKey = nil
	var errKey error = nil
	if(secret != nil) {
		if(len(secret) != edx448.SeedSize) {
			return nil, errors.New("Secret Key Size must be 57 bytes")
		}
		privKey = edx448.NewKeyFromSeed([]byte(secret))
	} else {
		_, privKey, errKey = edx448.GenerateKey(crand.Reader)
	}
	if(errKey != nil) {
		return nil, errKey
	}
	if(privKey == nil) {
		return nil, errors.New("Failed to generate a Private Key")
	}
	return privKey, nil
}

func GetEdzxPublicKeyFromPrivateKeyToBytes(privateKey edx448.PrivateKey) []byte {
	publicKey := privateKey.Public()
	return []byte(publicKey.(edx448.PublicKey))
}

func GetEdzxPublicKeyFromBytes(pKey []byte) edx448.PublicKey {
	return edx448.PublicKey(pKey)
}

//-- #

