
package openssh


import (
	"fmt"
	"errors"
	"reflect"

	"math/big"

	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"encoding/binary"
	"encoding/pem"

	bcrypt_pbkdf "github.com/unix-world/smartgo/crypto/bcrypt-pbkdf"
)


var errShortRead = errors.New("ssh: short read")


// MarshalPrivateKey returns a PEM block with the private key serialized in the
// OpenSSH format.
func MarshalPrivateKey(key crypto.PrivateKey, comment string) (*pem.Block, error) {
	return marshalOpenSSHPrivateKey(key, comment, unencryptedOpenSSHMarshaler)
}


// MarshalPrivateKeyWithPassphrase returns a PEM block holding the encrypted
// private key serialized in the OpenSSH format.
func MarshalPrivateKeyWithPassphrase(key crypto.PrivateKey, comment string, passphrase []byte) (*pem.Block, error) {
	return marshalOpenSSHPrivateKey(key, comment, passphraseProtectedOpenSSHMarshaler(passphrase))
}


// NewPublicKey takes an *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey,
// or ed25519.PublicKey returns a corresponding PublicKey instance.
// ECDSA keys must use P-256, P-384 or P-521.
func NewPublicKey(key interface{}) (PublicKey, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return (*rsaPublicKey)(key), nil
	case *ecdsa.PublicKey:
		if !supportedEllipticCurve(key.Curve) {
			return nil, errors.New("ssh: only P-256, P-384 and P-521 EC keys are supported")
		}
		return (*ecdsaPublicKey)(key), nil
	case ed25519.PublicKey:
		if l := len(key); l != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ssh: invalid size %d for Ed25519 public key", l)
		}
		return ed25519PublicKey(key), nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", key)
	}
}


// Marshal serializes the message in msg to SSH wire format.  The msg
// argument should be a struct or pointer to struct. If the first
// member has the "sshtype" tag set to a number in decimal, that
// number is prepended to the result. If the last of member has the
// "ssh" tag set to "rest", its contents are appended to the output.
func Marshal(msg interface{}) []byte {
	out := make([]byte, 0, 64)
	return marshalStruct(out, msg)
}


// Unmarshal parses data in SSH wire format into a structure. The out
// argument should be a pointer to struct. If the first member of the
// struct has the "sshtype" tag set to a '|'-separated set of numbers
// in decimal, the packet must start with one of those numbers. In
// case of error, Unmarshal returns a ParseError or
// UnexpectedMessageError.
func Unmarshal(data []byte, out interface{}) error {
	v := reflect.ValueOf(out).Elem()
	structType := v.Type()
	expectedTypes := typeTags(structType)

	var expectedType byte
	if len(expectedTypes) > 0 {
		expectedType = expectedTypes[0]
	}

	if len(data) == 0 {
		return parseError(expectedType)
	}

	if len(expectedTypes) > 0 {
		goodType := false
		for _, e := range expectedTypes {
			if e > 0 && data[0] == e {
				goodType = true
				break
			}
		}
		if !goodType {
			return fmt.Errorf("ssh: unexpected message type %d (expected one of %v)", data[0], expectedTypes)
		}
		data = data[1:]
	}

	var ok bool
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		t := field.Type()
		switch t.Kind() {
		case reflect.Bool:
			if len(data) < 1 {
				return errShortRead
			}
			field.SetBool(data[0] != 0)
			data = data[1:]
		case reflect.Array:
			if t.Elem().Kind() != reflect.Uint8 {
				return fieldError(structType, i, "array of unsupported type")
			}
			if len(data) < t.Len() {
				return errShortRead
			}
			for j, n := 0, t.Len(); j < n; j++ {
				field.Index(j).Set(reflect.ValueOf(data[j]))
			}
			data = data[t.Len():]
		case reflect.Uint64:
			var u64 uint64
			if u64, data, ok = parseUint64(data); !ok {
				return errShortRead
			}
			field.SetUint(u64)
		case reflect.Uint32:
			var u32 uint32
			if u32, data, ok = parseUint32(data); !ok {
				return errShortRead
			}
			field.SetUint(uint64(u32))
		case reflect.Uint8:
			if len(data) < 1 {
				return errShortRead
			}
			field.SetUint(uint64(data[0]))
			data = data[1:]
		case reflect.String:
			var s []byte
			if s, data, ok = parseString(data); !ok {
				return fieldError(structType, i, "")
			}
			field.SetString(string(s))
		case reflect.Slice:
			switch t.Elem().Kind() {
			case reflect.Uint8:
				if structType.Field(i).Tag.Get("ssh") == "rest" {
					field.Set(reflect.ValueOf(data))
					data = nil
				} else {
					var s []byte
					if s, data, ok = parseString(data); !ok {
						return errShortRead
					}
					field.Set(reflect.ValueOf(s))
				}
			case reflect.String:
				var nl []string
				if nl, data, ok = parseNameList(data); !ok {
					return errShortRead
				}
				field.Set(reflect.ValueOf(nl))
			default:
				return fieldError(structType, i, "slice of unsupported type")
			}
		case reflect.Ptr:
			if t == bigIntType {
				var n *big.Int
				if n, data, ok = parseInt(data); !ok {
					return errShortRead
				}
				field.Set(reflect.ValueOf(n))
			} else {
				return fieldError(structType, i, "pointer to unsupported type")
			}
		default:
			return fieldError(structType, i, fmt.Sprintf("unsupported type: %v", t))
		}
	}

	if len(data) != 0 {
		return parseError(expectedType)
	}

	return nil
}


func checkOpenSSHKeyPadding(pad []byte) error {
	for i, b := range pad {
		if int(b) != i+1 {
			return errors.New("ssh: padding not as expected")
		}
	}
	return nil
}


func generateOpenSSHPadding(block []byte, blockSize int) []byte {
	for i, l := 0, len(block); (l+i)%blockSize != 0; i++ {
		block = append(block, byte(i+1))
	}
	return block
}


func marshalOpenSSHPrivateKey(key crypto.PrivateKey, comment string, encrypt openSSHEncryptFunc) (*pem.Block, error) {
	var w openSSHEncryptedPrivateKey
	var pk1 openSSHPrivateKey

	// Random check bytes.
	var check uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &check); err != nil {
		return nil, err
	}

	pk1.Check1 = check
	pk1.Check2 = check
	w.NumKeys = 1

	// Use a []byte directly on ed25519 keys.
	if k, ok := key.(*ed25519.PrivateKey); ok {
		key = *k
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		E := new(big.Int).SetInt64(int64(k.PublicKey.E))
		// Marshal public key:
		// E and N are in reversed order in the public and private key.
		pubKey := struct {
			KeyType string
			E       *big.Int
			N       *big.Int
		}{
			KeyAlgoRSA,
			E, k.PublicKey.N,
		}
		w.PubKey = Marshal(pubKey)

		// Marshal private key.
		key := openSSHRSAPrivateKey{
			N:       k.PublicKey.N,
			E:       E,
			D:       k.D,
			Iqmp:    k.Precomputed.Qinv,
			P:       k.Primes[0],
			Q:       k.Primes[1],
			Comment: comment,
		}
		pk1.Keytype = KeyAlgoRSA
		pk1.Rest = Marshal(key)
	case ed25519.PrivateKey:
		pub := make([]byte, ed25519.PublicKeySize)
		priv := make([]byte, ed25519.PrivateKeySize)
		copy(pub, k[32:])
		copy(priv, k)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Pub     []byte
		}{
			KeyAlgoED25519, pub,
		}
		w.PubKey = Marshal(pubKey)

		// Marshal private key.
		key := openSSHEd25519PrivateKey{
			Pub:     pub,
			Priv:    priv,
			Comment: comment,
		}
		pk1.Keytype = KeyAlgoED25519
		pk1.Rest = Marshal(key)
	case *ecdsa.PrivateKey:
		var curve, keyType string
		switch name := k.Curve.Params().Name; name {
		//	case "P-256":
		//		curve = "nistp256"
		//		keyType = KeyAlgoECDSA256
			case "P-384":
				curve = "nistp384"
				keyType = KeyAlgoECDSA384
			case "P-521":
				curve = "nistp521"
				keyType = KeyAlgoECDSA521
			default:
				return nil, errors.New("ssh: unhandled elliptic curve " + name)
		}

		pub := elliptic.Marshal(k.Curve, k.PublicKey.X, k.PublicKey.Y)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Curve   string
			Pub     []byte
		}{
			keyType, curve, pub,
		}
		w.PubKey = Marshal(pubKey)

		// Marshal private key.
		key := openSSHECDSAPrivateKey{
			Curve:   curve,
			Pub:     pub,
			D:       k.D,
			Comment: comment,
		}
		pk1.Keytype = keyType
		pk1.Rest = Marshal(key)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}

	var err error
	// Add padding and encrypt the key if necessary.
	w.PrivKeyBlock, w.CipherName, w.KdfName, w.KdfOpts, err = encrypt(Marshal(pk1))
	if err != nil {
		return nil, err
	}

	b := Marshal(w)
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte(privateKeyAuthMagic), b...),
	}
	return block, nil
}


func unencryptedOpenSSHMarshaler(privKeyBlock []byte) ([]byte, string, string, string, error) {
	key := generateOpenSSHPadding(privKeyBlock, 8)
	return key, "none", "none", "", nil
}


func passphraseProtectedOpenSSHMarshaler(passphrase []byte) openSSHEncryptFunc {
	return func(privKeyBlock []byte) ([]byte, string, string, string, error) {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, "", "", "", err
		}

		opts := struct {
			Salt   []byte
			Rounds uint32
		}{salt, 16}

		// Derive key to encrypt the private key block.
		k, err := bcrypt_pbkdf.Key(passphrase, salt, int(opts.Rounds), 32+aes.BlockSize)
		if err != nil {
			return nil, "", "", "", err
		}

		// Add padding matching the block size of AES.
		keyBlock := generateOpenSSHPadding(privKeyBlock, aes.BlockSize)

		// Encrypt the private key using the derived secret.

		dst := make([]byte, len(keyBlock))
		key, iv := k[:32], k[32:]
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, "", "", "", err
		}

		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(dst, keyBlock)

		return dst, "aes256-ctr", "bcrypt", string(Marshal(opts)), nil
	}
}


func marshalStruct(out []byte, msg interface{}) []byte {
	v := reflect.Indirect(reflect.ValueOf(msg))
	msgTypes := typeTags(v.Type())
	if len(msgTypes) > 0 {
		out = append(out, msgTypes[0])
	}

	for i, n := 0, v.NumField(); i < n; i++ {
		field := v.Field(i)
		switch t := field.Type(); t.Kind() {
		case reflect.Bool:
			var v uint8
			if field.Bool() {
				v = 1
			}
			out = append(out, v)
		case reflect.Array:
			if t.Elem().Kind() != reflect.Uint8 {
				panic(fmt.Sprintf("array of non-uint8 in field %d: %T", i, field.Interface()))
			}
			for j, l := 0, t.Len(); j < l; j++ {
				out = append(out, uint8(field.Index(j).Uint()))
			}
		case reflect.Uint32:
			out = appendU32(out, uint32(field.Uint()))
		case reflect.Uint64:
			out = appendU64(out, uint64(field.Uint()))
		case reflect.Uint8:
			out = append(out, uint8(field.Uint()))
		case reflect.String:
			s := field.String()
			out = appendInt(out, len(s))
			out = append(out, s...)
		case reflect.Slice:
			switch t.Elem().Kind() {
			case reflect.Uint8:
				if v.Type().Field(i).Tag.Get("ssh") != "rest" {
					out = appendInt(out, field.Len())
				}
				out = append(out, field.Bytes()...)
			case reflect.String:
				offset := len(out)
				out = appendU32(out, 0)
				if n := field.Len(); n > 0 {
					for j := 0; j < n; j++ {
						f := field.Index(j)
						if j != 0 {
							out = append(out, ',')
						}
						out = append(out, f.String()...)
					}
					// overwrite length value
					binary.BigEndian.PutUint32(out[offset:], uint32(len(out)-offset-4))
				}
			default:
				panic(fmt.Sprintf("slice of unknown type in field %d: %T", i, field.Interface()))
			}
		case reflect.Ptr:
			if t == bigIntType {
				var n *big.Int
				nValue := reflect.ValueOf(&n)
				nValue.Elem().Set(field)
				needed := intLength(n)
				oldLength := len(out)

				if cap(out)-len(out) < needed {
					newOut := make([]byte, len(out), 2*(len(out)+needed))
					copy(newOut, out)
					out = newOut
				}
				out = out[:oldLength+needed]
				marshalInt(out[oldLength:], n)
			} else {
				panic(fmt.Sprintf("pointer to unknown type in field %d: %T", i, field.Interface()))
			}
		}
	}

	return out
}


//#end
