
package openssh


const privateKeyAuthMagic = "openssh-key-v1\x00"


var (
	comma         = []byte{','}
	emptyNameList = []string{}
)


type openSSHDecryptFunc func(CipherName, KdfName, KdfOpts string, PrivKeyBlock []byte) ([]byte, error)

type openSSHEncryptFunc func(PrivKeyBlock []byte) (ProtectedKeyBlock []byte, cipherName, kdfName, kdfOptions string, err error)


type openSSHEncryptedPrivateKey struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}


type openSSHPrivateKey struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}


// Signature represents a cryptographic signature.
type Signature struct {
	Format string
	Blob   []byte
	Rest   []byte `ssh:"rest"`
}


// PublicKey represents a public key using an unspecified algorithm.
//
// Some PublicKeys provided by this package also implement CryptoPublicKey.
type PublicKey interface {
	// Type returns the key format name, e.g. "ssh-rsa".
	Type() string

	// Marshal returns the serialized key data in SSH wire format, with the name
	// prefix. To unmarshal the returned data, use the ParsePublicKey function.
	Marshal() []byte

	// Verify that sig is a signature on the given data using this key. This
	// method will hash the data appropriately first. sig.Format is allowed to
	// be any signature algorithm compatible with the key type, the caller
	// should check if it has more stringent requirements.
	Verify(data []byte, sig *Signature) error
}


//#end
