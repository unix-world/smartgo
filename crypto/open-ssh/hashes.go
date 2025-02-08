
package openssh

import (
	"crypto"

	_ "crypto/sha256"
	_ "crypto/sha512"
)


// hashFuncs keeps the mapping of supported signature algorithms to their
// respective hashes needed for signing and verification.
var hashFuncs = map[string]crypto.Hash{
//	KeyAlgoRSASHA256:  crypto.SHA256,
	KeyAlgoRSASHA512:  crypto.SHA512,
//	KeyAlgoECDSA256:   crypto.SHA256,
	KeyAlgoECDSA384:   crypto.SHA384,
	KeyAlgoECDSA521:   crypto.SHA512,
	// KeyAlgoED25519 does not pre-hash
//	KeyAlgoSKECDSA256: crypto.SHA256,
	KeyAlgoSKED25519:  crypto.SHA256,
}


// algorithmsForKeyFormat returns the supported signature algorithms for a given
// public key format (PublicKey.Type), in order of preference. See RFC 8332,
// Section 2. See also the note in sendKexInit on backwards compatibility.
func algorithmsForKeyFormat(keyFormat string) []string {
	switch keyFormat {
		case KeyAlgoRSA:
		//	return []string{KeyAlgoRSASHA256, KeyAlgoRSASHA512}
			return []string{KeyAlgoRSASHA512}
		case CertAlgoRSAv01:
		//	return []string{CertAlgoRSASHA256v01, CertAlgoRSASHA512v01, CertAlgoRSAv01}
			return []string{CertAlgoRSASHA512v01}
		default:
			return []string{keyFormat}
	}
}


//#end
