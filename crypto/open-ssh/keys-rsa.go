
package openssh

import (
	"fmt"
	"errors"

	"math/big"

	"crypto"
	"crypto/rsa"
)

const (
	KeyAlgoRSA 					string = "ssh-rsa"

//	KeyAlgoRSASHA256 			string = "rsa-sha2-256"
	KeyAlgoRSASHA512 			string = "rsa-sha2-512"
)

const (
	CertAlgoRSAv01        		string = "ssh-rsa-cert-v01@openssh.com"
//	CertAlgoECDSA256v01   		string = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
	CertAlgoECDSA384v01   		string = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
	CertAlgoECDSA521v01   		string = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
//	CertAlgoSKECDSA256v01 		string = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
	CertAlgoED25519v01    		string = "ssh-ed25519-cert-v01@openssh.com"
	CertAlgoSKED25519v01  		string = "sk-ssh-ed25519-cert-v01@openssh.com"

	// CertAlgoRSASHA256v01 and CertAlgoRSASHA512v01 can't appear as a
	// Certificate.Type (or PublicKey.Type), but only in
	// ClientConfig.HostKeyAlgorithms.
//	CertAlgoRSASHA256v01 		string = "rsa-sha2-256-cert-v01@openssh.com"
	CertAlgoRSASHA512v01 		string = "rsa-sha2-512-cert-v01@openssh.com"
)

const (
	// Deprecated: use CertAlgoRSAv01.
//	CertSigAlgoRSAv01 			string = CertAlgoRSAv01
	// Deprecated: use CertAlgoRSASHA256v01.
//	CertSigAlgoRSASHA2256v01 	string = CertAlgoRSASHA256v01
	// Deprecated: use CertAlgoRSASHA512v01.
	CertSigAlgoRSASHA2512v01 	string = CertAlgoRSASHA512v01
)


type openSSHRSAPrivateKey struct {
	N       *big.Int
	E       *big.Int
	D       *big.Int
	Iqmp    *big.Int
	P       *big.Int
	Q       *big.Int
	Comment string
	Pad     []byte `ssh:"rest"`
}


type rsaPublicKey rsa.PublicKey


func (r *rsaPublicKey) Type() string {
	return "ssh-rsa"
}


func (r *rsaPublicKey) Marshal() []byte {
	e := new(big.Int).SetInt64(int64(r.E))
	// RSA publickey struct layout should match the struct used by
	// parseRSACert in the x/crypto/ssh/agent package.
	wirekey := struct {
		Name string
		E    *big.Int
		N    *big.Int
	}{
		KeyAlgoRSA,
		e,
		r.N,
	}
	return Marshal(&wirekey)
}


func (r *rsaPublicKey) Verify(data []byte, sig *Signature) error {
	supportedAlgos := algorithmsForKeyFormat(r.Type())
	if !contains(supportedAlgos, sig.Format) {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, r.Type())
	}
	hash := hashFuncs[sig.Format]
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Signatures in PKCS1v15 must match the key's modulus in
	// length. However with SSH, some signers provide RSA
	// signatures which are missing the MSB 0's of the bignum
	// represented. With ssh-rsa signatures, this is encouraged by
	// the spec (even though e.g. OpenSSH will give the full
	// length unconditionally). With rsa-sha2-* signatures, the
	// verifier is allowed to support these, even though they are
	// out of spec. See RFC 4253 Section 6.6 for ssh-rsa and RFC
	// 8332 Section 3 for rsa-sha2-* details.
	//
	// In practice:
	// * OpenSSH always allows "short" signatures:
	//   https://github.com/openssh/openssh-portable/blob/V_9_8_P1/ssh-rsa.c#L526
	//   but always generates padded signatures:
	//   https://github.com/openssh/openssh-portable/blob/V_9_8_P1/ssh-rsa.c#L439
	//
	// * PuTTY versions 0.81 and earlier will generate short
	//   signatures for all RSA signature variants. Note that
	//   PuTTY is embedded in other software, such as WinSCP and
	//   FileZilla. At the time of writing, a patch has been
	//   applied to PuTTY to generate padded signatures for
	//   rsa-sha2-*, but not yet released:
	//   https://git.tartarus.org/?p=simon/putty.git;a=commitdiff;h=a5bcf3d384e1bf15a51a6923c3724cbbee022d8e
	//
	// * SSH.NET versions 2024.0.0 and earlier will generate short
	//   signatures for all RSA signature variants, fixed in 2024.1.0:
	//   https://github.com/sshnet/SSH.NET/releases/tag/2024.1.0
	//
	// As a result, we pad these up to the key size by inserting
	// leading 0's.
	//
	// Note that support for short signatures with rsa-sha2-* may
	// be removed in the future due to such signatures not being
	// allowed by the spec.
	blob := sig.Blob
	keySize := (*rsa.PublicKey)(r).Size()
	if len(blob) < keySize {
		padded := make([]byte, keySize)
		copy(padded[keySize-len(blob):], blob)
		blob = padded
	}
	return rsa.VerifyPKCS1v15((*rsa.PublicKey)(r), hash, digest, blob)
}


func (r *rsaPublicKey) CryptoPublicKey() crypto.PublicKey {
	return (*rsa.PublicKey)(r)
}


// parseRSA parses an RSA key according to RFC 4253, section 6.6.
func parseRSA(in []byte) (out PublicKey, rest []byte, err error) {
	var w struct {
		E    *big.Int
		N    *big.Int
		Rest []byte `ssh:"rest"`
	}
	if err := Unmarshal(in, &w); err != nil {
		return nil, nil, err
	}

	if w.E.BitLen() > 24 {
		return nil, nil, errors.New("ssh: exponent too large")
	}
	e := w.E.Int64()
	if e < 3 || e&1 == 0 {
		return nil, nil, errors.New("ssh: incorrect exponent")
	}

	var key rsa.PublicKey
	key.E = int(e)
	key.N = w.N
	return (*rsaPublicKey)(&key), w.Rest, nil
}


//#end
