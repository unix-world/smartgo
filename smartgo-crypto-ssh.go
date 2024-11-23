
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241123.2358 :: STABLE
// [ CRYPTO / SSH ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"encoding/base64"
	"encoding/pem"

	"crypto"
	cryptorand "crypto/rand"
	"crypto/ed25519"

	"golang.org/x/crypto/ssh"
)

//-----


// return: err, pubKeyPEM, privKeyPEM
func GenerateSSHKeyPairEd25519(comment string, password string) (error, string, string) {
	//-- info
	// the comment is expected to be an email address or a slug
	//-- trim, normalize spaces, replace spaces with -, and allow max 255 chars
	comment = StrSubstr(StrReplaceAll(StrTrimWhitespaces(StrNormalizeSpaces(comment)), " ", "-"), 0, 255)
	//-- do not trim, just ensure max allowed size
	password = StrSubstr(password, 0, 72) // the PASSWORD_BCRYPT as the algorithm supports max length as 72 !
	//--
	pub, priv, errK := ed25519.GenerateKey(cryptorand.Reader)
	if(errK != nil) {
		return errK, "", ""
	} //end if
	//--
	var p *pem.Block
	var errM error
	if(password != "") {
		p, errM = ssh.MarshalPrivateKeyWithPassphrase(crypto.PrivateKey(priv), comment, []byte(password))
	} else {
		p, errM = ssh.MarshalPrivateKey(crypto.PrivateKey(priv), comment)
	} //end if else
	if(errM != nil) {
		return errM, "", ""
	} //end if
	//--
	publicKey, err := ssh.NewPublicKey(pub)
	if(err != nil) {
		return errM, "", ""
	} //end if
	privateKeyPem := pem.EncodeToMemory(p)
	//--
	pubPemK := "ssh-ed25519" + " " + base64.StdEncoding.EncodeToString(publicKey.Marshal()) + " " + comment
	privPemK := string(privateKeyPem)
	//--
	return nil, StrTrimWhitespaces(pubPemK), StrTrimWhitespaces(privPemK)
	//--
} //END FUNCTION


//-----


// #END
