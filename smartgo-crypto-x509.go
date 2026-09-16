
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260915.2358 :: STABLE
// [ CRYPTO / X509 ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"fmt"
	"log"
	"time"
	"strings"
	"math/big"
	"net"

	"crypto"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	"crypto/cipher"
	"crypto/aes"
	"crypto/md5"
	"io"

	uid "github.com/unix-world/smartgo/crypto/uuid"

	certinspect "github.com/unix-world/smartgo/crypto/x509-inspect"
)

const (
	enableLegacySupport bool = false // if set to TRUE will enable the support for legacy, unsafe PKCS1 / EC ; default is FALSE
)

var (
	CryptoX509UxmDebug bool = DEBUG // use the DEBUG value from main SmartGo, but can be changed later, is exported
)

type X509SignatureAlgorithm = x509.SignatureAlgorithm
const (
	X509PureEd25519 		= x509.PureEd25519

	X509EcdsaWithSha512 	= x509.ECDSAWithSHA512
	X509EcdsaWithSha384 	= x509.ECDSAWithSHA384
	X509EcdsaWithSha256 	= x509.ECDSAWithSHA256

	X509Sha512WithRsaPss 	= x509.SHA512WithRSAPSS
	X509Sha384WithRsaPss 	= x509.SHA384WithRSAPSS
	X509Sha256WithRsaPss 	= x509.SHA256WithRSAPSS

	X509Sha512WithRsa 		= x509.SHA512WithRSA
	X509Sha384WithRsa 		= x509.SHA384WithRSA
	X509Sha256WithRsa 		= x509.SHA256WithRSA
)

const (
	privateKeyTypePKCS8          string = "PKCS8:priv" 		// pair with PKIX  public     [modern]
	privateKeyTypePKCS1          string = "PKCS1:priv" 		// pair with PKCS1 public     [legacy]

	privateKeyTypeEC             string = "EC:priv" 		// supported only for logging [transitional]

	publicKeyTypePKIX            string = "PKIX:pub" 		// pair with PKCS8 private    [modern]
	publicKeyTypePKCS1           string = "PKCS1:pub" 		// pair with PKCS1 private    [legacy]
)

const ( // these are only supporting the PKCS8 / PKIX new format ; old formats are using: [PKCS1: `RSA PRIVATE KEY` | `RSA PUBLIC KEY`] ; [EC: `EC PRIVATE KEY` | `EC PUBLIC KEY`]
	X509PemCertificateStartTag   string = "-----BEGIN CERTIFICATE-----"
	X509PemCertificateEndTag     string = "-----END CERTIFICATE-----"

	X509PemPrivateKeyEncStartTag string = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
	X509PemPrivateKeyEncEndTag   string = "-----END ENCRYPTED PRIVATE KEY-----"

	X509PemPrivateKeyStartTag    string = "-----BEGIN PRIVATE KEY-----"
	X509PemPrivateKeyEndTag      string = "-----END PRIVATE KEY-----"

	X509PemPublicKeyStartTag     string = "-----BEGIN PUBLIC KEY-----"
	X509PemPublicKeyEndTag       string = "-----END PUBLIC KEY-----"
)


type CertX509KeyPair struct {
	PemCertificate string
	PemPrivateKey  string
	PemPublicKey   string
}

type CertX509Info struct {
	Validity 		uint8
	CommonName 		string

	AltName 		string // optional
	Hosts 			string // optional
	Organization 	string // optional
	OrgUnit 		string // optional
	Country 		string // optional
	Region 			string // optional
	City 			string // optional
	Street 			string // optional
	PostalCode 		string // optional

	OCSPUrl 		string // optional, just for CA
	Password 		[]byte // optional
}

type SignX509Definition struct { // this is compatible with ASN1, but can be used without ASN1 if R is not used ...
	R *big.Int
	S *big.Int
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}


func padX509Signature(bSig []byte, reqLen int) []byte {
	//--
	defer PanicHandler()
	//--
	if(bSig == nil) {
		return bSig // avoid pad on nil
	} //end if
	if(reqLen <= 0) {
		return bSig // something is wrong
	} //end if
	//--
	if(len(bSig) < reqLen) {
		var sSig string = StrPad2LenLeft(string(bSig), NULL_BYTE, reqLen)
		bSig = []byte(sSig)
	} //end if
	//--
	return bSig
	//--
} //END FUNCTION


func hashSignVerifyWithX509(algo string, data []byte, allowUnsafe bool) (error, []byte) {
	//--
	defer PanicHandler()
	//--
	var signHash []byte = nil
	//--
	algo = StrToLower(algo)
	switch(algo) { // {{{SYNC-OPENSSL-SIGN-ALGO}}} ; sync with PHP
		//--
		case "sha3-512":
			signHash = Sh3aByt512B64(data)
			break
		case "sha3-384":
			signHash = Sh3aByt384B64(data)
			break
		case "sha3-256":
			signHash = Sh3aByt256B64(data)
			break
		//--
		case "sha512":
			signHash = ShaByt512B64(data)
			break
		case "sha384":
			signHash = ShaByt384B64(data)
			break
		case "sha256":
			signHash = ShaByt256B64(data)
			break
		case "sha1": // unsafe, intended just for verify
			if(allowUnsafe != true) {
				return NewError("Unsafe Algo: `" + algo + "`"), nil
			} //end if
			signHash = ShaByt1B64(data)
			break
		//--
		default: // invalid ; important: EcDSA does not support MD5, thus have not supported here at all
			return NewError("Invalid Algo: `" + algo + "`"), nil
	} //end witch
	//--
	if(signHash == nil) {
		return NewError("Hash (" + algo + ") is Null"), nil
	} //end if
	//--
	return nil, Base64BytDecode(signHash)
	//--
} //END FUNCTION


func VerifySignedWithX509PublicKeyPEM(mode string, pemPubKey string, data []byte, b64Signature string, algo string, useASN1 bool) error {
	//--
	defer PanicHandler()
	//--
	pemPubKey = StrTrimWhitespaces(pemPubKey)
	if(pemPubKey == "") {
		return NewError("PublicKey PEM is Empty")
	} //end if
	//--
	if(data == nil) {
		return NewError("Data to Sign is Empty")
	} //end if
	//--
	algo = StrToLower(StrTrimWhitespaces(algo))
	if(algo == "") {
		return NewError("Hash Algo is Empty")
	} //end if
	//--
	errHash, signHash := hashSignVerifyWithX509(algo, data, true) // allow unsafe algos on verify
	if(errHash != nil) {
		return NewError("Hash Algo Failed: " + errHash.Error())
	} //end if
	if(signHash == nil) {
		return NewError("Hash Algo (" + algo + ") Sum is Null")
	} //end if
	//--
	b64Signature = StrTrimWhitespaces(b64Signature)
	if(b64Signature == "") {
		return NewError("B64 Signature is Empty")
	} //end if
	var signature []byte = Base64BytDecode([]byte(b64Signature))
	if(signature == nil) {
		return NewError("Signature is Empty")
	} //end if
	//--
	block, _ := pem.Decode([]byte(pemPubKey))
	if(block == nil) {
		return NewError("Failed to decode PEM PublicKey")
	} //end if
	if(block.Type != "PUBLIC KEY") {
		return NewError("Invalid PEM PublicKey Type: `" + block.Type + "`")
	} //end if
	//--
	_, pubKey, errPKIX := ParseX509PublicKey(block.Bytes, true) // for verify, use fallback ; no need to know the key type
	if(errPKIX != nil) {
		return NewError("Failed to parse PEM PublicKey: " + errPKIX.Error())
	} //end if
	if(pubKey == nil) {
		return NewError("Failed to parse PEM PublicKey, is Null")
	} //end if
	//--
	sig := SignX509Definition{} // Init the signature struct with R and S components
	if(useASN1) {
		//--
		_, errAsn1 := asn1.Unmarshal(signature, &sig)
		if(errAsn1 != nil) {
			return NewError("ASN1 Unmarshal Failed: " + errAsn1.Error())
		} //end if
		//--
	} else {
		//--
		if(mode == "EcDSA") {
			//--
			var reqLen int = 66 // must have fix 512 bytes
			switch(algo) { // {{{SYNC-X509-PADDING-ECDSA-REQ-LEN}}}
				case "sha3-512": fallthrough
				case "sha512":
					// use default: reqLen
					break
				case "sha3-384": fallthrough
				case "sha384":
					reqLen = 48
					break
				case "sha3-256": fallthrough
				case "sha256":
					reqLen = 32
					break
				case "sha1": // supported just for verify
					reqLen = 20
					break
			} //end witch
			//--
			if(len(signature) != reqLen * 2) { // expects: len(r) = 66 ; len(s) = 66
				return NewError("Invalid EcDSA Signature bytes length: " + ConvertIntToStr(len(signature)))
			} //end if
			//--
			sig.R = big.NewInt(0).SetBytes(signature[0:reqLen])
			sig.S = big.NewInt(0).SetBytes(signature[reqLen:reqLen*2])
			//--
		} else {
			//--
			sig.R = big.NewInt(0) // used just by EcDSA
			sig.S = big.NewInt(0).SetBytes(signature) // req. just by EcDSA ; EdDSA, RSA, RSA-PSS use raw bytes in this mode, otherwise some verify fails even if padded ...
			//--
		} //end if else
		//--
	} //end if else
	//--
	var ok bool = false
	switch(mode) { // {{{SYNC-GO-X509-SIGN-VERIFY-MODES}}}
		case "EdDSA": // PureEd25519
			//--
			var eddsaPbKey ed25519.PublicKey
			var okAssert bool
			eddsaPbKey, okAssert = pubKey.(ed25519.PublicKey) // safe assert
			if(!okAssert) {
				return NewError("Failed EdDSA PublicKey")
			} //end if
			if(eddsaPbKey == nil) {
				return NewError("Invalid EdDSA PublicKey")
			} //end if
			//--
			var reqLen int = 64 // must have fix 64 bytes
			var bSig []byte = nil
			if(useASN1) {
				bSig = sig.S.Bytes()
				if(len(bSig) < reqLen) {
					bSig = padX509Signature(bSig, reqLen) // fix for crypto/ed25519: verification error when leading zeroes are gone due conversions from byte[] to biging on signing
				} //end if
			} else { // bug fix, if signature is not ASN1 use it as this because some signature fails with sig SignX509Definition algo
				bSig = signature
			} //end if else
			//--
			if(CryptoX509UxmDebug) {
				log.Println("[DEBUG]", CurrentFunctionName(), "EdDSA verify signed", algo, "useASN1:", useASN1)
			} //end if
			ok = ed25519.Verify(eddsaPbKey, signHash, bSig)
			//--
			break
		case "EcDSA": // ECDSAWithSHA512 ; ECDSAWithSHA384 ; ECDSAWithSHA256
			//--
			var ecdsaPbKey *ecdsa.PublicKey
			var okAssert bool
			ecdsaPbKey, okAssert = pubKey.(*ecdsa.PublicKey) // safe assert
			if(!okAssert) {
				return NewError("Failed EcDSA PublicKey")
			} //end if
			if(ecdsaPbKey == nil) {
				return NewError("Invalid EcDSA PublicKey")
			} //end if
			//--
			// EcDSA is using only BigInt not Bytes ; no need to fix padding, is using directly the BigInt numbers sig.R / sig.S as they are fixed inside ASN1 on Unmarshal ...
			//--
			if(CryptoX509UxmDebug) {
				log.Println("[DEBUG]", CurrentFunctionName(), "EcDSA verify signed", algo, "useASN1:", useASN1)
			} //end if
			ok = ecdsa.Verify(ecdsaPbKey, signHash, sig.R, sig.S)
			//--
			break
		case "RSA": fallthrough 	// SHA512WithRSA ; SHA384WithRSA ; SHA256WithRSA
		case "RSA-PSS": 			// SHA512WithRSAPSS ; SHA384WithRSAPSS ; SHA256WithRSAPSS
			//--
			var rsaPbKey *rsa.PublicKey
			var okAssert bool
			rsaPbKey, okAssert = pubKey.(*rsa.PublicKey) // safe assert
			if(!okAssert) {
				return NewError("Failed RSA PublicKey")
			} //end if
			if(rsaPbKey == nil) {
				return NewError("Invalid RSA PublicKey")
			} //end if
			//--
			hashMode := crypto.SHA512 // default
			var reqLen int = 512 // must have fix 512 bytes
			switch(algo) { // {{{SYNC-X509-PADDING-REQ-LEN}}} ; {{{SYNC-X509-HASHING-BY-ALGO}}}
				case "sha512":
					// use default: crypto.SHA512, reqLen
					break
				case "sha3-512":
					hashMode = crypto.SHA3_512
					// use default: reqLen
					break
				case "sha384":
					hashMode = crypto.SHA384
					reqLen = 384
					break
				case "sha3-384":
					hashMode = crypto.SHA3_384
					reqLen = 384
					break
				case "sha256":
					hashMode = crypto.SHA256
					reqLen = 256
					break
				case "sha3-256":
					hashMode = crypto.SHA3_256
					reqLen = 256
					break
				case "sha1":
					hashMode = crypto.SHA1
					reqLen = 160
					break
			} //end witch
			//--
			var bSig []byte = nil
			if(useASN1) {
				bSig = sig.S.Bytes()
				if(len(bSig) < reqLen) {
					bSig = padX509Signature(bSig, reqLen) // fix for crypto/rsa: verification error when leading zeroes are gone due conversions from byte[] to biging on signing
				} //end if
			} else { // bug fix, if signature is not ASN1 use it as this because some signature fails with sig SignX509Definition algo
				bSig = signature
			} //end if else
			//--
			var errRSAVfy error = NewError("Not Yet Verified ...")
			if(mode == "RSA") {
				if(CryptoX509UxmDebug) {
					log.Println("[DEBUG]", CurrentFunctionName(), "RSA verify signed", algo, "useASN1:", useASN1)
				} //end if
				errRSAVfy = rsa.VerifyPKCS1v15(rsaPbKey, hashMode, signHash, bSig)
			} else { // "RSA-PSS"
				if(CryptoX509UxmDebug) {
					log.Println("[DEBUG]", CurrentFunctionName(), "RSA-PSS verify signed", algo, "useASN1:", useASN1)
				} //end if
				errRSAVfy = rsa.VerifyPSS(rsaPbKey, hashMode, signHash, bSig, nil)
			} //end if else
			if(errRSAVfy != nil) {
				return NewError("RSA Verify Failed with Error: " + errRSAVfy.Error())
			} //end if
			ok = true // if no error above
			//--
			break
		default:
			return NewError("Invalid Mode: `" + mode + "`")
	} //end switch
	if(ok != true) {
		return NewError("Verify Failed: Signature is Invalid")
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func SignWithX509PrivateKeyPEM(mode string, pemPrivKey string, passPrivKey string, pemPubKey string, data []byte, algo string, useASN1 bool) (error, string) {
	//--
	defer PanicHandler()
	//--
	pemPrivKey = StrTrimWhitespaces(pemPrivKey)
	if(pemPrivKey == "") {
		return NewError("PrivateKey PEM is Empty"), ""
	} //end if
	if(passPrivKey != "") {
		var errDecryptPrivPEM error = nil
		errDecryptPrivPEM, pemPrivKey = DecryptPrivateKeyPEM(pemPrivKey, passPrivKey, true) // as PEM
		if(errDecryptPrivPEM != nil) {
			return NewError("Failed to Decrypt the password protected PEM PrivateKey: " + errDecryptPrivPEM.Error()), ""
		} //end if
		pemPrivKey = StrTrimWhitespaces(pemPrivKey)
		if(pemPrivKey == "") {
			return NewError("PrivateKey PEM is Empty after decryption"), ""
		} //end if
	} //end if
	//--
	pemPubKey = StrTrimWhitespaces(pemPubKey)
	if(pemPubKey == "") {
		return NewError("PublicKey PEM is Empty"), ""
	} //end if
	//--
	if(data == nil) {
		return NewError("Data to Sign is Empty"), ""
	} //end if
	//--
	algo = StrToLower(StrTrimWhitespaces(algo))
	if(algo == "") {
		return NewError("Hash Algo is Empty"), ""
	} //end if
	//--
	errHash, signHash := hashSignVerifyWithX509(algo, data, false) // disallow unsafe algos on sign
	if(errHash != nil) {
		return NewError("Hash Algo Failed: " + errHash.Error()), ""
	} //end if
	if(signHash == nil) {
		return NewError("Hash Algo (" + algo + ") Sum is Null"), ""
	} //end if
	//--
	block, _ := pem.Decode([]byte(pemPrivKey))
	if(block == nil) {
		return NewError("Failed to decode PEM PrivateKey"), ""
	} //end if
	if(block.Type != "PRIVATE KEY") {
		return NewError("Invalid PEM PrivateKey Type: `" + block.Type + "`"), ""
	} //end if
	//--
	_, privKey, errParseKey := ParseX509PrivateKey(block.Bytes, false) // no fallback, signing is allowed just with modern keys in PKCS8 format ; key type is not needed here
	if(errParseKey != nil) {
		return NewError("Failed to parse PEM PrivateKey: " + errParseKey.Error()), ""
	} //end if
	if(privKey == nil) {
		return NewError("Failed to parse PEM PrivateKey, is Null"), ""
	} //end if
	//--
	var bSig []byte = nil
	sig := SignX509Definition{} // Init the signature struct with R and S components
	var ok bool = false
	switch(mode) { // {{{SYNC-GO-X509-SIGN-VERIFY-MODES}}}
		case "EdDSA": // PureEd25519
			//--
			var eddsaPvKey ed25519.PrivateKey
			var okAssert bool
			eddsaPvKey, okAssert = privKey.(ed25519.PrivateKey) // safe assert
			if(!okAssert) {
				return NewError("Failed EdDSA PrivateKey"), ""
			} //end if
			if(eddsaPvKey == nil) {
				return NewError("Invalid EdDSA PrivateKey"), ""
			} //end if
			//--
			if(CryptoX509UxmDebug) {
				log.Println("[DEBUG]", CurrentFunctionName(), "EdDSA sign", algo, "useASN1:", useASN1)
			} //end if
			s := ed25519.Sign(eddsaPvKey, signHash)
			if(len(s) != 64) {
				return NewError("Invalid EdDSA Signature Length: " + ConvertIntToStr(len(s)) + " bytes"), ""
			} //end if
			//--
			r := make([]byte, len(s)) // get another 64 random bytes
			_, errRand := crand.Read(r)
		//	_, errRand := io.ReadFull(crand.Reader, r)
			if(errRand != nil) {
				return NewError("Error while generating EdDSA Random Bytes: " + errRand.Error()), ""
			} //end if
			//--
			// no need to check if length of r is 64 because it have a fixed length [64]byte as defined above
			//--
			sig.R = big.NewInt(0).SetBytes(r)
			sig.S = big.NewInt(0).SetBytes(s)
			bSig = s
			//--
			ok = true
			//--
			break
		case "EcDSA": // ECDSAWithSHA512 ; ECDSAWithSHA384 ; ECDSAWithSHA256
			//--
			var ecdsaPvKey *ecdsa.PrivateKey
			var okAssert bool
			ecdsaPvKey, okAssert = privKey.(*ecdsa.PrivateKey) // safe assert
			if(!okAssert) {
				return NewError("Failed EcDSA PrivateKey"), ""
			} //end if
			if(ecdsaPvKey == nil) {
				return NewError("Invalid EcDSA PrivateKey"), ""
			} //end if
			//--
			if(CryptoX509UxmDebug) {
				log.Println("[DEBUG]", CurrentFunctionName(), "EcDSA sign", algo, "useASN1:", useASN1)
			} //end if
			r, s, serr := ecdsa.Sign(crand.Reader, ecdsaPvKey, signHash)
			if(serr != nil) {
				return NewError("EcDSA Sign Failed: " + serr.Error()), ""
			} //end if
			//--
			sig.R = r
			sig.S = s
			//--
			if(useASN1 != true) {
				//--
				var reqLen int = 66 // must have fix 512 bytes
				switch(algo) { // {{{SYNC-X509-PADDING-ECDSA-REQ-LEN}}}
					case "sha3-512": fallthrough
					case "sha512":
						// use default: reqLen
						break
					case "sha3-384": fallthrough
					case "sha384":
						reqLen = 48
						break
					case "sha3-256": fallthrough
					case "sha256":
						reqLen = 32
						break
				} //end witch
				//--
				var bR string = string(r.Bytes())
				var bS string = string(s.Bytes())
				if(len(bR) < reqLen) {
					bR = StrPad2LenLeft(bR, NULL_BYTE, reqLen)
				} //end if
				if(len(bS) < reqLen) {
					bS = StrPad2LenLeft(bS, NULL_BYTE, reqLen)
				} //end if
				if(len(bR) != reqLen) {
					return NewError("Invalid EcDSA R bytes length, expects: " + ConvertIntToStr(reqLen) + ", but have: " + ConvertIntToStr(len(bR))), ""
				} //end if
				if(len(bS) != reqLen) {
					return NewError("Invalid EcDSA S bytes length, expects: " + ConvertIntToStr(reqLen) + ", but have: " + ConvertIntToStr(len(bR))), ""
				} //end if
				//--
				bSig = BytesConcatenate([]byte(bR), []byte(bS))
				//--
			} //end if
			if(bSig == nil) {
				bSig = BytesConcatenate(r.Bytes(), s.Bytes()) // {{{SYNC-X509-EcDSA-ASN1-ONLY}}} ; this is just a fake fix to avoid having nil, will never work to be verified ; anyway, this mode is unsupported by EcDSA
			} //end if
			//--
			ok = true
			//--
			break
		case "RSA": fallthrough 	// SHA512WithRSA ; SHA384WithRSA ; SHA256WithRSA
		case "RSA-PSS": 			// SHA512WithRSAPSS ; SHA384WithRSAPSS ; SHA256WithRSAPSS
			//--
			var rsaPvKey *rsa.PrivateKey
			var okAssert bool
			rsaPvKey, okAssert = privKey.(*rsa.PrivateKey) // safe assert
			if(!okAssert) {
				return NewError("Failed RSA PrivateKey"), ""
			} //end if
			if(rsaPvKey == nil) {
				return NewError("Invalid RSA PrivateKey"), ""
			} //end if
			//--
			hashMode := crypto.SHA512 // default
			switch(algo) { // {{{SYNC-X509-HASHING-BY-ALGO}}}
				//--
				case "sha512":
					// use default: crypto.SHA512
					break
				case "sha3-512":
					hashMode = crypto.SHA3_512
					// use default: reqLen
					break
				case "sha384":
					hashMode = crypto.SHA384
					break
				case "sha3-384":
					hashMode = crypto.SHA3_384
					break
				case "sha256":
					hashMode = crypto.SHA256
					break
				case "sha3-256":
					hashMode = crypto.SHA3_256
					break
			} //end witch
			//--
			var s []byte = nil
			var serr error = NewError("Not Yet Signed ...")
			if(mode == "RSA") {
				if(CryptoX509UxmDebug) {
					log.Println("[DEBUG]", CurrentFunctionName(), "RSA sign", algo, "useASN1:", useASN1)
				} //end if
				s, serr = rsa.SignPKCS1v15(crand.Reader, rsaPvKey, hashMode, signHash)
			} else { // "RSA-PSS"
				if(CryptoX509UxmDebug) {
					log.Println("[DEBUG]", CurrentFunctionName(), "RSA-PSS sign", algo, "useASN1:", useASN1)
				} //end if
				s, serr = rsa.SignPSS(crand.Reader, rsaPvKey, hashMode, signHash, nil)
			} //end if else
			if(serr != nil) {
				return NewError("RSA Sign Failed: " + serr.Error()), ""
			} //end if
			//--
			r := make([]byte, len(s)) // get another random bytes
			_, errRand := crand.Read(r)
		//	_, errRand := io.ReadFull(crand.Reader, r)
			if(errRand != nil) {
				return NewError("Error while generating RSA Random Bytes: " + errRand.Error()), ""
			} //end if
			//--
			sig.R = big.NewInt(0).SetBytes(r)
			sig.S = big.NewInt(0).SetBytes(s)
			bSig = s
			//--
			ok = true
			//--
			break
		default:
			return NewError("Invalid Mode: `" + mode + "`"), ""
	} //end switch
	if(ok != true) {
		return NewError("Sign Failed: Invalid Mode Flag"), ""
	} //end if
	//--
	var signatureBytes []byte = nil
	if(useASN1) {
		var errAsn1 error = nil
		signatureBytes, errAsn1 = asn1.Marshal(sig) // Marshal the signature struct to ASN.1 DER format ; for compatibility with OpenSSL
		if(errAsn1 != nil) {
			return NewError("ASN1 Marshal Failed: " + errAsn1.Error()), ""
		} //end if
	} else {
		signatureBytes = bSig
	} //end if else
	//--
	var b64Signature string = StrTrimWhitespaces(string(Base64BytEncode(signatureBytes)))
	if(b64Signature == "") {
		return NewError("B64 Signature is Empty"), ""
	} //end if
	//--
	errVfy := VerifySignedWithX509PublicKeyPEM(mode, pemPubKey, data, b64Signature, algo, useASN1)
	if(errVfy != nil) {
		return NewError("Sign Verification Failed: " + errVfy.Error()), ""
	} //end if
	//--
	return nil, b64Signature
	//--
} //END FUNCTION


func VerifyX509CertificatePEM(pemCertificate string, verifyOpts map[string]string) error {
	//--
	defer PanicHandler()
	//--
	// TODO: extend certinfo to get as a structure with many info to be able to verify other options ...
	//--
	pemCertificate = StrTrimWhitespaces(pemCertificate)
	if(pemCertificate == "") {
		return NewError("Certificate PEM is Empty")
	} //end if
	//--
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(pemCertificate))
	if(!ok) {
		return NewError("Failed to parse PEM Certificate")
	} //end if
	//--
	block, _ := pem.Decode([]byte(pemCertificate))
	if(block == nil) {
		return NewError("Failed to decode PEM Certificate")
	} //end if
	if(block.Type != "CERTIFICATE") {
		return NewError("Invalid PEM Certificate Type: `" + block.Type + "`")
	} //end if
	//--
	cert, err := x509.ParseCertificate(block.Bytes)
	if(err != nil) {
		return NewError("Failed to parse Certificate: " + err.Error())
	} //end if
	if(cert == nil) {
		return NewError("Failed to parse Certificate, is Null")
	} //end if
	//--
	iCert := certinspect.ParseCertificateInfo(cert)
	if(iCert == nil) {
		return NewError("Failed to inspect the Certificate, result is Null")
	} //end if
	if(CryptoX509UxmDebug) {
		log.Println("[DEBUG]", CurrentFunctionName(), "Certificate Inspection:", fmt.Sprintf("%+v\n", iCert))
	} //end if
	//--
	opts := x509.VerifyOptions{
		Roots: 						roots,
		Intermediates: 				x509.NewCertPool(),
		MaxConstraintComparisions: 	1,
	}
	//--
	if(verifyOpts != nil) {
		if(len(verifyOpts) > 0) {
			var keyUsages []x509.ExtKeyUsage
			var certPolicies []x509.OID // compatible just with golang > 1.23
			const inspFailed string 			= "Certificate Inspection Failed: %s != %s"
			const inspStartsFailed string 		= "Certificate Inspection Failed: %s ^~ %s"
			const inspContainsFailed string 	= "Certificate Inspection Failed: %s &~ %s"
			const inspEndsFailed string 		= "Certificate Inspection Failed: %s $~ %s"
			const inspArrContainsFailed string 	= "Certificate Inspection Failed: %s @~ %s"
			for key, val := range verifyOpts {
				key = StrTrimWhitespaces(key)
				// do not trim val, startsWith, contains, endsWith may have leading or trailing spaces, for safety
				if(StrStartsWith(key, "keyUsage")) {
					if(val != "!") {
						return NewError("Invalid value for key: " + key + " = `" + val + "` ; acceptable value is `!`")
					} //end if
				} //end if
				switch(key) {
					//-- from inspect
					case "IsCA":
						switch(val) {
							case "true":
								if(iCert.IsCA != true) {
									return NewError(fmt.Sprintf(inspFailed, key, val))
								} //end if
								break
							case "false":
								if(iCert.IsCA == true) {
									return NewError(fmt.Sprintf(inspFailed, key, val))
								} //end if
								break
							default:
								return NewError(fmt.Sprintf(inspFailed, key, val) + " ; acceptable value is `true` or `false`")
						} //end switch
						break
					case "Subject": // subject is equal with
						if(iCert.Subject != val) {
							return NewError(fmt.Sprintf(inspFailed, key, val))
						} //end if
						break
					case "Subject^~": // subject starts with, case sensitive
						if(!StrStartsWith(iCert.Subject, val)) {
							return NewError(fmt.Sprintf(inspStartsFailed, key, val))
						} //end if
						break
					case "Subject^*": // subject starts with, case insensitive
						if(!StrIStartsWith(iCert.Subject, val)) {
							return NewError(fmt.Sprintf(inspStartsFailed, key, val))
						} //end if
						break
					case "Subject&~": // subject contains with, case sensitive
						if(!StrContains(iCert.Subject, val)) {
							return NewError(fmt.Sprintf(inspContainsFailed, key, val))
						} //end if
						break
					case "Subject&*": // subject contains with, case sensitive
						if(!StrIContains(iCert.Subject, val)) {
							return NewError(fmt.Sprintf(inspContainsFailed, key, val))
						} //end if
						break
					case "Subject&|~": fallthrough 	// subject contains with, case sensitive
					case "Subject&|*": 				// subject contains with, case insensitive
						arrExp := Explode("|", val)
						var exprFound bool = false
						for itr:=0; itr<len(arrExp); itr++ {
							arrExp[itr] = StrTrimWhitespaces(arrExp[itr])
							if(arrExp[itr] != "") {
								if(StrEndsWith(key, "&|~") && StrContains(iCert.Subject, arrExp[itr])) { // case sensitive
									exprFound = true
								} else if(StrEndsWith(key, "&|*") && StrIContains(iCert.Subject, arrExp[itr])) { // case insensitive
									exprFound = true
								} //end if
							} //end if
						} //end for
						if(exprFound != true) {
							return NewError(fmt.Sprintf(inspContainsFailed, key, val))
						} //end if
						break
					case "Subject$~": // subject ends with, case sensitive
						if(!StrEndsWith(iCert.Subject, val)) {
							return NewError(fmt.Sprintf(inspEndsFailed, key, val))
						} //end if
						break
					case "Subject$*": // subject ends with, case insensitive
						if(!StrIEndsWith(iCert.Subject, val)) {
							return NewError(fmt.Sprintf(inspEndsFailed, key, val))
						} //end if
						break
					case "Issuer": // issuer is equal with
						if(iCert.Issuer != val) {
							return NewError(fmt.Sprintf(inspFailed, key, val))
						} //end if
						break
					case "Issuer^~": // issuer starts with, case sensitive
						if(!StrStartsWith(iCert.Issuer, val)) {
							return NewError(fmt.Sprintf(inspStartsFailed, key, val))
						} //end if
						break
					case "Issuer^*": // issuer starts with, case insensitive
						if(!StrIStartsWith(iCert.Issuer, val)) {
							return NewError(fmt.Sprintf(inspStartsFailed, key, val))
						} //end if
						break
					case "Issuer&~": // issuer contains with, case sensitive
						if(!StrContains(iCert.Issuer, val)) {
							return NewError(fmt.Sprintf(inspContainsFailed, key, val))
						} //end if
						break
					case "Issuer&*": // issuer contains with, case insensitive
						if(!StrIContains(iCert.Issuer, val)) {
							return NewError(fmt.Sprintf(inspContainsFailed, key, val))
						} //end if
						break
					case "Issuer&|~": fallthrough 	// issuer contains with, case sensitive
					case "Issuer&|*": 				// issuer contains with, case insensitive
						arrExp := Explode("|", val)
						var exprFound bool = false
						for itr:=0; itr<len(arrExp); itr++ {
							arrExp[itr] = StrTrimWhitespaces(arrExp[itr])
							if(arrExp[itr] != "") {
								if(StrEndsWith(key, "&|~") && StrContains(iCert.Subject, arrExp[itr])) { // case sensitive
									exprFound = true
								} else if(StrEndsWith(key, "&|*") && StrIContains(iCert.Subject, arrExp[itr])) { // case insensitive
									exprFound = true
								} //end if
							} //end if
						} //end for
						if(exprFound != true) {
							return NewError(fmt.Sprintf(inspContainsFailed, key, val))
						} //end if
					case "Issuer$~": // issuer ends with, case sensitive
						if(!StrEndsWith(iCert.Issuer, val)) {
							return NewError(fmt.Sprintf(inspEndsFailed, key, val))
						} //end if
						break
					case "Issuer$*": // issuer ends with, case insensitive
						if(!StrIEndsWith(iCert.Issuer, val)) {
							return NewError(fmt.Sprintf(inspEndsFailed, key, val))
						} //end if
						break
					case "KeyUsage@~": // KeyUsage array contains
						if(StrTrimWhitespaces(val) != "") {
							arrUsages := Explode(",", val)
							for i:=0; i<len(arrUsages); i++ {
								arrUsages[i] = StrTrimWhitespaces(arrUsages[i])
								if(arrUsages[i] != "") {
									if(!InListArr(arrUsages[i], iCert.KeyUsage)) {
										return NewError(fmt.Sprintf(inspArrContainsFailed, key, val))
									} //end if
								} //end if
							} //end for
						} //end if
						break
					case "ExtKeyUsage@~": // ExtKeyUsage array contains
						if(StrTrimWhitespaces(val) != "") {
							arrUsages := Explode(",", val)
							for i:=0; i<len(arrUsages); i++ {
								arrUsages[i] = StrTrimWhitespaces(arrUsages[i])
								if(arrUsages[i] != "") {
									if(!InListArr(arrUsages[i], iCert.ExtKeyUsage)) {
										return NewError(fmt.Sprintf(inspArrContainsFailed, key, val))
									} //end if
								} //end if
							} //end for
						} //end if
						break
					case "SignatureAlgo": // exact match, upper case
						if(StrToUpper(val) != iCert.SignatureAlgo) {
							return NewError(fmt.Sprintf(inspFailed, key, val))
						} //end if
					//-- below are internal, go x509 verifications ...
					case "isExpired":
						tm, errTm := time.Parse(time.RFC3339, val) // RFC3339, ex: "2025-01-02T15:04:05Z"
						if(errTm != nil) {
							return NewError("Invalid value for isExpired: " + errTm.Error())
						} //end if
						opts.CurrentTime = tm
						break
					case "dnsName":
						opts.DNSName = val
						break
					case "keyUsageAny":
						keyUsages = append(keyUsages, x509.ExtKeyUsageAny)
						break
					case "keyUsageServerAuth":
						keyUsages = append(keyUsages, x509.ExtKeyUsageServerAuth)
						break
					case "keyUsageClientAuth":
						keyUsages = append(keyUsages, x509.ExtKeyUsageClientAuth)
						break
					case "keyUsageCodeSigning":
						keyUsages = append(keyUsages, x509.ExtKeyUsageCodeSigning)
						break
					case "keyUsageEmailProtection":
						keyUsages = append(keyUsages, x509.ExtKeyUsageEmailProtection)
						break
					case "keyUsageTimeStamping":
						keyUsages = append(keyUsages, x509.ExtKeyUsageTimeStamping)
						break
					case "keyUsageOCSPSigning":
						keyUsages = append(keyUsages, x509.ExtKeyUsageOCSPSigning)
						break
					case "oidPolicies": // compatible just with golang > 1.23 ; ex: "0.4.0.194112.1.2"
						if(StrTrimWhitespaces(val) != "") {
							arrOIDs := Explode(",", val)
							for i:=0; i<len(arrOIDs); i++ {
								arrOIDs[i] = StrTrimWhitespaces(arrOIDs[i])
								if(arrOIDs[i] != "") {
									oid, errOID := x509.ParseOID(arrOIDs[i])
									if(errOID != nil) {
										return NewError("Unknown Policy OID: `" + val + "`")
									} //end if
									certPolicies = append(certPolicies, oid)
								} //end if
							} //end for
						} //end if
						break
					//--
					default:
						return NewError("Unknown Verify Option: `" + key + "`")
					//--
				} //end switch
			} //end for
			if(len(keyUsages) > 0) {
				opts.KeyUsages = keyUsages
			} //end if
			if(len(certPolicies) > 0) { // compatible just with golang > 1.23
				opts.CertificatePolicies = certPolicies
			} //end if
		} //end if
	} //end if
	//--
	if(CryptoX509UxmDebug) {
		log.Println("[DEBUG]", CurrentFunctionName(), "verify options:", fmt.Sprintf("%+v\n", opts))
	} //end if
	//--
	if _, err := cert.Verify(opts); err != nil {
		return NewError("Certificate Verification Failed: " + err.Error())
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


//-----


func ParseX509PrivateEd25519Key(derBytes []byte) (typ string, prvEd25519 ed25519.PrivateKey, err error) {
	//--
	defer PanicHandler()
	//--
	var prv any
	typ, prv, err = ParseX509PrivateKey(derBytes, false) // Ed25519 private key can only use PKCS8 format
	//--
	if((err != nil) || (prv == nil)) {
		return typ, nil, err
	} //end if
	//--
	var okAssert bool
	prvEd25519, okAssert = prv.(ed25519.PrivateKey)
	if(!okAssert) {
		return typ, nil, NewError("Invalid Private Key Type, Not Ed25519")
	} //end if
	if(prvEd25519 == nil) {
		return typ, nil, NewError("Invalid Ed25519 Private Key Type, Null")
	} //end if
	//--
	typ = "Ed25519.Priv"
	//--
	return typ, prvEd25519, err
	//--
} //END FUNCTION


func ParseX509PrivateEcdsaKey(derBytes []byte) (typ string, prvEcdsa *ecdsa.PrivateKey, err error) {
	//--
	defer PanicHandler()
	//--
	var prv any
	typ, prv, err = ParseX509PrivateKey(derBytes, false) // EcDSA private key can only use PKCS8 format
	//--
	if((err != nil) || (prv == nil)) {
		return typ, nil, err
	} //end if
	//--
	var okAssert bool
	prvEcdsa, okAssert = prv.(*ecdsa.PrivateKey)
	if(!okAssert) {
		return typ, nil, NewError("Invalid Private Key Type, Not EcDSA")
	} //end if
	if(prvEcdsa == nil) {
		return typ, nil, NewError("Invalid EcDSA Private Key Type, Null")
	} //end if
	//--
	typ = "EcDSA.Priv"
	//--
	return typ, prvEcdsa, err
	//--
} //END FUNCTION


func ParseX509PrivateRsaKey(derBytes []byte, fallback bool) (typ string, prvRsa *rsa.PrivateKey, err error) {
	//--
	defer PanicHandler()
	//--
	var prv any
	typ, prv, err = ParseX509PrivateKey(derBytes, fallback)
	//--
	if((err != nil) || (prv == nil)) {
		return typ, nil, err
	} //end if
	//--
	var okAssert bool
	prvRsa, okAssert = prv.(*rsa.PrivateKey)
	if(!okAssert) {
		return typ, nil, NewError("Invalid Private Key Type, Not RSA")
	} //end if
	if(prvRsa == nil) {
		return typ, nil, NewError("Invalid RSA Private Key Type, Null")
	} //end if
	//--
	typ = "RSA.Priv"
	//--
	return typ, prvRsa, err
	//--
} //END FUNCTION


func ParseX509PrivateKey(derBytes []byte, fallback bool) (typ string, prv any, err error) {
	//--
	defer PanicHandler()
	//--
	if(CryptoX509UxmDebug) {
		log.Println("[DEBUG]", CurrentFunctionName(), "Legacy Support Enabled:", ConvertBoolToStr(enableLegacySupport))
	} //end if
	//--
	if((derBytes == nil) || (len(derBytes) <= 0)) {
		return "", nil, NewError("X509 Private Key is Empty, cannot parse")
	} //end if
	//--
	prv, err = x509.ParsePKCS8PrivateKey(derBytes) // modern
	if(err == nil) {
		typ = privateKeyTypePKCS8
	} else if((fallback == true) && (enableLegacySupport == true)) { // legacy, only if enabled ... ; {{{SYNC-SMARTGO-X509-ENABLE-LEGACY}}}
		prv, err = x509.ParsePKCS1PrivateKey(derBytes) // older format, RSA
		if(err == nil) {
			typ = privateKeyTypeEC
		} else {
				prv, err = x509.ParseECPrivateKey(derBytes) // older format, ECDSA
			if(err == nil) {
				typ = privateKeyTypePKCS1
			} //end if
		} //end if
	} //end if
	//--
	if(err != nil) {
		return "", nil, NewError("X509 Private Key parse Failed: " + err.Error())
	} //end if
	//--
	return typ, prv, err
	//--
} //END FUNCTION


//-----


func ParseX509PublicEd25519Key(derBytes []byte) (typ string, pubEd25519 ed25519.PublicKey, err error) {
	//--
	defer PanicHandler()
	//--
	var prv any
	typ, prv, err = ParseX509PublicKey(derBytes, false) // Ed25519 public key can only use PKIX format
	//--
	if((err != nil) || (prv == nil)) {
		return typ, nil, err
	} //end if
	//--
	var okAssert bool
	pubEd25519, okAssert = prv.(ed25519.PublicKey)
	if(!okAssert) {
		return typ, nil, NewError("Invalid Public Key Type, Not Ed25519")
	} //end if
	if(pubEd25519 == nil) {
		return typ, nil, NewError("Invalid Ed25519 Public Key Type, Null")
	} //end if
	//--
	typ = "Ed25519.Pub"
	//--
	return typ, pubEd25519, err
	//--
} //END FUNCTION


func ParseX509PublicEcdsaKey(derBytes []byte) (typ string, pubEcdsa *ecdsa.PublicKey, err error) {
	//--
	defer PanicHandler()
	//--
	var prv any
	typ, prv, err = ParseX509PublicKey(derBytes, false) // EcDSA public key can only use PKIX format
	//--
	if((err != nil) || (prv == nil)) {
		return typ, nil, err
	} //end if
	//--
	var okAssert bool
	pubEcdsa, okAssert = prv.(*ecdsa.PublicKey)
	if(!okAssert) {
		return typ, nil, NewError("Invalid Public Key Type, Not EcDSA")
	} //end if
	if(pubEcdsa == nil) {
		return typ, nil, NewError("Invalid EcDSA Public Key Type, Null")
	} //end if
	//--
	typ = "EcDSA.Pub"
	//--
	return typ, pubEcdsa, err
	//--
} //END FUNCTION


func ParseX509PublicRsaKey(derBytes []byte, fallback bool) (typ string, pubRsa *rsa.PublicKey, err error) {
	//--
	defer PanicHandler()
	//--
	var prv any
	typ, prv, err = ParseX509PublicKey(derBytes, fallback)
	//--
	if((err != nil) || (prv == nil)) {
		return typ, nil, err
	} //end if
	//--
	var okAssert bool
	pubRsa, okAssert = prv.(*rsa.PublicKey)
	if(!okAssert) {
		return typ, nil, NewError("Invalid Public Key Type, Not RSA")
	} //end if
	if(pubRsa == nil) {
		return typ, nil, NewError("Invalid RSA Public Key Type, Null")
	} //end if
	//--
	typ = "RSA.Pub"
	//--
	return typ, pubRsa, err
	//--
} //END FUNCTION


func ParseX509PublicKey(derBytes []byte, fallback bool) (typ string, pub any, err error) {
	//--
	defer PanicHandler()
	//--
	if(CryptoX509UxmDebug) {
		log.Println("[DEBUG]", CurrentFunctionName(), "Legacy Support Enabled:", ConvertBoolToStr(enableLegacySupport))
	} //end if
	//--
	if((derBytes == nil) || (len(derBytes) <= 0)) {
		return "", nil, NewError("X509 Public Key is Empty, cannot parse")
	} //end if
	//--
	pub, err = x509.ParsePKIXPublicKey(derBytes) // modern
	if(err == nil) {
		typ = publicKeyTypePKIX
	} else if((fallback == true) && (enableLegacySupport == true)) { // legacy, only if enabled ... ; {{{SYNC-SMARTGO-X509-ENABLE-LEGACY}}}
		pub, err = x509.ParsePKCS1PublicKey(derBytes) // older format: RSA
		if(err == nil) {
			typ = publicKeyTypePKCS1
		} //end if
	} //end if
	//--
	if(err != nil) {
		return "", nil, NewError("X509 Public Key parse Failed: " + err.Error())
	} //end if
	//--
	return typ, pub, err
	//--
} //END FUNCTION


//-----


func ExtractX509PublicKeyFromCertificatePEM(pemCertificate string, formatPEM bool) (error, string) {
	//--
	defer PanicHandler()
	//--
	pemCertificate = StrTrimWhitespaces(pemCertificate)
	if(pemCertificate == "") {
		return NewError("Certificate PEM is Empty"), ""
	} //end if
	//--
	block, _ := pem.Decode([]byte(pemCertificate))
	if(block == nil) {
		return NewError("Failed to decode PEM Certificate"), ""
	} //end if
	if(block.Type != "CERTIFICATE") {
		return NewError("Invalid PEM Certificate Type: `" + block.Type + "`"), ""
	} //end if
	//--
	cert, err := x509.ParseCertificate(block.Bytes)
	if(err != nil) {
		return NewError("Failed to parse PEM Certificate: " + err.Error()), ""
	} //end if
	if(cert == nil) {
		return NewError("Failed to parse PEM Certificate, is Null"), ""
	} //end if
	//--
	if(cert.PublicKey == nil) {
		return NewError("PublicKey is Null"), ""
	} //end if
	//--
	var mrslPkixErr error = nil
	var mrslPkcs1Err error = nil
	var pubBytes []byte = nil
	var typKey string = ""
	pubBytes, mrslPkixErr = x509.MarshalPKIXPublicKey(cert.PublicKey) // try 1st PKIX (modern format)
	if(mrslPkixErr != nil) { // here needs falback, don't know what kind of key a certificate may have
		var okAssert bool
		var tryRsaCert *rsa.PublicKey
		tryRsaCert, okAssert = cert.PublicKey.(*rsa.PublicKey) // safe assert
		if(okAssert) {
			if(tryRsaCert != nil) {
				pubBytes = x509.MarshalPKCS1PublicKey(tryRsaCert) // fallback on PKCS1, legacy format
				typKey = publicKeyTypePKCS1
			} else {
				mrslPkcs1Err = NewError("Invalid Certificare Type")
			} //end if else
		} else {
			mrslPkcs1Err = NewError("Type Conversion Error")
		} //end if else
	} else {
		typKey = publicKeyTypePKIX
	} //end if else
	if(mrslPkcs1Err != nil) {
		return NewError("PublicKey PKCS1 conversion Failed: " + mrslPkixErr.Error()), ""
	} else if(mrslPkixErr != nil) {
		return NewError("PublicKey PKIX conversion Failed: " + mrslPkixErr.Error()), ""
	} //end if
	if(pubBytes == nil) {
		if(typKey == publicKeyTypePKCS1) {
			return NewError("PublicKey PKCS1 conversion Failed, is Null"), ""
		} else {
			return NewError("PublicKey PKIX conversion Failed, is Null"), ""
		} //end if else
	} //end if
	//--
	if(formatPEM == false) {
		return nil, string(BytTrimWhitespaces(Base64BytEncode(pubBytes)))
	} //end if
	//--
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY",
		Bytes: pubBytes,
	})
	//--
	return nil, StrTrimWhitespaces(string(pubPEM))
	//--
} //END FUNCTION


func ExtractX509PublicKeyFromPrivateKeyPEM(mode string, pemPrivKey string, passPrivKey string, formatPEM bool) (error, string) {
	//--
	defer PanicHandler()
	//--
	pemPrivKey = StrTrimWhitespaces(pemPrivKey)
	if(pemPrivKey == "") {
		return NewError("PrivateKey PEM is Empty"), ""
	} //end if
	//--
	if(passPrivKey != "") {
		var errDecryptPrivPEM error = nil
		errDecryptPrivPEM, pemPrivKey = DecryptPrivateKeyPEM(pemPrivKey, passPrivKey, true) // as PEM
		if(errDecryptPrivPEM != nil) {
			return NewError("Failed to Decrypt the password protected PEM PrivateKey: " + errDecryptPrivPEM.Error()), ""
		} //end if
		pemPrivKey = StrTrimWhitespaces(pemPrivKey)
		if(pemPrivKey == "") {
			return NewError("PrivateKey PEM is Empty after decryption"), ""
		} //end if
	} //end if
	//--
	block, _ := pem.Decode([]byte(pemPrivKey))
	if(block == nil) {
		return NewError("Failed to decode PEM PrivateKey"), ""
	} //end if
	if(block.Type != "PRIVATE KEY") {
		return NewError("Invalid PEM PrivateKey Type: `" + block.Type + "`"), ""
	} //end if
	//--
	typKey, privKey, errParseKey := ParseX509PrivateKey(block.Bytes, true) // allow fallback, extract must work with 3rd party certificates
	if(errParseKey != nil) {
		return NewError("Failed to parse PEM PrivateKey: " + errParseKey.Error()), ""
	} //end if
	if(privKey == nil) {
		return NewError("Failed to parse PEM PrivateKey, is Null"), ""
	} //end if
	//--
	var mrslErr error = nil
	var pubBytes []byte = nil
	switch(mode) { // {{{SYNC-GO-X509-SIGN-VERIFY-MODES}}}
		case "EdDSA": // PureEd25519
			//--
			var eddsaPvKey ed25519.PrivateKey
			var okAssert bool
			eddsaPvKey, okAssert = privKey.(ed25519.PrivateKey) // safe assert
			if(!okAssert) {
				return NewError("Failed EdDSA PublicKey conversion from PrivateKey"), ""
			} //end if
			if(eddsaPvKey == nil) {
				return NewError("Invalid EdDSA PublicKey conversion from PrivateKey"), ""
			} //end if
			var eddsaPbKey crypto.PublicKey = eddsaPvKey.Public()
			if(eddsaPbKey == nil) {
				return NewError("Invalid EdDSA PublicKey"), ""
			} //end if
			//--
			switch(typKey) {
				case privateKeyTypePKCS8: // OK
					pubBytes, mrslErr = x509.MarshalPKIXPublicKey(eddsaPbKey)
					if(mrslErr != nil) {
						return NewError("EdDSA PublicKey PKIX conversion Failed: " + mrslErr.Error()), ""
					} //end if
					break
				case privateKeyTypeEC: // KO: this is only supported for legacy EcDSA
					return NewError("EdDSA PublicKey EC conversion Failed, unsupported type"), ""
					break
				case privateKeyTypePKCS1: // KO: only for legacy RSA
					return NewError("EdDSA PublicKey PKCS1 conversion Failed, unsupported type"), ""
					break
				default: // KO: unknown ... should not be landing here
					return NewError("EdDSA PublicKey conversion Failed, unknown type: " + typKey), ""
			} //end switch
			//--
			break
		case "EcDSA": // ECDSAWithSHA512 ; ECDSAWithSHA384 ; ECDSAWithSHA256
			//--
			var ecdsaPvKey *ecdsa.PrivateKey
			var okAssert bool
			ecdsaPvKey, okAssert = privKey.(*ecdsa.PrivateKey) // safe assert
			if(!okAssert) {
				return NewError("Failed EcDSA PublicKey conversion from PrivateKey"), ""
			} //end if
			if(ecdsaPvKey == nil) {
				return NewError("Invalid EcDSA PublicKey conversion from PrivateKey"), ""
			} //end if
			var ecdsaPbKey crypto.PublicKey = &ecdsaPvKey.PublicKey
			if(ecdsaPbKey == nil) {
				return NewError("Invalid EcDSA PublicKey"), ""
			} //end if
			//--
			switch(typKey) {
				case privateKeyTypePKCS8: // OK
					pubBytes, mrslErr = x509.MarshalPKIXPublicKey(ecdsaPbKey)
					if(mrslErr != nil) {
						return NewError("EcDSA PublicKey PKIX conversion Failed: " + mrslErr.Error()), ""
					} //end if
					break
				case privateKeyTypeEC: // KO: go is missing or there is not an EC marshal public key method ; go only have MarshalECPrivateKey which is for generating legacy certificates in EC format
					return NewError("EcDSA PublicKey EC conversion Failed, unsupported type"), ""
					break
				case privateKeyTypePKCS1: // KO: only for legacy RSA
					return NewError("EcDSA PublicKey PKCS1 conversion Failed, unsupported type"), ""
					break
				default: // KO: unknown ... should not be landing here
					return NewError("EcDSA PublicKey conversion Failed, unknown type: " + typKey), ""
			} //end switch
			//--
			break
		case "RSA": fallthrough 	// SHA512WithRSA ; SHA384WithRSA ; SHA256WithRSA
		case "RSA-PSS": 			// SHA512WithRSAPSS ; SHA384WithRSAPSS ; SHA256WithRSAPSS
			//--
			var rsaPvKey *rsa.PrivateKey
			var okAssert bool
			rsaPvKey, okAssert = privKey.(*rsa.PrivateKey) // safe assert
			if(!okAssert) {
				return NewError("Failed RSA PublicKey conversion from PrivateKey"), ""
			} //end if
			if(rsaPvKey == nil) {
				return NewError("Invalid RSA PublicKey conversion from PrivateKey"), ""
			} //end if
			var rsaPbKey *rsa.PublicKey = &rsaPvKey.PublicKey // cannot cast to crypto.PublicKey in this context
			if(rsaPbKey == nil) {
				return NewError("Invalid RSA PublicKey"), ""
			} //end if
			//--
			switch(typKey) {
				case privateKeyTypePKCS8: // OK
					pubBytes, mrslErr = x509.MarshalPKIXPublicKey(rsaPbKey)
					if(mrslErr != nil) {
						return NewError("RSA PublicKey PKIX conversion Failed: " + mrslErr.Error()), ""
					} //end if
					break
				case privateKeyTypeEC: // KO: this is only supported for legacy EcDSA
					return NewError("RSA PublicKey EC conversion Failed, unsupported type"), ""
					break
				case privateKeyTypePKCS1: // OK, legacy
					pubBytes = x509.MarshalPKCS1PublicKey(rsaPbKey) // there is no error control in this old method
					break
				default: // KO: unknown ... should not be landing here
					return NewError("RSA PublicKey conversion Failed, unknown type: " + typKey), ""
			} //end switch
			//--
			break
		default:
			return NewError("Invalid Mode: `" + mode + "`"), ""
	} //end switch
	if(mrslErr != nil) {
		return NewError("PublicKey conversion Failed by Unknown Reason: " + mrslErr.Error()), ""
	} //end if
	if(pubBytes == nil) {
		return NewError("PublicKey is Null after conversion"), ""
	} //end if
	//--
	if(formatPEM == false) {
		return nil, string(BytTrimWhitespaces(Base64BytEncode(pubBytes)))
	} //end if
	//--
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY",
		Bytes: pubBytes,
	})
	//--
	return nil, StrTrimWhitespaces(string(pubPEM))
	//--
} //END FUNCTION


func IsB64PublicKeyEqualWithPemPublicKey(b64PubKey string, pemPubKey string) bool {
	//--
	// DO NOT MODIFY THIS METHOD, it should use a canonize method to ensure all type of keys are validated, includding the ones from mime messages of which base64 key is splitted on multiple lines and also have a space after CRLF
	//--
	defer PanicHandler()
	//--
	b64PubKey = StrTrimWhitespaces(b64PubKey)
	if(b64PubKey == "") {
		return false
	} //end if
	pemPubKey = StrTrimWhitespaces(pemPubKey)
	if(pemPubKey == "") {
		return false
	} //end if
	//--
	b64PubKey = StrTrimWhitespaces(StrNormalizeLineEndings(Base64NormalizeMultiLineData(b64PubKey)))
	if(b64PubKey == "") {
		return false
	} //end if
	pemPubKey = StrTrimWhitespaces(StrNormalizeLineEndings(Base64NormalizeMultiLineData(pemPubKey)))
	if(pemPubKey == "") {
		return false
	} //end if
	b64PubKey = StrTrimWhitespaces(StrTrimWhitespaces(X509PemPublicKeyStartTag) + b64PubKey + StrTrimWhitespaces(X509PemPublicKeyEndTag))
	b64PubKey = StrTrimWhitespaces(StrNormalizeLineEndings(Base64NormalizeMultiLineData(b64PubKey)))
	if(b64PubKey == "") {
		return false
	} //end if
	if(b64PubKey != pemPubKey) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func GetB64PublicKeyFromPem(pemPubKey string) (string, error) {
	//--
	defer PanicHandler()
	//--
	pemPubKey = StrTrimWhitespaces(pemPubKey)
	if(pemPubKey == "") {
		return "", NewError("PEM PublicKey is Empty")
	} //end if
	//--
	block, _ := pem.Decode([]byte(pemPubKey))
	if(block == nil) {
		return "", NewError("Failed to decode PEM PublicKey")
	} //end if
	if(block.Type != "PUBLIC KEY") {
		return "", NewError("Invalid PEM PublicKey Type: `" + block.Type + "`")
	} //end if
	//--
	return string(BytTrimWhitespaces(Base64BytEncode(block.Bytes))), nil
	//--
} //END FUNCTION


func Asn1DecodeX509PublicKeyPKIXB64(b64PublicKey string) (error, string) {
	//--
	// why this method ?
	// for Ed25519 the key length from X509 is 44 bytes instead of 32, as it is using some extra ASN.1 info, so this method will extract the real public key s of 32 bytes
	// for EcDSA and RSA this should be working too
	// works just for modern public keys compatible with ParsePKIXPublicKey() format
	//--
	defer PanicHandler()
	//--
	b64PublicKey = StrTrimWhitespaces(b64PublicKey)
	if(b64PublicKey == "") {
		return NewError("B64 Public Key is Empty"), ""
	} //end if
	//--
	var rawPublicKey string = Base64Decode(b64PublicKey)
	if(rawPublicKey == "") {
		return NewError("Public Key is Empty after B64 Decode"), ""
	} //end if
	//-- unixman: below code taken and adapted from golang/crypto/x509.go # x509.ParsePKIXPublicKey()
	var derBytes []byte = []byte(rawPublicKey)
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return NewError("Failed to parse Public Key, ASN1 Unmarshal failed: " + err.Error()), ""
	} else if len(rest) > 0 {
		return NewError("Failed to parse Public Key, Trailing data after ASN.1 of PublicKey"), ""
	} //end if
	//-- #end
	var b []byte = pki.PublicKey.Bytes
	if(b == nil) {
		return NewError("Failed to Convert the Public Key, Null"), ""
	} //end if
	if(len(b) <= 0) {
		return NewError("Failed to Convert the Public Key, Empty"), ""
	} //end if
	b = BytTrimWhitespaces(Base64BytEncode(b))
	if(b == nil) {
		return NewError("Failed to B64 Encode the Public Key, Null"), ""
	} //end if
	if(len(b) <= 0) {
		return NewError("Failed to B64 Encode the Public Key, Empty"), ""
	} //end if
	//--
	return nil, string(b)
	//--
} // END FUNCTION


func DecryptPrivateKeyPEM(pemPrivKey string, password string, formatPEM bool) (error, string) {
	//--
	defer PanicHandler()
	//--
	block, _ := pem.Decode([]byte(pemPrivKey))
	if(block == nil) {
		return NewError("Failed to decode PEM PrivateKey"), ""
	} //end if
	if(block.Type != "PRIVATE KEY") {
		return NewError("Invalid PEM PrivateKey Type: `" + block.Type + "`"), ""
	} //end if
	//--
	if(!encryptedBlock(block) || !IsEncryptedPEMBlockAES256(block)) {
		return NewError("Invalid or Not an Encrypted PEM PrivateKey"), ""
	} //end if
	//--
	buf, err := DecryptPEMBlockAES256(block, []byte(password))
	if(err != nil) {
		return NewError("Invalid or Not an AES256 Encrypted PEM PrivateKey: " + err.Error()), ""
	} //end if
	//--
	if(formatPEM == false) {
		return nil, string(BytTrimWhitespaces(Base64BytEncode(buf)))
	} //end if
	//--
	plainBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	}
	privatePlainPem := BytTrimWhitespaces(pem.EncodeToMemory(plainBlock))
	if(privatePlainPem == nil) {
		return NewError("Failed to re-encode the plain PrivateKey as PEM"), ""
	} //end if
	//--
	return nil, string(privatePlainPem)
	//--
} //END FUNCTION


//-----


func GenerateX509CertificateWithCA(certCaInfo CertX509Info, certCliInfo CertX509Info, sigAlg x509.SignatureAlgorithm) (CertX509KeyPair, CertX509KeyPair, error) {
	//--
	defer PanicHandler()
	//--
	signer, err := GenerateX509Certificate(certCaInfo, sigAlg, true, "", nil) // ca
	if(err != nil) {
		return CertX509KeyPair{}, CertX509KeyPair{}, err
	} //end if
	//--
	pair, err := GenerateX509Certificate(certCliInfo, sigAlg, false, string(certCaInfo.Password), signer) // client
	if(err != nil) {
		return CertX509KeyPair{}, CertX509KeyPair{}, err
	} //end if
	//--
	return *signer, *pair, nil
	//--
} //END FUNCTION


func GenerateX509Certificate(certInfo CertX509Info, sigAlg x509.SignatureAlgorithm, isCA bool, caPwd string, issuer *CertX509KeyPair) (*CertX509KeyPair, error) {
	//--
	defer PanicHandler()
	//--
	if(CryptoX509UxmDebug) {
		log.Println("[DEBUG]", CurrentFunctionName(), sigAlg, "isCA:", isCA)
	} //end if
	//--
	var validity int 	= int(certInfo.Validity)
	if(validity < 1) {
		return nil, NewError("Min Validity is 1 year")
	} else if(validity > 100) { // sync with PHP
		return nil, NewError("Min Validity is 100 years")
	} //end if else
	//--
	var name string 	= StrTrimWhitespaces(certInfo.CommonName)
	var altname string 	= StrTrimWhitespaces(certInfo.AltName)
	var hosts string 	= StrTrimWhitespaces(certInfo.Hosts)
	var org string 		= StrTrimWhitespaces(certInfo.Organization)
	var unit string 	= StrTrimWhitespaces(certInfo.OrgUnit)
	var country string 	= StrTrimWhitespaces(certInfo.Country)
	var region string 	= StrTrimWhitespaces(certInfo.Region)
	var city string 	= StrTrimWhitespaces(certInfo.City)
	var street string 	= StrTrimWhitespaces(certInfo.Street)
	var zipcode string 	= StrTrimWhitespaces(certInfo.PostalCode)
	//--
	var ocspUrl string = StrTrimWhitespaces(certInfo.OCSPUrl)
	if(isCA != true) { // ca
		if(ocspUrl != "") {
			return nil, NewError("OCSP Url is just for CA")
		} //end if
	} //end if
	//--
	var pwd string = string(certInfo.Password) // do not trim !
	//--
	if(name == "") {
		return nil, NewError("Common Name is Empty")
	} //end if
	//--
	var (
		err 			error
		priv 			crypto.PrivateKey
		pubk 			crypto.PublicKey
		derCert 		[]byte
		issuerCert 		*x509.Certificate
		issuerKey 		crypto.PrivateKey
		issuerPubKey 	crypto.PublicKey
	)
	//--
	if(isCA == true) { // ca
		if(issuer != nil) {
			return nil, NewError("CA Certificate cannot have an Issuer")
		} //end if
	} else {
		if(issuer == nil) {
			return nil, NewError("CA Certificate must have an Issuer")
		} //end if
	} //end if else
	//--
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(888888887777777787), 256) // 256 bit serial, starting from 888888887777777787 as min, to have a safe large number as min.
	serialNumber, errSerial := crand.Int(crand.Reader, serialNumberLimit)
	if(errSerial != nil) {
		return nil, NewError("Certificate Serial Error: " + errSerial.Error())
	} //end if
	//--
	criticalTimestampExt, errCritTimeStamp := criticalTimestamping()
	if(errCritTimeStamp != nil) {
		return nil, errCritTimeStamp
	} //end if
	//--
	extKey := []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if(isCA == true) {
		extKey = append(extKey, x509.ExtKeyUsageOCSPSigning)
	} //end if
	//--
	subject := pkix.Name{
		SerialNumber: 	serialNumber.String(),
		CommonName: 	name,
	}
	if(org != "") {
		subject.Organization = []string{org}
		if(unit != "") {
			subject.OrganizationalUnit = []string{unit}
		} //end if
	} //end if
	if(country != "") {
		subject.Country = []string{country}
		if(region != "") {
			subject.Province = []string{region}
			if(city != "") {
				subject.Locality = []string{city}
				if(street != "") {
					subject.StreetAddress = []string{street}
				} //end if
				if(zipcode != "") {
					subject.PostalCode = []string{zipcode}
				} //end if
			} //end if
		} //end if
	} //end if
	//--
	var subjId string = uid.Uuid17Seq() + "-" + uid.Uuid13Str() + "-" + uid.Uuid10Num() // UInt64ToHex(NanoTimeRandInt63N(1001, -1))
	//println("subjId", subjId)
	template := x509.Certificate{ // nonRepudiation: recent editions of X.509 have renamed this bit to contentCommitment
		Version: 				3,
		SerialNumber: 			serialNumber,
		Subject: 				subject,
		NotBefore: 				time.Now().Add(-1 * time.Second),
		NotAfter: 				time.Now().AddDate(validity, 0, 0),
		IsCA: 					false,
		BasicConstraintsValid: 	true,
		KeyUsage: 				x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: 			extKey,
		Extensions: 			append([]pkix.Extension{}, criticalTimestampExt),
		ExtraExtensions: 		[]pkix.Extension{},
	//	MaxPathLen: 			2,
	}
	//--
	if(hosts != "") {
		arrHosts := Explode(",", hosts) // ex: "127.0.0.1,localhost"
		for _, h := range arrHosts {
			h = StrToLower(StrTrimWhitespaces(h))
			if(h != "") {
				if(StrContains(h, "@")) {
					if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, h)) {
						return nil, NewError("Invalid Email Address in Hosts: `" + h + "`")
					} //end if
					template.EmailAddresses = append(template.EmailAddresses, h)
				} else if((StrStartsWith(h, "https://")) || (StrStartsWith(h, "http://"))) {
					if(IsNetValidHttpUrl(h) != true) {
						return nil, NewError("Invalid URL in Hosts: `" + h + "`")
					} //end if
					pUrl, errUrl := ParseUrl(h)
					if((errUrl != nil) || (pUrl == nil)) {
						return nil, NewError("Wrong URL in Hosts: `" + h + "`")
					} //end if
					if((pUrl.Scheme != "https") && (pUrl.Scheme != "http")) {
						return nil, NewError("Invalid URL Prefix in Hosts: `" + h + "`")
					} //end if
					template.URIs = append(template.URIs, pUrl)
				} else if(IsNetValidIpAddr(h) == true) {
					ip := net.ParseIP(h)
					if(ip == nil) {
						return nil, NewError("Invalid IP Address in Hosts: `" + h + "`")
					} //end if
					template.IPAddresses = append(template.IPAddresses, ip)
				} else {
					if(IsNetValidHostName(h) != true) {
						return nil, NewError("Invalid DNS Name in Hosts: `" + h + "`")
					} //end if
					template.DNSNames = append(template.DNSNames, h)
				} //end if else
			} //end if
		} //end for
	} //end if
	//--
	if(altname != "") {
		extSubjectAltName := pkix.Extension{}
		extSubjectAltName.Id = asn1.ObjectIdentifier{2, 5, 29, 17}
		extSubjectAltName.Critical = false
		extSubjectAltName.Value, err = asn1.Marshal([]string{altname}) // ex: `email:my@mail.tld, URI:http://ca.dom.tld/`
		if(err != nil) {
			return nil, NewError("AltName is Invalid")
		} //end if
		template.ExtraExtensions = []pkix.Extension{extSubjectAltName}
	} //end if
	//--
	template.SubjectKeyId = []byte(subjId)
	//--
	if(isCA) {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.KeyUsage |= x509.KeyUsageCRLSign
		template.AuthorityKeyId = []byte(subjId)
		if(ocspUrl != "") {
			pUrl, errUrl := ParseUrl(ocspUrl)
			if((errUrl != nil) || (pUrl == nil)) {
				return nil, NewError("Invalid OCSP URL: `" + ocspUrl + "`")
			} //end if
			if(pUrl.Scheme != "https") {
				return nil, NewError("Invalid OCSP URL, must start with https: `" + ocspUrl + "`")
			} //end if
			template.OCSPServer = []string{ocspUrl}
		} //end if
	//	template.BasicConstraintsValid = true // already set global
	} //end if
	//--
	if((isCA != true) && (issuer != nil)) {
		//--
		issuer.PemCertificate = StrTrimWhitespaces(issuer.PemCertificate)
		if(issuer.PemCertificate == "") {
			return nil, NewError("Issuer PEM Certificate is Empty")
		} //end if
		certBlock, _ := pem.Decode([]byte(issuer.PemCertificate))
		if(certBlock == nil) {
			return nil, NewError("Failed to Parse Issuer PEM Certificate")
		} //end if
		issuerCert, err = x509.ParseCertificate(certBlock.Bytes)
		if(err != nil) {
			return nil, NewError("Failed to Parse Issuer Certificate: " + err.Error())
		} //end if
		if(issuerCert == nil) {
			return nil, NewError("Failed to Parse Issuer Certificate, is Null")
		} //end if
		//--
		template.AuthorityKeyId = []byte(issuerCert.SubjectKeyId)
		//--
		issuer.PemPrivateKey = StrTrimWhitespaces(issuer.PemPrivateKey)
		if(issuer.PemPrivateKey == "") {
			return nil, NewError("Issuer PEM Private Key is Empty")
		} //end if
		keyBlock, _ := pem.Decode([]byte(issuer.PemPrivateKey))
		if(keyBlock == nil) {
			return nil, NewError("Failed to Parse Issuer PEM Private Key")
		} //end if
		if(caPwd != "") {
			var decryptedBlock []byte
			decryptedBlock, err = DecryptPEMBlockAES256(keyBlock, []byte(caPwd))
			if(err != nil) {
				return nil, err
			} //end if
			if(decryptedBlock == nil) {
				return nil, NewError("Failed to Decrypt Private Key by Issuer Pass, Null")
			} //end if
			keyBlock = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: decryptedBlock,
			}
		} //end if
		_, issuerKey, err = ParseX509PrivateKey(keyBlock.Bytes, false) // no fallback, this must be strict in PKCS8 format, when issue a new certificate
		if(err != nil) {
			return nil, NewError("Failed to Parse Issuer Private Key: " + err.Error())
		} //end if
		if(issuerKey == nil) {
			return nil, NewError("Failed to Parse Issuer Private Key, is Null")
		} //end if
		//--
		issuer.PemPublicKey = StrTrimWhitespaces(issuer.PemPublicKey)
		if(issuer.PemPublicKey == "") {
			return nil, NewError("Issuer PEM Public Key is Empty")
		} //end if
		keyPubBlock, _ := pem.Decode([]byte(issuer.PemPublicKey))
		if(keyPubBlock == nil) {
			return nil, NewError("Failed to Parse Issuer PEM Public Key")
		} //end if
		_, issuerPubKey, err = ParseX509PublicKey(keyPubBlock.Bytes, false) // no fallback, this must be strict in PKIX format, when issue a new certificate
		if(err != nil) {
			return nil, NewError("Failed to Parse Issuer Public Key: " + err.Error())
		} //end if
		if(issuerPubKey == nil) {
			return nil, NewError("Issuer PEM Public Key is Null")
		} //end if
		//--
	} //end if
	//--
	switch sigAlg {
		case x509.PureEd25519: // Ed25519 (EdDSA)
			_, priv, err = ed25519.GenerateKey(crand.Reader)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case ed25519.PrivateKey:
					template.SignatureAlgorithm = x509.PureEd25519
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
		case x509.ECDSAWithSHA512: // EcDSA-SHA512
			priv, err = ecdsa.GenerateKey(elliptic.P521(), crand.Reader)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case *ecdsa.PrivateKey:
					template.SignatureAlgorithm = x509.ECDSAWithSHA512
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
		case x509.ECDSAWithSHA384: // EcDSA-SHA384
			priv, err = ecdsa.GenerateKey(elliptic.P384(), crand.Reader)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case *ecdsa.PrivateKey:
					template.SignatureAlgorithm = x509.ECDSAWithSHA384
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
		case x509.ECDSAWithSHA256: // EcDSA-SHA256
			priv, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case *ecdsa.PrivateKey:
					template.SignatureAlgorithm = x509.ECDSAWithSHA256
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
		case x509.SHA512WithRSAPSS: // RSA-PSS 4094
			priv, err = rsa.GenerateKey(crand.Reader, 4096)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case *rsa.PrivateKey:
					template.SignatureAlgorithm = x509.SHA512WithRSAPSS
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
		case x509.SHA512WithRSA: // RSA 4094
			priv, err = rsa.GenerateKey(crand.Reader, 4096)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case *rsa.PrivateKey:
					template.SignatureAlgorithm = x509.SHA512WithRSA
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
		case x509.SHA384WithRSAPSS: // RSA-PSS 3072
			priv, err = rsa.GenerateKey(crand.Reader, 3072)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case *rsa.PrivateKey:
					template.SignatureAlgorithm = x509.SHA384WithRSAPSS
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
		case x509.SHA384WithRSA: // RSA 3072
			priv, err = rsa.GenerateKey(crand.Reader, 3072)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case *rsa.PrivateKey:
					template.SignatureAlgorithm = x509.SHA384WithRSA
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
		case x509.SHA256WithRSAPSS: // RSA-PSS 2048
			priv, err = rsa.GenerateKey(crand.Reader, 2048)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case *rsa.PrivateKey:
					template.SignatureAlgorithm = x509.SHA256WithRSAPSS
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
		case x509.SHA256WithRSA: // RSA 2048
			priv, err = rsa.GenerateKey(crand.Reader, 2048)
			if(err != nil) {
				return nil, err
			} //end if
			switch issuerKey.(type) {
				case nil:
					if(!isCA) {
						return nil, NewError("Null Issuer Algo")
					} //end if
					break
				case *rsa.PrivateKey:
					template.SignatureAlgorithm = x509.SHA256WithRSA
					break
				default:
					return nil, NewError("Invalid Issuer Algo")
			} //end switch
			break
	} //end switch
	//--
	if(priv == nil) {
		return nil, NewError("Private key is Null")
	} //end if
	//--
	if(issuer == nil) { // no issuer given,make this a self-signed root cert
		issuerCert = &template
		issuerKey = priv
	} //end if
	//--
	switch priv.(type) {
		case ed25519.PrivateKey:
			var theKey ed25519.PrivateKey
			var okAssert bool
			theKey, okAssert = priv.(ed25519.PrivateKey) // safe assert
			if(!okAssert) {
				return nil, NewError("Failed Issuer PrivKey Algo, Type")
			} //end if
			if(theKey == nil) {
				return nil, NewError("Failed Issuer PrivKey Algo, Null")
			} //end if
			pubk = theKey.Public()
			switch issuerKey.(type) {
				case ed25519.PrivateKey:
					pvKey, okAsrt := issuerKey.(ed25519.PrivateKey) // safe assert
					if(!okAsrt) {
						return nil, NewError("Failed Issuer PrivKey Algo, Type: EdDSA")
					} //end if
					if(pvKey == nil) {
						return nil, NewError("Failed Issuer PrivKey Algo, Null: EdDSA")
					} //end if
					derCert, err = x509.CreateCertificate(crand.Reader, &template, issuerCert, pubk, pvKey)
					break
				default:
					return nil, NewError("Invalid Issuer PrivKey Algo")
			} //end switch
			break
		case *ecdsa.PrivateKey:
			var theKey *ecdsa.PrivateKey
			var okAssert bool
			theKey, okAssert = priv.(*ecdsa.PrivateKey) // safe assert
			if(!okAssert) {
				return nil, NewError("Failed Issuer PrivKey Algo, Type")
			} //end if
			if(theKey == nil) {
				return nil, NewError("Failed Issuer PrivKey Algo, Null")
			} //end if
			pubk = theKey.Public()
			switch issuerKey.(type) {
				case *ecdsa.PrivateKey:
					pvKey, okAsrt := issuerKey.(*ecdsa.PrivateKey) // safe assert
					if(!okAsrt) {
						return nil, NewError("Failed Issuer PrivKey Algo, Type: EcDSA")
					} //end if
					if(pvKey == nil) {
						return nil, NewError("Failed Issuer PrivKey Algo, Null: EcDSA")
					} //end if
					derCert, err = x509.CreateCertificate(crand.Reader, &template, issuerCert, pubk, pvKey)
					break
				default:
					return nil, NewError("Invalid Issuer PrivKey Algo")
			} //end switch
			break
		case *rsa.PrivateKey:
			var theKey *rsa.PrivateKey
			var okAssert bool
			theKey, okAssert = priv.(*rsa.PrivateKey) // safe assert
			if(!okAssert) {
				return nil, NewError("Failed Issuer PrivKey Algo, Type")
			} //end if
			if(theKey == nil) {
				return nil, NewError("Failed Issuer PrivKey Algo, Null")
			} //end if
			pubk = theKey.Public()
			switch issuerKey.(type) {
				case *rsa.PrivateKey:
					pvKey, okAsrt := issuerKey.(*rsa.PrivateKey) // safe assert
					if(!okAsrt) {
						return nil, NewError("Failed Issuer PrivKey Algo, Type: RSA")
					} //end if
					if(pvKey == nil) {
						return nil, NewError("Failed Issuer PrivKey Algo, Null: RSA")
					} //end if
					derCert, err = x509.CreateCertificate(crand.Reader, &template, issuerCert, pubk, pvKey)
					break
				default:
					return nil, NewError("Invalid Issuer PrivKey Algo")
			} //end switch
			break
		default:
			return nil, NewError("Invalid Issuer PrivKey Type")
	} //end switch
	if(pubk == nil) {
		return nil, NewError("Public key is Null")
	} //end if
	//--
	if(err != nil) {
		return nil, err
	} //end if
	if(len(derCert) <= 0) {
		return nil, NewError("No CA Certificate created, probably due to wrong keys")
	} //end if
	//--
	cert, errParseCertif := x509.ParseCertificate(derCert)
	if(errParseCertif != nil) {
		return nil, NewError("CA certificate Error: " + errParseCertif.Error())
	} //end if
	if(cert == nil) {
		return nil, NewError("CA certificate is Null")
	} //end if
	//--
	if(isCA == true) {
		err = cert.CheckSignatureFrom(cert)
		if(err != nil) {
			return nil, NewError("CA Certificate Signature is Invalid: " + err.Error())
		} //end if
	} else {
		cpb, _ := pem.Decode([]byte(issuer.PemCertificate))
		crt, errIssParse := x509.ParseCertificate(cpb.Bytes)
		if(errIssParse != nil) {
			return nil, NewError("Certificate Parsing CA Issuer Failed: " + errIssParse.Error())
		} //end if
		if(crt == nil) {
			return nil, NewError("Certificate Parsing CA Issuer Failed, is Null")
		} //end if
		err = cert.CheckSignatureFrom(crt)
		if(err != nil) {
			return nil, NewError("Certificate Signature is Invalid: " + err.Error())
		} //end if
	} //end if
	//--
	privBytes, pkcs8PrivErr := x509.MarshalPKCS8PrivateKey(priv) // new certificate must use PKCS8 only for the Private Key
	if(pkcs8PrivErr != nil) {
		return nil, pkcs8PrivErr
	} //end if
	if(privBytes == nil) {
		return nil, NewError("CA Certificate Private Key is Null")
	} //end if
	//--
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	certTestPrivPEM := pem.EncodeToMemory(block) // the test must be done on the un-encrypted version
	if(pwd != "") {
		block, err = EncryptPEMBlockAES256(block.Type, block.Bytes, []byte(pwd))
	} //end if
	privatePem := pem.EncodeToMemory(block)
	//--
	pubBytes, pkcs8PubErr := x509.MarshalPKIXPublicKey(pubk) // new certificate must use PKIX only for the Public Key
	if(pkcs8PubErr != nil) {
		return nil, pkcs8PubErr
	} //end if
	if(pubBytes == nil) {
		return nil, NewError("CA Certificate Public Key is Null")
	} //end if
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY",
		Bytes: pubBytes,
	})
	//--
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	//--
	_, errSrvCert := tls.X509KeyPair([]byte(certPem), []byte(certTestPrivPEM)) // test if certificate can be loaded by a server, with TLS
	if(errSrvCert != nil) {
		return nil, errSrvCert
	} //end if
	//--
	keyPair := &CertX509KeyPair{
		PemCertificate: StrTrimWhitespaces(string(certPem)),
		PemPrivateKey:  StrTrimWhitespaces(string(privatePem)),
		PemPublicKey:   StrTrimWhitespaces(string(pubPEM)),
	}
	//--
	return keyPair, nil
	//--
} //END FUNCTION


//-----


func criticalTimestamping() (ext pkix.Extension, err error) {
	//--
	defer PanicHandler()
	//--
	var oidExtensionExtendedKeyUsage= asn1.ObjectIdentifier{2, 5, 29, 37}
	var oidExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	//--
	ext = pkix.Extension{}
	ext.Id = oidExtensionExtendedKeyUsage
	ext.Critical = true
	ext.Value, err = asn1.Marshal([]asn1.ObjectIdentifier{oidExtKeyUsageTimeStamping})
	//--
	return ext, err
	//--
} //END FUNCTION


//-----


type PEMCipher int // taken from x509.PEMCipherAES256

const PEMCipherAES256 = 5 // taken from x509.PEMCipherAES256


// rfc1423Algo holds a method for enciphering a PEM block.
type rfc1423Algo struct {
	cipher     PEMCipher
	name       string
	cipherFunc func(key []byte) (cipher.Block, error)
	keySize    int
	blockSize  int
}

// deriveKey uses a key derivation function to stretch the password into a key
// with the number of bits our cipher requires. This algorithm was derived from
// the OpenSSL source.
func (c rfc1423Algo) deriveKey(password, salt []byte) []byte {
	//--
	defer PanicHandler()
	//--
	hash := md5.New()
	out := make([]byte, c.keySize)
	var digest []byte
	for i := 0; i < len(out); i += len(digest) {
		hash.Reset()
		hash.Write(digest)
		hash.Write(password)
		hash.Write(salt)
		digest = hash.Sum(digest[:0])
		copy(out[i:], digest)
	} //end for
	//--
	return out
	//--
} //END FUNCTION


var rfc1423AlgoPEMCipherAES256 rfc1423Algo = rfc1423Algo{
	cipher:     4,
	name:       "AES-256-CBC",
	cipherFunc: aes.NewCipher,
	keySize:    32,
	blockSize:  aes.BlockSize,
}


// encryptedBlock tells whether a private key is encrypted by examining its Proc-Type header for a mention of ENCRYPTED according to RFC 1421 Section 4.6.1.1.
func encryptedBlock(block *pem.Block) bool { // modified version, taken from of go/x/crypto/ssh/keys.go
	//--
	defer PanicHandler()
	//--
	if(block == nil) {
		return false
	} //end if
	//--
	return StrContains(block.Headers["Proc-Type"], "ENCRYPTED")
	//--
} //END FUNCTION


func IsEncryptedPEMBlockAES256(b *pem.Block) bool { // modified version of deprecated x509.IsEncryptedPEMBlock
	//--
	defer PanicHandler()
	//--
	if(b == nil) {
		return false
	} //end if
	//--
	if(!encryptedBlock(b)) {
		return false
	} //end if
	//--
	mode, ok := b.Headers["DEK-Info"]
	if(!ok) {
		return false
	} //end if
	//--
	mode = StrTrimWhitespaces(mode)
	if(mode == "") {
		return false
	} //end if
	//--
	if(!StrStartsWith(mode, "AES-256-CBC,")) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func EncryptPEMBlockAES256(blockType string, data []byte, password []byte) (*pem.Block, error) { // modified version of deprecated x509.EncryptPEMBlock
	//--
	defer PanicHandler()
	//--
	if(data == nil) {
		return nil, NewError("x509Cert: Data to Encrypt is Null")
	} //end if
	if(password == nil) {
		return nil, NewError("x509Cert: Encryption Password is Null")
	} //end if
	//--
	ciph := rfc1423AlgoPEMCipherAES256
	//--
	rand := crand.Reader
	//--
	iv := make([]byte, ciph.blockSize)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, NewError("x509Cert: cannot generate IV: " + err.Error())
	} //end if
	//-- The salt is the first 8 bytes of the initialization vector, matching the key derivation in DecryptPEMBlock.
	key := ciph.deriveKey(password, iv[:8])
	if(key == nil) {
		return nil, NewError("x509Cert: cannot generate derived key, is Null")
	} //end if
	block, err := ciph.cipherFunc(key)
	if(err != nil) {
		return nil, err
	} //end if
	//--
	enc := cipher.NewCBCEncrypter(block, iv)
	pad := ciph.blockSize - len(data)%ciph.blockSize
	encrypted := make([]byte, len(data), len(data)+pad)
	//-- We could save this copy by encrypting all the whole blocks in the data separately, but it doesn't seem worth the additional code.
	copy(encrypted, data)
	//-- See RFC 1423, Section 1.1.
	for i := 0; i < pad; i++ {
		encrypted = append(encrypted, byte(pad))
	} //end for
	enc.CryptBlocks(encrypted, encrypted)
	//--
	return &pem.Block{
		Type: blockType,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  ciph.name + "," + string(Bin2BytHex(iv)),
		},
		Bytes: encrypted,
	}, nil
	//--
} //END FUNCTION


func DecryptPEMBlockAES256(b *pem.Block, password []byte) ([]byte, error) { // separate version of deprecated x509.DecryptPEMBlock
	//--
	defer PanicHandler()
	//--
	if(b == nil) {
		return nil, NewError("x509Cert: Block is Null")
	} //end if
	//--
	ciph := rfc1423AlgoPEMCipherAES256
	//--
	var incorrectPasswordError = NewError("x509Cert: decryption password incorrect")
	//--
	dek, ok := b.Headers["DEK-Info"]
	if(!ok) {
		return nil, NewError("x509Cert: no DEK-Info header in block")
	} //end if
	//--
	mode, hexIV, ok := strings.Cut(dek, ",")
	if(!ok) {
		return nil, NewError("x509Cert: malformed DEK-Info header: " + mode)
	} //end if
	//--
	iv := Hex2BytBin([]byte(hexIV))
	if(iv == nil) {
		return nil, NewError("x509Cert: empty IV after Hex Decode")
	} //end if
	if(len(iv) != ciph.blockSize) {
		return nil, NewError("x509Cert: incorrect IV size")
	} //end if
	//-- Based on the OpenSSL implementation. The salt is the first 8 bytes of the initialization vector.
	key := ciph.deriveKey(password, iv[:8])
	if(key == nil) {
		return nil, NewError("x509Cert: cannot generate derived key, is Null")
	} //end if
	block, err := ciph.cipherFunc(key)
	if(err != nil) {
		return nil, err
	} //end if
	//--
	if((len(b.Bytes) % block.BlockSize()) != 0) {
		return nil, NewError("x509Cert: encrypted PEM data is not a multiple of the block size")
	} //end if
	//--
	data := make([]byte, len(b.Bytes))
	dec := cipher.NewCBCDecrypter(block, iv)
	dec.CryptBlocks(data, b.Bytes)
	// Blocks are padded using a scheme where the last n bytes of padding are all
	// equal to n. It can pad from 1 to blocksize bytes inclusive. See RFC 1423.
	// For example:
	//	[x y z 2 2]
	//	[x y 7 7 7 7 7 7 7]
	// If we detect a bad padding, we assume it is an invalid password.
	//--
	dlen := len(data)
	if(dlen == 0 || (dlen % ciph.blockSize != 0)) {
		return nil, NewError("x509Cert: invalid padding")
	} //end if
	last := int(data[dlen-1])
	if(dlen < last) {
		return nil, incorrectPasswordError
	} //end if
	if(last == 0 || (last > ciph.blockSize)) {
		return nil, incorrectPasswordError
	} //end if
	for _, val := range data[dlen-last:] {
		if(int(val) != last) {
			return nil, incorrectPasswordError
		} //end if
	} //end for
	//--
	return data[:dlen-last], nil
	//--
} //END FUNCTION


//-----


// #END
