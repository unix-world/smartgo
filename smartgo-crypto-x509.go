
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20251229.2358 :: STABLE
// [ CRYPTO / X509 ]

// REQUIRE: go 1.22 or later
package smartgo

import (
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
)


const (
	PureEd25519 		= x509.PureEd25519

	ECDSAWithSHA512 	= x509.ECDSAWithSHA512
	ECDSAWithSHA384 	= x509.ECDSAWithSHA384
	ECDSAWithSHA256 	= x509.ECDSAWithSHA256

	SHA512WithRSAPSS 	= x509.SHA512WithRSAPSS
	SHA384WithRSAPSS 	= x509.SHA384WithRSAPSS
	SHA256WithRSAPSS 	= x509.SHA256WithRSAPSS

	SHA256WithRSA 		= x509.SHA256WithRSA
	SHA384WithRSA 		= x509.SHA384WithRSA
	SHA512WithRSA 		= x509.SHA512WithRSA
)


type CertX509KeyPair struct {
	PemCertificate string
	PemPrivateKey  string
	PemPublicKey   string
}

type CertInfo struct {
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


func GenerateX509CertificateWithCA(certCaInfo CertInfo, certCliInfo CertInfo, sigAlg x509.SignatureAlgorithm) (CertX509KeyPair, CertX509KeyPair, error) {
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


func GenerateX509Certificate(certInfo CertInfo, sigAlg x509.SignatureAlgorithm, isCA bool, caPwd string, issuer *CertX509KeyPair) (*CertX509KeyPair, error) {
	//--
	defer PanicHandler()
	//--
	var validity int 	= int(certInfo.Validity)
	if(validity < 1) {
		return nil, NewError("Min Validity is 1 year")
	} else if(validity > 10) {
		return nil, NewError("Min Validity is 10 years")
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
		keyPrefix 		string
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
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 256) // 256 bit serial
	serialNumber, errSerial := crand.Int(crand.Reader, serialNumberLimit)
	if(errSerial != nil) {
		return nil, NewError("Serial Error: " + errSerial.Error())
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
	template := x509.Certificate{
		Version: 			3,
		SerialNumber: 		serialNumber,
		Subject: 			subject,
		NotBefore: 			time.Now().Add(-1 * time.Second),
		NotAfter: 			time.Now().AddDate(validity, 0, 0),
		KeyUsage: 			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: 		extKey,
		Extensions: 		append([]pkix.Extension{}, criticalTimestampExt),
		ExtraExtensions: 	[]pkix.Extension{},
	//	MaxPathLen: 	2,
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
			return nil, NewError("Altname is Invalid")
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
		template.BasicConstraintsValid = true
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
			return nil, NewError("Failed to Parse Issuer Certificate")
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
		issuerKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if(err != nil) {
			return nil, NewError("Failed to Parse Issuer Private Key")
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
		issuerPubKey, err = x509.ParsePKIXPublicKey(keyPubBlock.Bytes)
		if(err != nil) {
			return nil, NewError("Failed to Parse Issuer Public Key")
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
			keyPrefix = "ED"
			pubk = priv.(ed25519.PrivateKey).Public()
			switch issuerKey.(type) {
				case ed25519.PrivateKey:
					derCert, err = x509.CreateCertificate(crand.Reader, &template, issuerCert, pubk, issuerKey.(ed25519.PrivateKey))
					break
				default:
					return nil, NewError("Invalid Issuer PrivKey Algo")
			} //end switch
			break
		case *ecdsa.PrivateKey:
			keyPrefix = "EC"
			pubk = priv.(*ecdsa.PrivateKey).Public()
			switch issuerKey.(type) {
				case *ecdsa.PrivateKey:
					derCert, err = x509.CreateCertificate(crand.Reader, &template, issuerCert, pubk, issuerKey.(*ecdsa.PrivateKey))
					break
				default:
					return nil, NewError("Invalid Issuer PrivKey Algo")
			} //end switch
			break
		case *rsa.PrivateKey:
			keyPrefix = "RSA"
			pubk = priv.(*rsa.PrivateKey).Public()
			switch issuerKey.(type) {
				case *rsa.PrivateKey:
					derCert, err = x509.CreateCertificate(crand.Reader, &template, issuerCert, pubk, issuerKey.(*rsa.PrivateKey))
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
		return nil, NewError("No certificate created, probably due to wrong keys")
	} //end if
	//--
	cert, errParseCertif := x509.ParseCertificate(derCert)
	if(errParseCertif != nil) {
		return nil, err
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
		err = cert.CheckSignatureFrom(crt)
		if(err != nil) {
			return nil, NewError("Certificate Signature is Invalid: " + err.Error())
		} //end if
	} //end if
	//--
	if(isCA) {
		keyPrefix = StrTrimWhitespaces("CA " + keyPrefix)
	} //end if
	//--
	privBytes, pkcs8PrivErr := x509.MarshalPKCS8PrivateKey(priv)
	if(pkcs8PrivErr != nil) {
		return nil, pkcs8PrivErr
	} //end if
	//--
	block := &pem.Block{
		Type:  StrTrimWhitespaces(keyPrefix + " PRIVATE KEY"),
		Bytes: privBytes,
	}
	certTestPrivPEM := pem.EncodeToMemory(block) // the test must be done on the un-encrypted version
	if(pwd != "") {
		block, err = EncryptPEMBlockAES256(block.Type, block.Bytes, []byte(pwd))
	} //end if
	privatePem := pem.EncodeToMemory(block)
	//--
	pubBytes, pkcs8PubErr := x509.MarshalPKIXPublicKey(pubk)
	if(pkcs8PubErr != nil) {
		return nil, pkcs8PubErr
	} //end if
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type: StrTrimWhitespaces(keyPrefix + " PUBLIC KEY"),
		Bytes: pubBytes,
	})
	//--
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE", // this must not include key prefix because servers fail to parse it
		Bytes: cert.Raw,
	})
	//--
	_, errSrvCert := tls.X509KeyPair([]byte(certPem), []byte(certTestPrivPEM)) // test if certificate can be loaded by a server, with TLS
	if(errSrvCert != nil) {
		return nil, errSrvCert
	} //end if
	//--
	keyPair := &CertX509KeyPair{
		PemCertificate: string(certPem),
		PemPrivateKey: string(privatePem),
		PemPublicKey: string(pubPEM),
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


func EncryptPEMBlockAES256(blockType string, data []byte, password []byte) (*pem.Block, error) { // modified version of deprecated x509.EncryptPEMBlock
	//--
	defer PanicHandler()
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


func DecryptPEMBlockAES256(b *pem.Block, password []byte) ([]byte, error) {
	//--
	defer PanicHandler()
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
