
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260915.2358 :: STABLE
// [ MAIL / SEND ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"log"

	"time"
	"io"

	"crypto"

	uid 				"github.com/unix-world/smartgo/crypto/uuid"
	dkim 				"github.com/unix-world/smartgo/mx/dkim"
	mailer 				"github.com/unix-world/smartgo/utils/mail"
	certinfo 			"github.com/unix-world/smartgo/crypto/x509-certinfo"
	validatemailaddr 	"github.com/unix-world/smartgo/validate/email"
)

const (
	MIME_FROM_NAME_MAX_LEN 			 			uint64 =   128
	MIME_SUBJECT_MAX_LEN 						uint64 =   255
	MIME_BODY_MAX_LEN  							uint64 = 65535
	MIME_EMBEDS_MAX_NUM 		 	 			uint64 =    16
	MIME_ATTACHMENTS_MAX_NUM 	 	 			uint64 =    32
	MIME_FILENAME_MAX_LEN 		 	 			uint64 =    64

	MIME_SIZE_PER_ATTACH_OR_EMBEDD 				uint64 = SIZE_BYTES_16M * 2 //  32MB (ex: gmail only have 25MB)
	MIME_SIZE_TOTAL_ATTACH_AND_EMBEDD 			uint64 = SIZE_BYTES_16M * 8 // 128MB (safety) ; {{{SYNC-MIME-MESSAGE-TOTAL-SIZE}}}
)

const ( // DO NOT CHANGE any of these, they are synced with the mailer
	SMTP_AUTH_NONE 								string = "NONE" 		// use no auth ; if this is set the username/pass(token) should be empty
	SMTP_AUTH_CRAMMD5 							string = "CRAM-MD5" 	// this is the only smtp auth method supported for unencrypted smtp connections
	SMTP_AUTH_LOGIN 							string = "LOGIN" 		// legacy, wide supported ; requires encrypted ssl/starttls smtp connection
	SMTP_AUTH_PLAIN 							string = "PLAIN" 		// modern, wide supported ; requires encrypted ssl/starttls smtp connection
	SMTP_AUTH_XOAUTH2 							string = "XOAUTH2" 		// very modern, will use bearer token instead of password ; supported by gmail
	SMTP_AUTH_OAUTHBEARER 						string = "OAUTHBEARER" 	// newest, will use bearer token instead of password ; supported by gmail

	SMTP_TLS_STARTTLS 							string = "STARTTLS"
	SMTP_TLS_OPTIONAL_STARTTLS 					string = "STARTTLS/OPTIONAL"
	SMTP_SSL_TLS 								string = "SSL"
	SMTP_NO_TLS_NO_SSL 							string = "NOTLS/NOSSL"

	MAIL_ENCODING_B64  							string = "B64"
	MAIL_ENCODING_QP   							string = "QP"
	MAIL_ENCODING_8BIT 							string = "8BIT"
	MAIL_ENCODING_7BIT 							string = "7BIT" // this is emulated, will use 8bit but will deaccent all characters

	MIME_COMPOSER_EPILOGUE_HEADER_KEY_PREFIX 	string = mailer.PrefixEpilogue

	MIME_COMPOSER_DEFAULT_ALT_BODY_TEXT 		string = "This is a MIME Message in HTML Format."

	ED25519_DNS_RAW_KEY_LEN 					 uint8 =  32 // raw
	ED25519_DNS_KEY_LEN 						 uint8 =  44 // signify

	ECDSA_P256_DNS_KEY_LEN 						 uint8 = 124 // asn1
	ECDSA_P384_DNS_KEY_LEN 						 uint8 = 160 // asn1
	ECDSA_P521_DNS_KEY_LEN 						 uint8 = 212 // asn1

	SEAL_DKIM_EMULATED_DOMAIN 					string = "smartgo.mime-message.seal.local"
	SEAL_DKIM_EMULATED_SELECTOR 				string = "ecdsa-p521-dk-seal"
	SEAL_DKIM_CANONIZATION 						string = "smart.dk.rlx"
	SEAL_DKIM_CHAIN_CHECKSUM_EMPTY 				string = "[CHAIN.CHECKSUM:N/A]"
	SEAL_PUBKEY_NOT_VALIDATED_HINT 				string = "ACKNOWLEDGE: The Seal EcDSA Public Key provided in this Mime Message was NOT (yet) Verified if it really belongs to the Author / Sender of this Mime Message. Only the Seal Signature was Verified if matches with the Public Key provided in this Mime Message. In case that the Public Key does not belong to the Author / Sender of this Mime Message the Seal would be invalid."
	SEAL_PUBKEY_NOT_VALIDATED_TODO 				string = "TODO: YOU NEED TO DO ONE MORE STEP, VERIFY IF THIS PUBLIC KEY BELONGS TO THE AUTHOR / SENDER OF THIS MIME MESSAGE, and if so, Seal is Validated OK, otherwise is NOT OK, as would be a case of fake signature impersonation ..."
)


//-----

var SmtpAllowedPorts []uint16 = []uint16{ // this can be redefined at the app level if not appropriate, but mostly these are all the well known SMTP Ports
	   25, // standard
	  465, // standard SSL
	  587, // standard STARTTLS
	 1025, // SMTP DEBUG playground
	 2525, // alternative proxy
	10025, // alternative relay
	10465, // alternative relay SSL
	10587, // alternative relay STARTTLS
}

//-----


type SmtpConfig struct {
	DkimSgnOpts 	*dkim.SignOptions 				// DKIM Sign Options or Null ; if non-Null is used to sign the message using the DKIM algorithm
	DkimVfyOpts 	*dkim.VerifyOptions 			// DKIM Verify Options or Null ; if non-Null is used to verify the signed message before sending using the DKIM algorithm
	MimeEpilogueFn 	mailer.MessageXtraEpilogueFn 	// null or a custom method to append to the mime message epilogue part ...
	MxDomain 		string 							// the base domain name, ex: unix-world.org, used for HELO/EHLO validation
	Host 			string 							// smtp host name, ex: mail.unix-world.org
	Port 			uint16 							// smtp port, ex: 25 | 587 (STARTTLS) | 465 (SSL)
	TlsMode 		string 							// SSL | STARTTLS | STARTTLS/OPTIONAL | NOTLS/NOSSL
	TimeoutSec 		uint8 							// smtp dial (connect) timeout ; the amount of time the function waits for a connection to be accepted ; includes also the DNS resolution
	AuthType 		string 							// NONE | CRAM-MD5 | LOGIN | PLAIN | XOAUTH2 | OAUTHBEARER ; except NONE | CRAM-MD5, all the rest require SSL | STARTTLS
	AuthUser 		string 							// the SMTP Auth UserName if any, or blank
	AuthPass 		string 							// the SMTP Auth Password | Token (XOAUTH2, OAUTHBEARER) if any, or blank
}

type MimeSendMessageStruct struct {
	DkimPubKeyB64 	string 							// if set must be the DNS Public Key (B64) ; !!! DO NOT SET HERE THE PRIVATE KEY BY MISTAKE !!!)
	FromName 		string 							// ex: `John Doe`
	FromAddress 	string 							// ex: `john@doe`
	ToAddresses 	[]string 						// ex: `jane@doe`
	CcAddresses 	[]string 						// ex: `copy@doe`
	BccAddresses 	[]string 						// ex: `extra@doe`
	Subject 		string 							// ex: `Hello World`
	Body 			string 							// ex: `<h1>This is a html message</h1>` | `can be also text if AltBody is empty`
	AltBody 		string 							// ex: `This is a text message` ; set it just if Body is HTML, having 2 text bodies is non-compliant, otherwise leave it blank
	IsHtml 			bool 							// set it to true if the Body is HTML
	Embedds 		map[string]string 				// the list of images as CIDs related to the Html Body | or empty
	Attachments 	map[string]string 				// list of the files attached to the message | empty
	MainEncodingQp 	bool 							// if set to TRUE will use the QP encoding for head and the main body
	Encoding 		string 							// B64 (base 64) | QP (quoted-printable) | 8BIT (unicode) | 7BIT (ISO)
}


//-----


var smtpDefaultConfig *SmtpConfig = nil


//-----


func SmtpSetDefaultConfig(dkimOpts *dkim.SignOptions, dkimVfyOpts *dkim.VerifyOptions, epilogueFn mailer.MessageXtraEpilogueFn, mxDomain string, timeOutSec uint8, host string, port uint16, tlsMode string, authType string, authUser string, authPass string) error {
	//--
	if(smtpDefaultConfig != nil) {
		return NewError("SMTP Default Config is already set") // allow to be set just once
	} //end if
	//--
	if(mxDomain == "") {
		return NewError("SMTP Default Config: MxDomain is empty")
	} //end if
	if(host == "") {
		return NewError("SMTP Default Config: Host is empty")
	} //end if
	if(port <= 0) {
		return NewError("SMTP Default Config: Port is zero")
	} //end if
	//--
	smtpDefaultConfig = &SmtpConfig{
		DkimSgnOpts: dkimOpts,
		DkimVfyOpts: dkimVfyOpts,
		MimeEpilogueFn: epilogueFn,
		MxDomain: mxDomain,
		Host: host,
		Port: port,
		TlsMode: tlsMode,
		TimeoutSec: timeOutSec,
		AuthType: authType,
		AuthUser: authUser,
		AuthPass: authPass,
	}
	//--
	return nil
	//--
} //END FUNCTION


func SmtpGetDefaultConfig() *SmtpConfig {
	//--
	return smtpDefaultConfig
	//--
} //END FUNCTION


func DkimGenerateDnsTxtRecord(typ, pemPubKeyB64 string) (string, error) {
	//--
	defer PanicHandler()
	//--
	typ = StrToLower(StrTrimWhitespaces(typ))
	//--
	pemPubKeyB64 = StrTrimWhitespaces(pemPubKeyB64)
	if(pemPubKeyB64 == "") {
		return "", NewError("B64 Public Key is Empty")
	} //end if
	//--
	var dnsTyp string = ""
	switch(typ) {
		case "ecdsa256":
			dnsTyp = typ
			if(len(pemPubKeyB64) != int(ECDSA_P256_DNS_KEY_LEN)) {
				return "", NewError("B64 Public Key has an Invalid Length, expects EcDSA/P256 ASN1 B64 Public Key (124 bytes)")
			} //end if
			break
		case "ecdsa384":
			dnsTyp = typ
			if(len(pemPubKeyB64) != int(ECDSA_P384_DNS_KEY_LEN)) {
				return "", NewError("B64 Public Key has an Invalid Length, expects EcDSA/P384 ASN1 B64 Public Key (160 bytes)")
			} //end if
			break
		case "ecdsa521":
			dnsTyp = typ
			if(len(pemPubKeyB64) != int(ECDSA_P521_DNS_KEY_LEN)) {
				return "", NewError("B64 Public Key has an Invalid Length, expects EcDSA/P521 ASN1 B64 Public Key (212 bytes)")
			} //end if
			break
	/*	case "ed25519": // ed25519, EdDSA ... TO BE DONE
			dnsTyp = "ed25519"
			if(len(pemPubKeyB64) != int(ED25519_DNS_RAW_KEY_LEN)) {
				return "", NewError("B64 Public Key has an Invalid Length, expects EdDSA/Ed25519 Raw B64 Public Key (32 bytes)")
			} //end if
			break */
		case "signify.ed25519": // ed25519, Signify
			dnsTyp = "ed25519"
			if(len(pemPubKeyB64) != int(ED25519_DNS_KEY_LEN)) {
				return "", NewError("B64 Public Key has an Invalid Length, expects Signify/Ed25519 B64 Public Key (44 bytes)")
			} //end if
			break
		default:
			return "", NewError("Invalid Key Type: " + typ)
	} //end switch
	//--
	return dkim.CreateTxtDkimRecord(pemPubKeyB64, dnsTyp)
	//--
} //END FUNCTION


func DkimPubKeyConvertToDnsRecordKey(typ string, pemPubKey string) (string, error) {
	//--
	defer PanicHandler()
	//--
	typ = StrToLower(StrTrimWhitespaces(typ))
	//--
	pemPubKey = StrTrimWhitespaces(pemPubKey)
	if(pemPubKey == "") {
		return "", NewError("The PEM Public is Empty")
	} //end if
	//--
	var theRawKey []byte = nil
	switch(typ) {
		case "ecdsa256": fallthrough
		case "ecdsa384": fallthrough
		case "ecdsa521":
			pubKey, errPubKey := GetB64PublicKeyFromPem(pemPubKey)
			if(errPubKey != nil) {
				return "", errPubKey
			} //end if
			pubKey = StrTrimWhitespaces(pubKey)
			if(pubKey == "") {
				return "", NewError("EcDSA B64 Public Failed, Null")
			} //end if
			theRawKey = []byte(pubKey)
			break
		case "signify.ed25519": // ed25519, signify
			errPubKey, sigPubKey := SignifyParsePublicKey([]byte(pemPubKey))
			if(errPubKey != nil) {
				return "", errPubKey
			} //end if
			if(sigPubKey == nil) {
				return "", NewError("Signify Public Failed, Null")
			} //end if
			var eddsaRawKey []byte = sigPubKey.Bytes[:]
			if(len(eddsaRawKey) <= 0) {
				return "", NewError("EdDSA Public Failed, Null")
			} //end if
			eddsaRawKey = BytTrimWhitespaces(Base64BytEncode(sigPubKey.Bytes[:]))
			if(len(eddsaRawKey) <= 0) {
				return "", NewError("EdDSA B64 Public Failed, Null")
			} //end if
			theRawKey = eddsaRawKey
			break
		default:
			return "", NewError("Invalid Key Type: " + typ)
	} //end switch
	//--
	return string(theRawKey), nil
	//--
} //END FUNCTION


func DkimEmulateDnsKey(domain string, pubKey string, typ string) ([]string, error) {
	//--
	// get the raw public key from pem public key to be used with DNS ...
	// DNS example for current public key: `default._domainkey IN TXT "v=DKIM1; k=ed25519; p=eK1ljX35KL6mY9OZiSPqkm4CYbxhNhnLykTTv9PLn04="`
	// this method can also be used for sending email to emulate real DKIM domain query verify ...
	//--
	defer PanicHandler()
	//--
	var keys []string = []string{}
	//--
	domain = StrTrimWhitespaces(domain)
	if(domain == "") {
		return keys, NewError("Domain is Empty")
	} //end if
	pubKey = StrTrimWhitespaces(pubKey)
	if(pubKey == "") {
		return keys, NewError("Public Key is Empty")
	} //end if
	//--
	dnsPubKey, errPubKey := DkimPubKeyConvertToDnsRecordKey(typ, pubKey)
	if(errPubKey != nil) {
		return keys, errPubKey
	} //end if
	dnsPubKey = StrTrimWhitespaces(dnsPubKey)
	if(dnsPubKey == "") {
		return keys, NewError("Signify Public Failed, Empty")
	} //end if
	//--
	dnsTxtKey, errTxtKey := DkimGenerateDnsTxtRecord(typ, dnsPubKey)
	if(errTxtKey != nil) {
		return keys, NewError("DNS Txt Key Failed: " + errTxtKey.Error())
	} //end if
	dnsTxtKey = StrTrimWhitespaces(dnsTxtKey)
	if(dnsTxtKey == "") {
		return keys, NewError("DNS Txt Key Failed, Empty")
	} //end if
	//--
	keys = append(keys, dnsTxtKey)
	//--
	return keys, nil
	//--
} //END FUNCTION


func DkimSignPrivKeyPass(emailAddr string, emailPass string) ([]byte, error) {
	//--
	defer PanicHandler()
	//--
	const algo string = "sha3-512"
	//--
	emailAddr = StrToLower(StrTrimWhitespaces(emailAddr))
	if(emailAddr == "") {
		return nil, NewError("eMail Address is Empty")
	} //end if
	if(validatemailaddr.IsValid(emailAddr) != true) {
		return nil, NewError("eMail Address is Invalid")
	} //end if
	if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, emailAddr)) {
		return nil, NewError("eMail Address is Not Safe Valid")
	} //end if
	//--
	signifyPass, errHmac := HashHmac(algo, emailAddr, emailPass, true) // B64, allow just higher algos (384/512) on the algo will return 64..88 ± 12 chars
	if(errHmac != nil) {
		return nil, NewError("HMac hash failed: " + errHmac.Error())
	} //end if
	//--
	var bytPass []byte = []byte(Base64ToBase64s(signifyPass))
	if((len(bytPass) < 52) || (len(bytPass) > 100)) {
		return nil, NewError("Hash length is Invalid, try a different algo")
	} //end if
	//--
	return bytPass, nil
	//--
} //END FUNCTION


func DkimGetDefaultVerifyOptions(maxNumSignaturesToVerify int8, dkVerifyFn dkim.TxtLookupFunc) (*dkim.VerifyOptions, error) {
	//--
	if(maxNumSignaturesToVerify < 0) {
		return nil, NewError("Max Num Verifications is Negative")
	} //end if
	//--
	dkimVfyOpts := dkim.VerifyOptions{
		MaxVerifications: int(maxNumSignaturesToVerify),
		LookupTXT: dkVerifyFn,
	}
	//--
	return &dkimVfyOpts, nil
	//--
} //END FUNCTION


func DkimGetDefaultOptions(domain string, selector string, hashAlgo string, sigAlgo string, pemPrivKey []byte, passPrivKey []byte, canonModeHead string, canonModeBody string) (*dkim.SignOptions, error) {
	//--
	defer PanicHandler()
	//--
	domain = StrToLower(StrTrimWhitespaces(domain))
	if(domain == "") {
		return nil, nil // no error, means no sign !
	} //end if
	//--
	selector = StrToLower(StrTrimWhitespaces(selector))
	if(selector == "") {
		return nil, nil // no error, means no sign !
	} //end if
	//--
	pemPrivKey = BytTrimWhitespaces(pemPrivKey)
	if(len(pemPrivKey) <= 0) {
		return nil, nil // no error, means no sign !
	} //end if
	var privKey crypto.Signer
	switch(sigAlgo) {
		case "ecdsa256": fallthrough
		case "ecdsa384": fallthrough
		case "ecdsa521":
			errPrivRawKey, b64PrivKey := DecryptPrivateKeyPEM(string(pemPrivKey), string(passPrivKey), false) // as B64 (not PEM)
			if(errPrivRawKey != nil) {
				return nil, NewError("Extract B64 PrivateKey from PEM PrivateKey failed: " + errPrivRawKey.Error())
			} //end if
			b64PrivKey = StrTrimWhitespaces(b64PrivKey)
			if(b64PrivKey == "") {
				return nil, NewError("Extract B64 PrivateKey from PEM PrivateKey failed, Empty")
			} //end if
			rawPrivKey := Base64Decode(b64PrivKey)
			if(StrTrimWhitespaces(rawPrivKey) == "") {
				return nil, NewError("Extract Raw PrivateKey from PEM PrivateKey failed, Empty")
			} //end if
			typ, privRealKey, errPKCS8 := ParseX509PrivateEcdsaKey([]byte(rawPrivKey))
			if(errPKCS8 != nil) {
				return nil, NewError("Failed to parse Raw PrivateKey: " + errPKCS8.Error())
			} //end if
			if(privRealKey == nil) {
				return nil, NewError("Failed to parse Raw PrivateKey, is Null")
			} //end if
			if(StrToLower(StrTrimWhitespaces(typ)) != "ecdsa.priv") {
				return nil, NewError("Invalid Private Key Type: " + typ)
			} //end if
			privKey = privRealKey
		case "signify.ed25519": // ed25519, signify
			errParsePrivKey, thePrivKey, thePubKey := SignifyGetPrivateKey(pemPrivKey, passPrivKey)
			if(errParsePrivKey != nil) {
				return nil, NewError("Private Key Parse Error: " + errParsePrivKey.Error())
			} //end if
			if(thePrivKey == nil) {
				return nil, NewError("Private Key is Null")
			} //end if
			if(thePubKey == nil) {
				return nil, NewError("Public Key is Null")
			} //end if
			privKey = thePrivKey
			break
		default:
			return nil, NewError("Invalid Signature Algo: " + sigAlgo)
	} //end switch
	//--
	var hash crypto.Hash = crypto.SHA256 // default
	hashAlgo = StrToLower(StrTrimWhitespaces(hashAlgo))
	if(hashAlgo == "") {
		hashAlgo = "sha256" // default
	} //end if
	switch(hashAlgo) {
		case "sha3-512":
			hash = crypto.SHA3_512
			break
		case "sha3-384":
			hash = crypto.SHA3_384
			break
		case "sha3-256":
			hash = crypto.SHA3_256
			break
		case "sha3-224":
			hash = crypto.SHA3_224
			break
		//--
		case "sha512":
			hash = crypto.SHA512
			break
		case "sha384":
			hash = crypto.SHA384
			break
		case "sha256":
			hash = crypto.SHA256
			break
		case "sha224":
			hash = crypto.SHA224
			break
		default:
			return nil, NewError("Invalid Hash Algo: " + hashAlgo)
	} //end switch
	//--
	var headCanonicalization dkim.Canonicalization
	var bodyCanonicalization dkim.Canonicalization
	//--
	canonModeHead = StrToLower(StrTrimWhitespaces(canonModeHead))
	switch(canonModeHead) {
		case "simple":
			headCanonicalization = dkim.CanonicalizationSimple
			break
		case "relaxed": fallthrough
		case "": // default is relaxed
			headCanonicalization = dkim.CanonicalizationRelaxed
			break
		default:
			return nil, NewError("Invalid Head Canonicalization: " + canonModeHead)
	} //end switch
	//--
	canonModeBody = StrToLower(StrTrimWhitespaces(canonModeBody))
	switch(canonModeBody) {
		case "simple":
			bodyCanonicalization = dkim.CanonicalizationSimple
			break
		case "relaxed": fallthrough
		case "": // default is relaxed
			bodyCanonicalization = dkim.CanonicalizationRelaxed
			break
		default:
			return nil, NewError("Invalid Body Canonicalization: " + canonModeBody)
	} //end switch
	//--
	dkimOpts := dkim.SignOptions{
		Domain: 				domain,
		Selector: 				selector,
		Signer: 				privKey,
		Hash: 					hash,
		HeaderCanonicalization: headCanonicalization,
		BodyCanonicalization: 	bodyCanonicalization,
	}
	//--
	return &dkimOpts, nil
	//--
} //END FUNCTION


//-----


func SendSmtpEmail(smtpConf SmtpConfig, mimeMsgStruct MimeSendMessageStruct) ([]mailer.MimeSentMessage, error) {
	//--
	defer PanicHandler()
	//-- smtp mx domain
	smtpConf.MxDomain = StrTrimWhitespaces(smtpConf.MxDomain)
	if(smtpConf.MxDomain == "") {
		return nil, NewError("SMTP MxDomain is Empty, it should be set to the advertised host name of the SMTP server")
	} //end if
	if(len(smtpConf.MxDomain) > MAX_HOSTNAME_SEGMENT_LENGTH) { // allow just 63 characters here, for safety ...
		return nil, NewError("SMTP MxDomain is Too Long")
	} //end if
	if(!IsNetValidHostName(smtpConf.MxDomain)) {
		return nil, NewError("SMTP MxDomain is Invalid as a HostName")
	} //end if
	//-- smtp host
	smtpConf.Host = StrTrimWhitespaces(smtpConf.Host)
	if(smtpConf.Host == "") {
		return nil, NewError("SMTP Host is Empty")
	} //end if
	if((!IsNetValidHostName(smtpConf.Host)) && (!IsNetValidIpAddr(smtpConf.Host))) { // can be hostname or ip
		return nil, NewError("SMTP Host should be either a valid HostName or an IPv4/IPv6 Address")
	} //end if
	//-- smtp port
	if(!InListArr(smtpConf.Port, SmtpAllowedPorts)) {
		return nil, NewError("SMTP Port [" + ConvertUInt16ToStr(smtpConf.Port) + "] is Disallowed by the list of SmtpAllowedPorts: " + ObjectToString(SmtpAllowedPorts))
	} //end if
	//-- smtp tls mode
	smtpConf.TlsMode = StrToUpper(StrTrimWhitespaces(smtpConf.TlsMode))
	switch(smtpConf.TlsMode) {
		case SMTP_SSL_TLS: 					fallthrough
		case SMTP_TLS_STARTTLS: 			fallthrough
		case SMTP_TLS_OPTIONAL_STARTTLS: 	fallthrough
		case SMTP_NO_TLS_NO_SSL:
			break
		default:
			return nil, NewError("SMTP TLS Policy is Invalid: `" + smtpConf.TlsMode + "` ; accepted values are: `NONE`, `SSL`, `STARTTLS` and `STARTTLS/OPTIONAL`")
	} //end switch
	//-- smtp auth type
	smtpConf.AuthType = StrToUpper(StrTrimWhitespaces(smtpConf.AuthType))
	smtpConf.AuthUser = StrTrimWhitespaces(smtpConf.AuthUser)
	smtpConf.AuthPass = smtpConf.AuthPass // do not trim
	switch(smtpConf.AuthType) {
		case SMTP_AUTH_OAUTHBEARER: fallthrough
		case SMTP_AUTH_XOAUTH2: 	fallthrough
		case SMTP_AUTH_PLAIN: 		fallthrough
		case SMTP_AUTH_LOGIN: 		fallthrough
		case SMTP_AUTH_CRAMMD5: // this is the only one that is supported over non-encrypted connection
			if(smtpConf.AuthUser == "") {
				return nil, NewError("SMTP Auth User is Empty, but Authentication Type has been set to `" + smtpConf.AuthType + "`")
			} //end if
			if(len(smtpConf.AuthUser) > 127) { // allow: 63 + 1 + 63 as in the REGEX_SMART_SAFE_EMAIL_ADDRESS regex limits
				return nil, NewError("SMTP Auth User is too long")
			} //end if
			if(!StrRegexMatch(REGEX_SMART_SAFE_NET_USERNAME, smtpConf.AuthUser)) {
				return nil, NewError("SMTP Auth User contains invalid characters")
			} //end if
			if(StrTrimWhitespaces(smtpConf.AuthPass) == "") {
				return nil, NewError("SMTP Auth Password or Token is Empty or consists of only space characters, but Authentication Type has been set to `" + smtpConf.AuthType + "`")
			} //end if
			if((smtpConf.AuthType == SMTP_AUTH_OAUTHBEARER) || (smtpConf.AuthType == SMTP_AUTH_XOAUTH2)) {
				if(len(smtpConf.AuthPass) > 4096) { // allow 4096 because the OAUTHBEARER or XOAUTH2 can use very long tokens, otherwise passwords are much shorter
					return nil, NewError("SMTP Auth Token is too long for the selected Authentication Type: `" + smtpConf.AuthType + "`")
				} //end if
			} else {
				if(len(smtpConf.AuthPass) > 255) {
					return nil, NewError("SMTP Auth Password is too long for the selected Authentication Type: `" + smtpConf.AuthType + "`")
				} //end if
			} //end if else
			if(smtpConf.AuthType != SMTP_AUTH_CRAMMD5) {
				if((smtpConf.TlsMode != SMTP_SSL_TLS) && (smtpConf.TlsMode != SMTP_TLS_STARTTLS)) {
					return nil, NewError("The selected SMTP Auth method requires SSL or STARTTLS but the connection mode is set to: `" + smtpConf.TlsMode + "`")
				} //end if
			} //end if
			break
		case SMTP_AUTH_NONE:
			if((smtpConf.AuthUser != "") || (smtpConf.AuthPass != "")) {
				return nil, NewError("SMTP Auth User is Not Empty or Auth Pass is Not Empty, but Authentication Type has been set to `NONE`")
			} //end if
			break
		default:
			return nil, NewError("SMTP Auth Type is Invalid: `" + smtpConf.AuthType + "` ; accepted values are: `NONE`, `LOGIN`, `PLAIN`, `CRAM-MD5` and `XOAUTH2`")
	} //end switch
	//--
	msg, errMsg := composeMimeMessage(mimeMsgStruct)
	if(errMsg != nil) {
		return nil, errMsg
	} //end if
	if(msg == nil) {
		return nil, NewError("Message is Null")
	} //end if
	//--
	var tlsPolicy mailer.StartTLSPolicy = mailer.NoStartTLS
	var isSslPolicy bool = false
	// mailer.MandatoryStartTLS
	switch(smtpConf.TlsMode) {
		case SMTP_SSL_TLS:
			isSslPolicy = true
			break;
		case SMTP_TLS_STARTTLS:
			tlsPolicy = mailer.MandatoryStartTLS
			break
		case SMTP_TLS_OPTIONAL_STARTTLS:
			tlsPolicy = mailer.OpportunisticStartTLS
			break
		case SMTP_NO_TLS_NO_SSL: fallthrough
		default:
			// use no TLS, no SSL
	} //end switch
	//--
	if((smtpConf.TimeoutSec < mailer.MinTimeOutSeconds) || (smtpConf.TimeoutSec > mailer.MaxTimeOutSeconds)) {
		smtpConf.TimeoutSec = mailer.DefaultTimeOutSeconds
	} //end if else
	//--
	const retryFailure bool = true
	d, errD := mailer.NewDialer(smtpConf.DkimSgnOpts, smtpConf.DkimVfyOpts, smtpConf.MimeEpilogueFn, smtpConf.MxDomain, smtpConf.TimeoutSec, smtpConf.Host, smtpConf.Port, retryFailure, smtpConf.AuthType, smtpConf.AuthUser, smtpConf.AuthPass, isSslPolicy, tlsPolicy)
	if(errD != nil) {
		return nil, errD
	} //end if
	if(d == nil) {
		return nil, NewError("SMTP Dialer is Null")
	} //end if
	//--
	sendErr := d.DialAndSend(msg)
	//--
	return d.SentMessages, sendErr
	//--
} //END FUNCTION


//-----


func CreateMimeMessageSignSealComposerFn(senderEmail string, senderPass string, ecdsaPemPrivKey string, ecdsaPemPubKey string, ecdsaPemCert string) mailer.MessageXtraEpilogueFn {
	//--
	defer PanicHandler()
	//--
	var msgXtraEpilogueFn mailer.MessageXtraEpilogueFn = func(bytMsg []byte, chainChecksum string) (map[string]string, error) {
		//--
		defer PanicHandler()
		//--
		sealKey, sealVal, errSeal := CreateMimeMessageSignSeal(bytMsg, chainChecksum, senderEmail, senderPass, ecdsaPemPrivKey, ecdsaPemPubKey, ecdsaPemCert)
		if(errSeal != nil) {
			return nil, NewError("Xtra Epilogue Sign Failed: " + errSeal.Error())
		} //end if
		sealKey = StrTrimWhitespaces(sealKey)
		if(sealKey == "") {
			return nil, NewError("Xtra Epilogue Sign Failed: Key is Empty")
		} //end if
		sealVal = StrTrimWhitespaces(sealVal)
		if(sealVal == "") {
			return nil, NewError("Xtra Epilogue Sign Failed: Value is Empty")
		} //end if
		//--
		arr := map[string]string{
			sealKey: sealVal,
		}
		//--
		return arr, nil
		//--
	} //end fn
	//--
	return msgXtraEpilogueFn
	//--
} //END FUNCTION


func VerifyMimeMessageSignSealParserFn(ecdsaPemPubKey string) MessageXtraEpilogueVerifyFn {
	//--
	defer PanicHandler()
	//--
	var msgXtraEpilogueVerifyFn MessageXtraEpilogueVerifyFn = func(bytMsg []byte, hdr MimeHeader, senderEmail string) (string, error) {
		//--
		defer PanicHandler()
		//--
		if(MIME_DEBUG == true) {
			if(ecdsaPemPubKey != "") {
				log.Println("[DEBUG]", CurrentFunctionName(), "Verifying Sign Seal from the Message Xtra Epilogue for Author, with the email address:", senderEmail, "with PEM Public Key:", ecdsaPemPubKey)
			} else {
				log.Println("[DEBUG]", CurrentFunctionName(), "Verifying Sign Seal from the Message Xtra Epilogue for Author, with the email address:", senderEmail, "using the PEM Public Key embedded in the message")
			} //end if else
		} //end if
		//--
		sealData, errVfySeal := VerifyMimeMessageSignSeal(bytMsg, hdr, senderEmail, ecdsaPemPubKey)
		var sealJsonData string = JsonNoErrChkEncode(sealData, true, false) // prettyprint, no htmlsafe
		if(errVfySeal != nil) {
			return sealJsonData, NewError("Xtra Epilogue Sign Verify Failed: " + errVfySeal.Error())
		} //end if
		//--
		return sealJsonData, nil
		//--
	} //end fn
	//--
	return msgXtraEpilogueVerifyFn
	//--
} //END FUNCTION


//-----


func CreateMimeMessageSignSeal(bytMsg []byte, chainChecksum string, senderEmail string, senderPass string, ecdsaPemPrivKey string, ecdsaPemPubKey string, ecdsaPemCert string) (string, string, error) {
	//--
	defer PanicHandler()
	//--
	var sealKey string = StrTrimWhitespaces(ConformHeaderKeyName(MIME_MESSAGE_UXM_SEAL_KEY))
	if(sealKey == "") {
		return "", "", NewError("Internal Error, Seal Key is Empty")
	} //end if
	//--
	if(len(bytMsg) <= 0) {
		return sealKey, "", NewError("Message Data is Empty")
	} //end if
	if(uint64(len(bytMsg)) > MIME_MESSAGE_MAX_SIZE_PARSE) { // check this before check if empty to avoid trim on very large string
		return sealKey, "", NewError("Message is OverSized, limit is 128MB")
	} //end if
	//--
	senderEmail = StrToLower(StrTrimWhitespaces(senderEmail))
	if(senderEmail == "") {
		return sealKey, "", NewError("Sender Email Address is Empty")
	} //end if
	if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, senderEmail)) {
		return sealKey, "", NewError("Sender Email Address is Invalid")
	} //end if
	//--
	if(StrTrimWhitespaces(senderPass) == "") {
		return sealKey, "", NewError("Sender Email Password is Empty")
	} //end if
	//--
	signifyPass, errSigPass := DkimSignPrivKeyPass(senderEmail, senderPass)
	if(errSigPass != nil) {
		return sealKey, "", NewError("SignSeal Failed, Pass Error: " + errSigPass.Error())
	} //end if
	if(len(signifyPass) <= 0) {
		return sealKey, "", NewError("SignifyPass is Empty or Null")
	} //end if
	//--
	ecdsaPemPrivKey = StrTrimWhitespaces(ecdsaPemPrivKey)
	if(ecdsaPemPrivKey == "") {
		return sealKey, "", NewError("EcDSA PEM Private Key is Empty")
	} //end if
	//--
	ecdsaPemPubKey = StrTrimWhitespaces(ecdsaPemPubKey)
	if(ecdsaPemPubKey == "") {
		return sealKey, "", NewError("EcDSA PEM Public Key is Empty")
	} //end if
	ecdsaPemCert = StrTrimWhitespaces(ecdsaPemCert)
	if(ecdsaPemCert == "") {
		return sealKey, "", NewError("EcDSA PEM Certificate is Empty")
	} //end if
	//--
	b64PubKey, errB64PubKey := GetB64PublicKeyFromPem(ecdsaPemPubKey)
	if(errB64PubKey != nil) {
		return sealKey, "", NewError("EcDSA PEM Public Failed to extract B64 Part: " + errB64PubKey.Error())
	} //end if
	b64PubKey = StrTrimWhitespaces(b64PubKey)
	if(b64PubKey == "") {
		return sealKey, "", NewError("EcDSA PEM Public Failed to extract B64 Part, Empty")
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_B64_STR, b64PubKey)) {
		return sealKey, "", NewError("EcDSA PEM Public Failed to extract B64 Part, contains illegal characters")
	} //end if
	//--
	dkimOpts, errDkimOpts := DkimGetDefaultOptions(SEAL_DKIM_EMULATED_DOMAIN, SEAL_DKIM_EMULATED_SELECTOR, "sha3-512", "ecdsa521", []byte(ecdsaPemPrivKey), signifyPass, "relaxed", "relaxed")
	if(errDkimOpts != nil) {
		return sealKey, "", NewError("EcDSA DKIM Options Sign Seal Failed: " + errDkimOpts.Error())
	} //end if
	if(dkimOpts == nil) {
		return sealKey, "", NewError("EcDSA DKIM Options Sign Seal Failed, Null")
	} //end if
	dkimSignature, errDkimSignature := dkim.SignMimeMessage(dkimOpts, bytMsg)
	bytMsg = nil // free mem
	if(errDkimSignature != nil) {
		return sealKey, "", NewError("EcDSA DKIM Sign Seal Failed: " + errDkimSignature.Error())
	} //end if
	if(dkimSignature == "") {
		return sealKey, "", NewError("EcDSA DKIM Sign Seal Failed, Empty")
	} //end if
	dkimSignature = StrTrimWhitespaces(canonizeSmartDkimSealSignature(dkimSignature))
	if(dkimSignature == "") {
		return sealKey, "", NewError("EcDSA DKIM Sign Seal Failed, Empty after Smart Canonization")
	} //end if
	var dkimB64Signature string = StrTrimWhitespaces(Base64sEncode(dkimSignature))
	if(dkimB64Signature == "") {
		return sealKey, "", NewError("EcDSA DKIM Sign Seal Failed, Empty after B64s Encoding")
	} //end if
	//--
	chainChecksum = StrTrimWhitespaces(chainChecksum)
	if(chainChecksum != "") {
		if(!StrRegexMatch(REGEX_SAFE_B64_STR, chainChecksum)) {
			return sealKey, "", NewError("Chain Checksum is Not in Base64 Format .. this is optional but if supplied must be B64 SHA-384")
		} //end if
	} //end if
	if(chainChecksum == "") {
		chainChecksum = SEAL_DKIM_CHAIN_CHECKSUM_EMPTY
	} //end if
	//--
	var theTimeNowUnix string = ConvertInt64ToStr(TimeNowUnix())
	//--
	var signBytData []byte = []byte(StrToLower(DESCRIPTION + " " + VERSION) + "\n" + StrToLower(MIME_MESSAGE_UXM_SEAL_TYPE) + "\n" + "v.1" + "\n" + StrToLower(SEAL_DKIM_CANONIZATION) + "\n" + senderEmail + "\n" + dkimSignature + "\n" + theTimeNowUnix + "\n" + chainChecksum)
	//-- it will sign the DKIM Signature NOT the Message, as the DKIM signature is relaxed and can handle message slight changes (by ex: gmail is moving subject from the place at the end of header ...)
	errSign, strB64Sign := SignWithX509PrivateKeyPEM("EcDSA", ecdsaPemPrivKey, string(signifyPass), ecdsaPemPubKey, signBytData, "sha3-512", true) // asn1
	if(errSign != nil) {
		return sealKey, "", NewError("SignSeal EcDSA.Sign Failed: " + errSign.Error())
	} //end if else
	//--
	errVfy := VerifySignedWithX509PublicKeyPEM("EcDSA", ecdsaPemPubKey, signBytData, strB64Sign, "sha3-512", true) // asn1
	if(errVfy != nil) {
		return sealKey, "", NewError("SignSeal EcDSA.VerifySign Failed: " + errVfy.Error())
	} //end if
	//--
	return sealKey, MIME_MESSAGE_UXM_SEAL_TYPE + "; v=1; c=" + SEAL_DKIM_CANONIZATION + ";" + "\n" + `a="` + senderEmail + `";` + "\n" + StrTrimWhitespaces(StrChunkSplit(`k="` + dkimB64Signature, 75, "\n")) + `";` + "\n" + StrTrimWhitespaces(StrChunkSplit(`s="` + strB64Sign, 75, "\n")) + `";` + "\n" + StrTrimWhitespaces(StrChunkSplit(`p="` + b64PubKey, 75, "\n")) + `";` + "\n" + "l=" + ConvertIntToStr(len(dkimSignature)) + "; d=" + theTimeNowUnix + `; m="` + DESCRIPTION + " " + VERSION + `"`, nil
	//--
} //END FUNCTION


func canonizeSmartDkimSealSignature(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = StrNormalizeSpaces(s)
	s = StrTrimWhitespaces(s)
	s = StrReplaceAll(s, " ", "")
	//--
	s = StrReplaceWithLimit(s, ":", ": ", 1) // required to have `: `
	s = StrReplaceAll(s, ";", "; ") // required to have `; `
	//--
	return StrTrimWhitespaces(s)
	//--
} //END FUNCTION


type MimeSeal struct {
	ReportType 						string 					`json:"reportType"`

	MessageMimeVersion 				string 					`json:"messageMimeVersion"`
	MessageContentType 				string 					`json:"messageContentType"`
	MessageId 						string 					`json:"messageId"`
	MessageDateTime 				string 					`json:"messageDateTime"`
	MessageSubject 					string 					`json:"messageSubject"`
	MessageFromAddr 				[]MimeAddress 			`json:"messageFromAddr"`
	MessageToAddr 					[]MimeAddress 			`json:"messageToAddr"`
	MessageCcAddr 					[]MimeAddress 			`json:"messageCcAddr"`
	MessageBccAddr 					[]MimeAddress 			`json:"messageBccAddr"`
	MessageNumParts 				uint64 					`json:"messageNumParts"`
	MessageNumAttachments 			uint64 					`json:"messageNumAttachments"`
	MessageNumEmbedds 				uint64 					`json:"messageNumEmbedds"`
	MessageNumEmbeddTextParts 		uint64 					`json:"messageNumEmbeddTextParts"`
	MessageNumEmbeddHtmlParts 		uint64 					`json:"messageNumEmbeddHtmlParts"`
	MessageNumWarnings 				uint64 					`json:"messageNumWarnings"`
	MessageNumErrors 				uint64 					`json:"messageNumErrors"`
	MessageEpilogueVerifyOK 		bool 					`json:"messageEpilogueVerifyOK"`
	MessageDKIMSigned 				bool 					`json:"messageDKIMSigned"`
	MessageDKIMCustomVerifier 		bool 					`json:"messageDKIMCustomVerifier"`
	MessageDKIMVerifyOK 			bool 					`json:"messageDKIMVerifyOK"`
	MessageDKIMVerifications 		[]*dkim.Verification 	`json:"messageDKIMVerifications"`
	MessageDKIMSignature 			string 					`json:"messageDKIMSignature"`
	MessageDKIMPubKey 				string 					`json:"messageDKIMPubKey"`

	SealKey 						string 					`json:"sealKey"`
	SealFound 						bool 					`json:"sealFound"`
	SealMark 						string 					`json:"sealMark"`
	SealVersion 					string 					`json:"sealVersion"`
	SealContentType 				string 					`json:"sealContentType"`
	SealSenderEmail 				string 					`json:"senderEmail"`
	AuthorValidateEmail 			string 					`json:"authorValidateEmail"`
	EcDSAPubKeyValidated 			bool 					`json:"ecDSAPubKeyValidate"`
	EcDSAPubKey 					string 					`json:"ecDSAPubKey"`
	EcDSASignature 					string 					`json:"ecDSASignature"`
	CanonizeMethod 					string 					`json:"canonizeMethod"`
	UnixTime 						int64 					`json:"unixTime"`
	ChainCheckSumAlgo 				string 					`json:"chainCheckSumAlgo"`
	ChainCheckSum 					string 					`json:"chainCheckSum"`
	SealDkimSignatureLen 			int64 					`json:"sealDkimSignatureLen"`
	SealDkimSignature 				string 					`json:"sealDkimSignature"`
	SealDkimVerifyPassed 			bool 					`json:"sealDkimVerifyPassed"`
	SealDkimVerifyError 			error 					`json:"sealDkimVerifyError,omitempty"`
	SealDkimVerifications 			[]*dkim.Verification 	`json:"sealDkimVerifications,omitempty"`
	ErrSealVerifySign 				error 					`json:"errSealVerifySign,omitempty"`
	IsSealSignatureOK 				bool 					`json:"isSealSignatureOK"`
	IsSealValidOK 					bool 					`json:"isSealValidOK"` // if this is true everything is ok, all seal verifications passed
	SealValidationsSecurityNotes 	[]string 				`json:"sealValidationsSecurityNotes,omitempty"`
	SealVerifyDateTime 				string 					`json:"sealVerifyDateTime"`
}


func VerifyMimeMessageSignSeal(bytMsg []byte, hdr MimeHeader, senderEmail string, ecdsaPemPubKey string) (MimeSeal, error) {
	//--
	defer PanicHandler()
	//--
	var eplg MimeEpilogue = hdr.Epilogue
	//--
	ms := MimeSeal{
		ReportType: "SmartGo MimeMessage Seal Signature Report " + VERSION,
		MessageMimeVersion: hdr.MimeVersion,
		MessageContentType: hdr.ContentType,
		MessageId: hdr.MessageId,
		MessageDateTime: hdr.DateTime,
		MessageSubject: hdr.Subject,
		MessageFromAddr: hdr.From,
		MessageToAddr: hdr.To,
		MessageCcAddr: hdr.Cc,
		MessageBccAddr: hdr.Bcc,
		MessageNumParts: hdr.NumParts,
		MessageNumAttachments: hdr.NumAttachments,
		MessageNumEmbedds: hdr.NumEmbedds,
		MessageNumEmbeddTextParts: hdr.NumEmbeddTextParts,
		MessageNumEmbeddHtmlParts: hdr.NumEmbeddHtmlParts,
		MessageNumWarnings: hdr.NumWarnings,
		MessageNumErrors: hdr.NumErrors,
		MessageEpilogueVerifyOK: hdr.EpilogueVfyOK,
		MessageDKIMSigned: hdr.DKIMSigned,
		MessageDKIMCustomVerifier: hdr.DKIMCustomVerifier,
		MessageDKIMVerifyOK: hdr.DKIMVerifyOK,
		MessageDKIMVerifications: hdr.DKIMVerifications,
		MessageDKIMSignature: hdr.DKIMSignature,
		MessageDKIMPubKey: hdr.DKIMPubKey,
	}
	//--
	var sealKey string = StrTrimWhitespaces(ConformHeaderKeyName(mailer.PrefixEpilogue + MIME_MESSAGE_UXM_SEAL_KEY))
	if(sealKey == "") {
		return ms, NewError("Internal Error, Seal Key is Empty")
	} //end if
	ms.SealKey = sealKey
	//--
	if(len(bytMsg) <= 0) {
		return ms, NewError("Message Data is Empty")
	} //end if
	if(uint64(len(bytMsg)) > MIME_MESSAGE_MAX_SIZE_PARSE) { // check this before check if empty to avoid trim on very large string
		return ms, NewError("Message is OverSized, limit is 128MB")
	} //end if
	//--
	senderEmail = StrToLower(StrTrimWhitespaces(senderEmail))
	if(senderEmail == "") {
		return ms, NewError("Sender Email Address is Empty")
	} //end if
	if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, senderEmail)) {
		return ms, NewError("Sender Email Address is Invalid")
	} //end if
	ms.AuthorValidateEmail = senderEmail
	//--
	if(ecdsaPemPubKey != "") { // this is optional, if not provided will use the mime embedded public key
		ecdsaPemPubKey = StrTrimWhitespaces(ecdsaPemPubKey)
		if(ecdsaPemPubKey == "") {
			return ms, NewError("EcDSA PEM Public Key was provided as Non-Empty but contain only spaces")
		} //end if
	} //end if
	//--
	bytMsg = GetMimeMessageCleanContent(bytMsg)
	if(len(bytMsg) <= 0) {
		return ms, NewError("Failed to get the Clean Part, is Empty")
	} //end if
	//--
	arrDat := BExplodeWithLimit([]byte(sealKey + ":"), bytMsg, 2)
	if((len(arrDat) != 2) || (len(arrDat[0]) <= 0) || (len(arrDat[1]) <= 0)) {
		return ms, NewError("Failed to get the Clean Part Before Seal Key, is Empty")
	} //end if
	bytMsg = arrDat[0]
	arrDat = nil // free mem
	//--
	if(len(eplg.Values) <= 0) {
		return ms, NewError("Failed, No Xtra Values")
	} //end if
	//--
	epilogueSeals, okSeal := eplg.Values[StrToLower(sealKey)]
	if(!okSeal) {
		return ms, NewError("Failed, Xtra Values contain No Seals")
	} //end if
	ms.SealFound = true
	if(len(epilogueSeals) <= 0) {
		return ms, NewError("Failed, Xtra Values Seals List is Empty")
	} else if(len(epilogueSeals) > 1) {
		return ms, NewError("Failed, Xtra Values Seals List contain more than one value")
	} //end if else
	//--
	var epilogueSeal string = StrTrimWhitespaces(epilogueSeals[0])
	if(epilogueSeal == "") {
		return ms, NewError("Failed, Xtra Values Seal is Empty")
	} //end if
	//--
	cTyp, cParams, errParseSeal := ParseMediaTypeHeaderVal(epilogueSeal)
	cTyp = StrToLower(StrTrimWhitespaces(cTyp))
	if(cTyp != StrToLower(MIME_MESSAGE_UXM_SEAL_TYPE)) {
		return ms, NewError("Failed, Xtra Values Seal Type is Invalid: `" + cTyp + "`")
	} //end if
	if(errParseSeal != nil) {
		return ms, NewError("Failed, Seal parse Error: " + errParseSeal.Error())
	} //end if
	if(len(cParams) <= 0) {
		return ms, NewError("Failed, Seal Parameters List is Empty")
	} //end if
	ms.SealContentType = cTyp
	//--
	theVersion, okVersion := cParams["v"]
	if(!okVersion) {
		return ms, NewError("Failed, Seal Parameters List is Incomplete, Version is Missing")
	} //end if
	theVersion = StrTrimWhitespaces(theVersion)
	if(theVersion == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, Version is Empty")
	} //end if
	if(theVersion != "1") {
		return ms, NewError("Failed, Seal Parameters List MisMatch, Version is is Unsupported: `" + theVersion + "`")
	} //end if
	ms.SealVersion = theVersion
	//--
	b64PubKey, okB64PubKey := cParams["p"]
	if(!okB64PubKey) {
		return ms, NewError("Failed, Seal Parameters List is Incomplete, EcDSA B64 Public Key is Missing")
	} //end if
	b64PubKey = StrTrimWhitespaces(Base64NormalizeMultiLineData(b64PubKey))
	if(b64PubKey == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, EcDSA B64 Public Key is Empty")
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_B64_STR, b64PubKey)) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, EcDSA B64 Public Key contains Invalid Characters")
	} //end if
	ms.EcDSAPubKey = b64PubKey
	//--
	theCanM, okCanM := cParams["c"]
	if(!okCanM) {
		return ms, NewError("Failed, Seal Parameters List is Incomplete, Canonization Method is Missing")
	} //end if
	theCanM = StrToLower(StrTrimWhitespaces(theCanM))
	if(theCanM == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, Canonization Method is Empty")
	} //end if
	if(theCanM != StrToLower(SEAL_DKIM_CANONIZATION)) { // at the moment only the "dksmart" canonization is supported
		return ms, NewError("Failed, Seal Parameters List MisMatch, Canonization Method is Unsupported: `" + theCanM + "`")
	} //end if
	ms.CanonizeMethod = theCanM
	//--
	theEmail, okEml := cParams["a"]
	if(!okEml) {
		return ms, NewError("Failed, Seal Parameters List is Incomplete, Sender Email is Missing")
	} //end if
	theEmail = StrToLower(StrTrimWhitespaces(theEmail))
	if(theEmail == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, Sender Email is Empty")
	} //end if
	ms.SealSenderEmail = theEmail
	//--
	strB64DkimSgn, okB64DkimSgn := cParams["k"]
	if(!okB64DkimSgn) {
		return ms, NewError("Failed, Seal Parameters List is Incomplete, Base64s DKIM Data is Missing")
	} //end if
	strB64DkimSgn = StrTrimWhitespaces(Base64NormalizeMultiLineData(strB64DkimSgn))
	if(strB64DkimSgn == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, Base64s DKIM Data is Empty")
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_B64S_STR, strB64DkimSgn)) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, Base64s DKIM Data contains Invalid Characters")
	} //end if
	//--
	strB64Sign, okB64Sgn := cParams["s"]
	if(!okB64Sgn) {
		return ms, NewError("Failed, Seal Parameters List is Incomplete, Base64 Signature is Missing")
	} //end if
	strB64Sign = StrTrimWhitespaces(Base64NormalizeMultiLineData(strB64Sign))
	if(strB64Sign == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, Base64 Signature is Empty")
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_B64_STR, strB64Sign)) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, Base64 Signature contains Invalid Characters")
	} //end if
	ms.EcDSASignature = strB64Sign
	//--
	lData, okLData := cParams["l"]
	if(!okLData) {
		return ms, NewError("Failed, Seal Parameters List is Incomplete, DataLength is Missing")
	} //end if
	lData = StrTrimWhitespaces(lData)
	if(lData == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, DataLength is Empty")
	} //end if
	if(!StrRegexMatch(REGEX_STR_IS_NUMERIC_UINTEGER, lData)) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, DataLength contains Invalid Characters")
	} //end if
	//--
	dTime, okDtime := cParams["d"]
	if(!okDtime) {
		return ms, NewError("Failed, Seal Parameters List is Incomplete, DateTime Stamp is Missing")
	} //end if
	dTime = StrTrimWhitespaces(dTime)
	if(dTime == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, DateTime Stamp is Empty")
	} //end if
	if(!StrRegexMatch(REGEX_STR_IS_NUMERIC_UINTEGER, dTime)) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, DateTime Stamp contains Invalid Characters")
	} //end if
	//--
	smartMark, okMark := cParams["m"]
	if(!okMark) {
		return ms, NewError("Failed, Seal Parameters List is Incomplete, SmartMark is Missing")
	} //end if
	smartMark = StrTrimWhitespaces(smartMark)
	if(smartMark == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, SmartMark is Empty")
	} //end if
	if(!StrIStartsWith(smartMark, DESCRIPTION + " " + "v.")) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, SmartMark prefix is Invalid")
	} //end if
	ms.SealMark = smartMark
	//--
	var strDkimSgn string = StrTrimWhitespaces(Base64sDecode(strB64DkimSgn))
	if(strDkimSgn == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, DKIM Data is Empty after B64 Decode")
	} //end if
	strDkimSgn = StrTrimWhitespaces(canonizeSmartDkimSealSignature(strDkimSgn))
	if(strDkimSgn == "") {
		return ms, NewError("Failed, Seal Parameters List is Wrong, DKIM Data is Empty after Smart Canonization")
	} //end if
	ms.SealDkimSignature = strDkimSgn
	//--
	if(theEmail != senderEmail) {
		return ms, NewError("Failed, Seal Parameters List MisMatch, Sender Email does not match")
	} //end if
	//--
	if(ecdsaPemPubKey == "") { // if the pem public key of the author was not provided compose the public PEM Key from the Seal Data
		ecdsaPemPubKey = X509PemPublicKeyStartTag + "\n" + b64PubKey + "\n" + X509PemPublicKeyEndTag
	} else {
		ms.EcDSAPubKeyValidated = true // this is a flag to know which key has been used ; when this is set to true the author EcDSA PubKey has been provided and will be used ; otherwise the EcDSA PubKey found in email have to be used ... but in this case there is one more step after this method, to check if the key belongs to that user !
	} //end if
	//--
	if(IsB64PublicKeyEqualWithPemPublicKey(b64PubKey, ecdsaPemPubKey) != true) {
		return ms, NewError("Failed, Seal Parameters List is Wrong, EcDSA B64 Public Key is Different")
	} //end if
	//--
	var nLData int64 = ParseStrAsInt64(lData)
	if(nLData <= 0) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, DataLength is Zero or Negative")
	} else if(nLData != int64(len(strDkimSgn))) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, DataLength is Not Matching the DKIM Length")
	} //end if
	ms.SealDkimSignatureLen = nLData
	//--
	var chainChecksum string = ""
	if(eplg.Sha384B64 != "") {
		chainChecksum = StrTrimWhitespaces(Base64NormalizeMultiLineData(eplg.Sha384B64))
		if(chainChecksum != "") {
			if(!StrRegexMatch(REGEX_SAFE_B64_STR, chainChecksum)) {
				return ms, NewError("Failed, Chain Checksum B64 SHA-384 contains illegal characters")
			} //end if
		} //end if
	} //end if
	if(chainChecksum == "") {
		chainChecksum = SEAL_DKIM_CHAIN_CHECKSUM_EMPTY
		ms.ChainCheckSumAlgo = "[NONE]"
	} else {
		ms.ChainCheckSumAlgo = "SHA-384"
	} //end if
	ms.ChainCheckSum = chainChecksum
	//--
	var signBytData []byte = []byte(StrToLower(smartMark) + "\n" + StrToLower(cTyp) + "\n" + "v." + theVersion + "\n" + StrToLower(theCanM) + "\n" + senderEmail + "\n" + strDkimSgn + "\n" + dTime + "\n" + chainChecksum)
	//--
	errVfy := VerifySignedWithX509PublicKeyPEM("EcDSA", ecdsaPemPubKey, signBytData, strB64Sign, "sha3-512", true) // asn1
	ms.ErrSealVerifySign = errVfy
	if(errVfy != nil) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, Base64 Signature does not match: " + errVfy.Error())
	} //end if
	ms.IsSealSignatureOK = true
	//--
	var nDtime int64 = ParseStrAsInt64(dTime)
	if(nDtime <= 0) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, DateTime Stamp is Zero or Negative")
	} else if(nDtime > TimeNowUnix()) {
		return ms, NewError("Failed, Seal Parameters List is MisMatch, DateTime Stamp is in the Future")
	} //end if
	ms.UnixTime = nDtime
	//--
	var dkimFnVerifyEmulatedSealDomain = func(domain string) ([]string, error) {
		return DkimEmulateDnsKey(SEAL_DKIM_EMULATED_DOMAIN, ecdsaPemPubKey, "ecdsa521")
	}
	dkimVfyOpts, errDkimVfyOpts := DkimGetDefaultVerifyOptions(1, dkimFnVerifyEmulatedSealDomain) // use emulated verify
	if(errDkimVfyOpts != nil) {
		return ms, NewError("DKIM Seal Verify Default Options Failed: " + errDkimVfyOpts.Error())
	} //end if
	if(dkimVfyOpts == nil) {
		return ms, NewError("DKIM Seal Verify Default Options is Null")
	} //end if
	okDkim, dkVerifs, errDkimVfy := dkim.VerifySignedMimeMessage(dkimVfyOpts, append([]byte(strDkimSgn + "\r\n"), bytMsg...))
	ms.SealDkimVerifyPassed = okDkim
	ms.SealDkimVerifyError = errDkimVfy
	ms.SealDkimVerifications = dkVerifs
	if(errDkimVfy != nil) {
		return ms, NewError("DKIM Seal Verify Failed: " + errDkimVfy.Error())
	} //end if
	if(len(dkVerifs) <= 0) {
		return ms, NewError("DKIM Seal Verify Failed, NO VERIFICATIONS")
	} //end if
	if(okDkim != true) {
		return ms, NewError("DKIM Seal Verification is NOT OK")
	} //end if
	for _, v := range dkVerifs {
		if(v != nil) {
			if(v.Err != nil) {
				return ms, NewError("DKIM Seal Verification: at least one Verification has Failed: " + v.Err.Error() + ", for the Seal sandboxed Domain: `" + v.Domain + "`")
			} //end if
		} //end if
	} //end for
	//--
	ms.IsSealValidOK = true
	ms.SealValidationsSecurityNotes = []string{}
	if(ms.EcDSAPubKeyValidated != true) {
		ms.SealValidationsSecurityNotes = append(ms.SealValidationsSecurityNotes, SEAL_PUBKEY_NOT_VALIDATED_HINT)
		ms.SealValidationsSecurityNotes = append(ms.SealValidationsSecurityNotes, SEAL_PUBKEY_NOT_VALIDATED_TODO)
	} //end if
	ms.SealVerifyDateTime = DateNowUtc()
	//--
	return ms, nil
	//--
} //END FUNCTION


func VerifyMailerEcdsaCertAndKeys(pemCertificate string, pemPublicKey string, pemPrivateKey string, passPrivateKey []byte) error {
	//--
	defer PanicHandler()
	//--
	pemCertificate = StrTrimWhitespaces(pemCertificate)
	if(pemCertificate == "") {
		return NewError("Certificate PEM is Empty")
	} //end if
	//--
	pemPublicKey = StrTrimWhitespaces(pemPublicKey)
	if(pemPublicKey == "") {
		return NewError("PublicKey PEM is Empty")
	} //end if
	//--
	pemPrivateKey = StrTrimWhitespaces(pemPrivateKey)
	if(pemPrivateKey == "") {
		return NewError("PrivateKey PEM is Empty")
	} //end if
	if(BytTrimWhitespaces(passPrivateKey) == nil) {
		return NewError("PrivateKey Pass is Empty")
	} //end if
	//--
	errCliX509, cliX509 := certinfo.CertificatePEMToX509(pemCertificate)
	if(errCliX509 != nil) {
		return errCliX509
	} //end if
	if(cliX509 == nil) {
		return NewError("X509 Certificate is Null")
	} //end if
	//--
	errExtract, pubKeyPEMExtract := ExtractX509PublicKeyFromCertificatePEM(pemCertificate, true) // as PEM
	if(errExtract != nil) {
		return errExtract
	} //end if
	if(pubKeyPEMExtract != pemPublicKey) {
		return NewError("PublicKey extract from Certificate comparison failed")
	} //end if
	//--
	errPExtract, pubKeyPEMPExtract := ExtractX509PublicKeyFromPrivateKeyPEM("EcDSA", pemPrivateKey, string(passPrivateKey), true) // as PEM
	if(errPExtract != nil) {
		return errPExtract
	} //end if
	if(pubKeyPEMPExtract != pemPublicKey) {
		return NewError("PublicKey extract from PrivateKey comparison failed")
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func VerifyMailerSignifyKeys(pemPublicKey string, pemPrivateKey string, passPrivateKey []byte) error {
	//--
	defer PanicHandler()
	//--
	pemPublicKey = StrTrimWhitespaces(pemPublicKey)
	if(pemPublicKey == "") {
		return NewError("PublicKey PEM is Empty")
	} //end if
	//--
	pemPrivateKey = StrTrimWhitespaces(pemPrivateKey)
	if(pemPrivateKey == "") {
		return NewError("PrivateKey PEM is Empty")
	} //end if
	if(BytTrimWhitespaces(passPrivateKey) == nil) {
		return NewError("PrivateKey Pass is Empty")
	} //end if
	//--
	errParsePubKey, pubKey := SignifyGetPublicKey([]byte(pemPublicKey))
	if(errParsePubKey != nil) {
		return NewError("Public Key Parse Error: " + errParsePubKey.Error())
	} //end if
	if(pubKey == nil) {
		return NewError("Public Key is Null")
	} //end if
	//--
	errParsePrivKey, thePrivKey, thePubKey := SignifyGetPrivateKey([]byte(pemPrivateKey), passPrivateKey)
	if(errParsePrivKey != nil) {
		return NewError("Private Key Parse Error: " + errParsePrivKey.Error())
	} //end if
	if(thePrivKey == nil) {
		return NewError("Private Key is Null")
	} //end if
	if(thePubKey == nil) {
		return NewError("Public Key is Null, from Private Key")
	} //end if
	//--
	if(pubKey.Equal(thePubKey) != true) {
		return NewError("Public Key does not match the Public Key from Private Key")
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


//-----


func ComposeMimeMessage(mimeMsgStruct MimeSendMessageStruct, dkimOpts *dkim.SignOptions, dkimVfyOpts *dkim.VerifyOptions, msgXtraEpilogueFn mailer.MessageXtraEpilogueFn) ([]byte, []string, error) {
	//--
	defer PanicHandler()
	//--
	msg, errMsg := composeMimeMessage(mimeMsgStruct)
	if(errMsg != nil) {
		return nil, nil, errMsg
	} //end if
	if(msg == nil) {
		return nil, nil, NewError("Mime Message is Null")
	} //end if
	//--
	return mailer.GetComposedMessageContent(msg, dkimOpts, dkimVfyOpts, msgXtraEpilogueFn)
	//--
} //END FUNCTION


func composeMimeMessage(mimeMsgStruct MimeSendMessageStruct) (*mailer.Message, error) {
	//--
	defer PanicHandler()
	//--
	mimeMsgStruct.DkimPubKeyB64 = StrTrimWhitespaces(mimeMsgStruct.DkimPubKeyB64)
	if(mimeMsgStruct.DkimPubKeyB64 != "") {
		if(!StrRegexMatch(REGEX_SAFE_B64_STR, mimeMsgStruct.DkimPubKeyB64)) {
			return nil, NewError("The DKIM Public Key for Mime Header as for DNS is not in B64 format")
		} //end if
	} //end if
	//-- From Addr
	mimeMsgStruct.FromAddress = StrTrimWhitespaces(mimeMsgStruct.FromAddress)
	if(mimeMsgStruct.FromAddress == "") {
		return nil, NewError("From Address is Empty")
	} //end if
	if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, mimeMsgStruct.FromAddress)) {
		return nil, NewError("From Address is Invalid")
	} //end if
	//-- From Name
	mimeMsgStruct.FromName = StrNormalizeSpaces(StrTrimWhitespaces(mimeMsgStruct.FromName))
	if(int64(StrUnicodeLen(mimeMsgStruct.FromName)) > int64(MIME_FROM_NAME_MAX_LEN)) { // can be empty
		return nil, NewError("From Name is Too Long")
	} //end if
	if(StrContains(mimeMsgStruct.FromName, "@")) {
		return nil, NewError("From Name cannot contain `@` character")
	} //end if
	//-- To
	if(len(mimeMsgStruct.ToAddresses) <= 0) {
		return nil, NewError("To addresses list is Empty")
	} //end if
	for i:=0; i<len(mimeMsgStruct.ToAddresses); i++ {
		mimeMsgStruct.ToAddresses[i] = StrTrimWhitespaces(mimeMsgStruct.ToAddresses[i])
		if(mimeMsgStruct.ToAddresses[i] == "") {
			return nil, NewError("Empty Email Address, To #" + ConvertIntToStr(i))
		} //end if
		if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, mimeMsgStruct.ToAddresses[i])) {
			return nil, NewError("Invalid Email Address, To #" + ConvertIntToStr(i))
		} //end if
	} //end for
	//-- Cc
	if(len(mimeMsgStruct.CcAddresses) > 0) {
		for i:=0; i<len(mimeMsgStruct.CcAddresses); i++ {
			mimeMsgStruct.CcAddresses[i] = StrTrimWhitespaces(mimeMsgStruct.CcAddresses[i])
			if(mimeMsgStruct.CcAddresses[i] == "") {
				return nil, NewError("Empty Email Address, Cc #" + ConvertIntToStr(i))
			} //end if
			if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, mimeMsgStruct.CcAddresses[i])) {
				return nil, NewError("Invalid Email Address, Cc #" + ConvertIntToStr(i))
			} //end if
		} //end for
	} //end if
	//-- Bcc
	if(len(mimeMsgStruct.BccAddresses) > 0) {
		for i:=0; i<len(mimeMsgStruct.BccAddresses); i++ {
			mimeMsgStruct.BccAddresses[i] = StrTrimWhitespaces(mimeMsgStruct.BccAddresses[i])
			if(mimeMsgStruct.BccAddresses[i] == "") {
				return nil, NewError("Empty Email Address, Cc #" + ConvertIntToStr(i))
			} //end if
			if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, mimeMsgStruct.BccAddresses[i])) {
				return nil, NewError("Invalid Email Address, Cc #" + ConvertIntToStr(i))
			} //end if
		} //end for
	} //end if
	//-- Subject
	mimeMsgStruct.Subject = StrNormalizeSpaces(StrTrimWhitespaces(mimeMsgStruct.Subject))
	if(mimeMsgStruct.Subject == "") {
		return nil, NewError("Subject is Empty")
	} //end if
	if(int64(StrUnicodeLen(mimeMsgStruct.Subject)) > int64(MIME_SUBJECT_MAX_LEN)) {
		return nil, NewError("Subject is Too Long")
	} //end if
	//-- Body
	mimeMsgStruct.Body = StrTrimWhitespaces(StrNormalizeOnlySpaces(mimeMsgStruct.Body))
	if(mimeMsgStruct.Body == "") {
		return nil, NewError("Body is Empty")
	} //end if
	if(int64(len(mimeMsgStruct.Body)) > int64(MIME_BODY_MAX_LEN)) {
		return nil, NewError("Body is Too Long")
	} //end if
	//-- Alt Body (allowed just if body is html)
	mimeMsgStruct.AltBody = StrTrimWhitespaces(StrNormalizeOnlySpaces(mimeMsgStruct.AltBody))
	if(mimeMsgStruct.IsHtml == true) {
		if(int64(len(mimeMsgStruct.AltBody)) > int64(MIME_BODY_MAX_LEN)) {
			return nil, NewError("Alternate Body is Too Long")
		} //end if
	} else {
		if(mimeMsgStruct.AltBody != "") {
			return nil, NewError("Alternate Body is allowed just with HTML Body")
		} //end if
	} //end if else
	//-- Size Calculator
	var maxAttachAndEmbeddSize int = 0
	//-- Embedds
	var numEmbedds int = len(mimeMsgStruct.Embedds)
	if(int64(numEmbedds) > int64(MIME_EMBEDS_MAX_NUM)) {
		return nil, NewError("Embedds list can contain max " + ConvertUInt64ToStr(MIME_EMBEDS_MAX_NUM))
	} //end if
	if(numEmbedds > 0) {
		for key, val := range mimeMsgStruct.Embedds {
			//--
			if(StrTrimWhitespaces(key) == "") {
				return nil, NewError("Embedds list contain an empty key")
			} //end if
			if(int64(len(key)) > int64(MIME_FILENAME_MAX_LEN)) {
				return nil, NewError("Embedds list contain an key which is too long: `" + key + "`")
			} //end if
			if(!PathIsSafeValidFileName(key)) {
				return nil, NewError("Embedds list contain an key which contain unsafe characters: `" + key + "`")
			} //end if
			//--
			if(len(val) <= 0) {
				return nil, NewError("Embedds list contain an empty value at key: `" + key + "`")
			} //end if
			if(uint64(len(val)) > MIME_SIZE_PER_ATTACH_OR_EMBEDD) {
				return nil, NewError("Embedds list contain an oversized value (more than 32MB) at key: `" + key + "`")
			} //end if
			//--
			maxAttachAndEmbeddSize += len(val)
			//--
		} //end for
	} //end if
	//-- Attachments
	var numAttachments int = len(mimeMsgStruct.Attachments)
	if(int64(numAttachments) > int64(MIME_ATTACHMENTS_MAX_NUM)) {
		return nil, NewError("Attachments list can contain max " + ConvertUInt64ToStr(MIME_ATTACHMENTS_MAX_NUM))
	} //end if
	if(numAttachments > 0) {
		for key, val := range mimeMsgStruct.Attachments {
			//--
			if(StrTrimWhitespaces(key) == "") {
				return nil, NewError("Attachments list contain an empty key")
			} //end if
			if(int64(len(key)) > int64(MIME_FILENAME_MAX_LEN)) {
				return nil, NewError("Attachments list contain an key which is too long: `" + key + "`")
			} //end if
			if(!PathIsSafeValidFileName(key)) {
				return nil, NewError("Attachments list contain an key which contain unsafe characters: `" + key + "`")
			} //end if
			//--
			if(len(val) <= 0) {
				return nil, NewError("Attachments list contain an empty value at key: `" + key + "`")
			} //end if
			if(uint64(len(val)) > MIME_SIZE_PER_ATTACH_OR_EMBEDD) {
				return nil, NewError("Attachments list contain an oversized value (more than 32MB) at key: `" + key + "`")
			} //end if
			//--
			maxAttachAndEmbeddSize += len(val)
			//--
		} //end for
	} //end if
	//--
	if((maxAttachAndEmbeddSize < 0) || (uint64(maxAttachAndEmbeddSize) > MIME_SIZE_TOTAL_ATTACH_AND_EMBEDD)) {
		return nil, NewError("The total size of all Embedds and Attachments cannot be more than 128MB")
	} //end if
	//--
	mimeMsgStruct.Encoding = StrToUpper(StrTrimWhitespaces(mimeMsgStruct.Encoding))
	if(mimeMsgStruct.Encoding == "") {
		mimeMsgStruct.Encoding = MAIL_ENCODING_B64 // B64
	} //end if
	var mEncoding mailer.Encoding = mailer.Base64 // B64
	switch(mimeMsgStruct.Encoding) {
		case MAIL_ENCODING_7BIT: // 7-bit emulated (uses 8-bit but deaccents all headers and text/html bodies)
			mimeMsgStruct.FromName = StrDeaccent(mimeMsgStruct.FromName)
			mimeMsgStruct.Subject = StrDeaccent(mimeMsgStruct.Subject)
			mimeMsgStruct.Body = StrDeaccent(mimeMsgStruct.Body)
			mimeMsgStruct.AltBody = StrDeaccent(mimeMsgStruct.AltBody)
			mEncoding = mailer.Unencoded // 8-bit
			break
		case MAIL_ENCODING_8BIT:
			mEncoding = mailer.Unencoded // 8-bit
			break
		case MAIL_ENCODING_QP:
			mEncoding = mailer.QuotedPrintable // QP
			break
		case MAIL_ENCODING_B64:
			// as default: B64
			break
		default:
			return nil, NewError("Invalid Encoding: `" + mimeMsgStruct.Encoding + "`")
	} //end switch
	//--
	msg := mailer.NewMessage(mEncoding, mimeMsgStruct.MainEncodingQp)
	msg.SetEncoding(mEncoding)
	msg.SetCharset(CHARSET)
	//--
	if(mimeMsgStruct.DkimPubKeyB64 != "") {
		msg.SetHeader(MIME_HEADER_KEY_DKIM_PUBKEY, mimeMsgStruct.DkimPubKeyB64)
	} //end if
	//--
	msg.SetDateHeader(MIME_HEADER_KEY_DATE, time.Now().UTC())
	//--
	_, mailDomain, errParseEmlAddr := ParseEmailAddress(mimeMsgStruct.FromAddress)
	if(errParseEmlAddr != nil) {
		return nil, NewError("Email Address (From) Separation Failed for the Message ID: " + errParseEmlAddr.Error())
	} //end if
	mailDomain = StrTrimWhitespaces(mailDomain)
	if(mailDomain == "") {
		return nil, NewError("Email Address (From) Separation Failed for the Message ID, Domain part is Empty")
	} //end if
	//--
	msgID := "<MsgId!" + StrToLower(Crc64eB36(mimeMsgStruct.FromAddress + "\n" + mailDomain) + "!" + uid.Uuid17Seq() + "-" + uid.Uuid13Str() + "-" + uid.Uuid10Num() + "@" + mailDomain) + ">" // must be case sensitive with lower and upper characters
	//println(msgID)
	msg.SetHeader(MIME_HEADER_KEY_MESSAGE_ID, msgID)
	//--
	uuidBound := "000000000000000" + uid.Uuid10Num() + uid.Uuid10Num() + uid.Uuid10Str() // 45
	boundary  := "_Smart-Mail=X=" + uuidBound + "_" // 60 characters ; multipart/mixed
	aboundary := "_Smart-Mail=A=" + uuidBound + "_" // 60 characters ; multipart/alternative
	rboundary := "_Smart-Mail=R=" + uuidBound + "_" // 60 characters ; multipart/related
	//--
	msg.SetBoundary(boundary)
	msg.SetABoundary(aboundary)
	msg.SetRBoundary(rboundary)
	//--
	msg.SetAddressHeader(MIME_HEADER_KEY_FROM, mimeMsgStruct.FromAddress, mimeMsgStruct.FromName)
	msg.SetHeader(MIME_HEADER_KEY_TO,  mimeMsgStruct.ToAddresses...)
	if(len(mimeMsgStruct.CcAddresses) > 0) {
		msg.SetHeader(MIME_HEADER_KEY_CC,  mimeMsgStruct.CcAddresses...)
	} //end if
	if(len(mimeMsgStruct.BccAddresses) > 0) {
		msg.SetHeader(MIME_HEADER_KEY_BCC, mimeMsgStruct.BccAddresses...)
	} //end if
	//--
	msg.SetHeader(MIME_HEADER_KEY_SUBJECT, mimeMsgStruct.Subject)
	//--
	if(mimeMsgStruct.IsHtml == true) {
		if(mimeMsgStruct.AltBody == "") { // anti-spam rules needs an alternate plain text for html messages for better score
			mimeMsgStruct.AltBody = StrTrimWhitespaces(StrNormalizeOnlySpaces(MIME_COMPOSER_DEFAULT_ALT_BODY_TEXT))
		} //end if
		errAddBody := msg.SetBody(MIME_MESSAGE_PART_MIMETYPE_TEXT, mimeMsgStruct.AltBody)
		if(errAddBody != nil) {
			return nil, errAddBody
		} //end if
		errAddAltBody := msg.AddAlternative(MIME_MESSAGE_PART_MIMETYPE_HTML, mimeMsgStruct.Body)
		if(errAddAltBody != nil) {
			return nil, errAddAltBody
		} //end if
	} else {
		errAddBody := msg.SetBody(MIME_MESSAGE_PART_MIMETYPE_TEXT, mimeMsgStruct.Body)
		if(errAddBody != nil) {
			return nil, errAddBody
		} //end if
	} //end if
	//--
	if(numEmbedds > 0) {
		var errEmbedd error
		for key, val := range mimeMsgStruct.Embedds {
			if(len(val) <= 0) {
				errEmbedd = NewError("Failed to Embedd `" + key + "`, Content is Empty")
			} else {
				msg.Embed(key, mailer.SetCopyFunc(func(w io.Writer) error {
					_, err := w.Write([]byte(val))
					errEmbedd = err
					return err
				}))
			} //end if else
			if(errEmbedd != nil) {
				return nil, NewError("Failed to Embedd `" + key + "`, Error: " + errEmbedd.Error())
			} //end if
		} //end for
	} //end if
	mimeMsgStruct.Embedds = nil // free mem
	//--
	if(numAttachments > 0) {
		var errAttach error
		for key, val := range mimeMsgStruct.Attachments {
			if(len(val) <= 0) {
				errAttach = NewError("Failed to Attach `" + key + "`, Content is Empty")
			} else {
				msg.Attach(key, mailer.SetCopyFunc(func(w io.Writer) error {
					_, err := w.Write([]byte(val))
					errAttach = err
					return err
				}))
			} //end if else
			if(errAttach != nil) {
				return nil, NewError("Failed to Attach `" + key + "`, Error: " + errAttach.Error())
			} //end if
		} //end for
	} //end if
	mimeMsgStruct.Attachments = nil // free mem
	//--
	return msg, nil
	//--
} //END FUNCTION


//-----


// #END
