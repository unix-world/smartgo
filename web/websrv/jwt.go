
// GO Lang :: SmartGo / Web Server / JWT :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241128.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"time"

	smart 	"github.com/unix-world/smartgo"
	jwt 	"github.com/unix-world/smartgo/web/jwt"
)


const (
	JwtDefaultExpirationMinutes int64 = 60 * 24
	JwtMaxExpirationMinutes 	int64 = 60 * 24 * 365
	JwtMinExpirationMinutes 	int64 = 1

	JwtMinLength                uint16 = 128
	JwtMaxLength                uint16 = 512
)

var (
	authJwtAlgo string = "" // if this is empty, will dissalow JWT use ; allowed values: "Ed448" ; "Edx25519" ; "Ed25519" ; "H3S512" ; "H3S384" ; "H3S256" ; "H3S224" ; "HS384" ; "HS224"
)

type JwtClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type JwtData struct {
	Type  		string 		`json:"type"`
	Size 		uint64 		`json:"size"`
	Token 		string 		`json:"token"`
	TimeNow     int64 		`json:"timeNow"`
	ExpMinutes 	int64 		`json:"expMinutes"`
	ExpAt 		string 		`json:"expAt"`
	PublicKey 	string 		`json:"publicKey,omitempty"`
	MetaInfo 	JwtClaims 	`json:"metaInfo"`
}


//-----


func JwtExtractUserName(tokenString string) string {
	//--
	defer smart.PanicHandler() // req. by base64 decode with malformed data
	//--
	tokenString = smart.StrTrimWhitespaces(tokenString)
	if(tokenString == "") {
		return ""
	} //end if
	if(len(tokenString) < int(JwtMinLength)) {
		return ""
	} //end if
	if(len(tokenString) > int(JwtMaxLength)) {
		return ""
	} //end if
	//--
	arrParts := smart.ExplodeWithLimit(".", tokenString, 3)
	if(len(arrParts) < 3) { // expects: header.data.signature
		return ""
	} //end if
	var jsonPartTxt string = smart.StrTrimWhitespaces(arrParts[1])
	if(jsonPartTxt == "") {
		return ""
	} //end if
	jsonPartByteTxt, errJwtB64SegDecode := jwt.DecodeSegment(jsonPartTxt)
	if(errJwtB64SegDecode != nil) {
		return ""
	} //end if
	jsonPartTxt = smart.StrTrimWhitespaces(string(jsonPartByteTxt))
	jsonPartByteTxt = nil
	if(jsonPartTxt == "") {
		return ""
	} //end if
	//--
	var userName string = smart.StrTrimWhitespaces(smart.JsonGetValueByKeyPath(jsonPartTxt, "username").String())
	//--
	return userName
	//--
} //END FUNCTION


func JwtVerifyWithUserPrivKey(tokenString string, jwtSignMethod string, dom string, port string, userName string, userPrivKey string) error {
	//--
	defer smart.PanicHandler() // req. by base64 decode, inside JWT with malformed data
	//-- works for both: Ed* and HS*
	return jwtVerify(tokenString, jwtSignMethod, dom, port, userName, userPrivKey, "")
	//--
} //END FUNCTION


func JwtVerifyWithPublicKey(tokenString string, jwtSignMethod string, dom string, port string, userName string, publicKey string) error {
	//--
	defer smart.PanicHandler() // req. by base64 decode, inside JWT with malformed data
	//-- works just for: Ed*
	return jwtVerify(tokenString, jwtSignMethod, dom, port, userName, "", publicKey)
	//--
} //END FUNCTION


func JwtGetFullNameSigningAlgo(jwtSignMethod string) string {
	//--
	return "JWT:" + jwtSignMethod
	//--
} //END FUNCTION


func JwtNew(jwtSignMethod string, expirationMinutes int64, dom string, port string, userName string, userPrivKey string) (JwtData, error) {
	//--
	defer smart.PanicHandler() // req. by base64 decode, inside JWT with malformed data
	//--
	if(expirationMinutes < JwtMinExpirationMinutes) {
		expirationMinutes = JwtMinExpirationMinutes // disallow no-expiration JWT Tokens, where expire is zero
	} else if(expirationMinutes > JwtMaxExpirationMinutes) {
		expirationMinutes = JwtMaxExpirationMinutes
	} //end if
	//--
	noData := JwtData{}
	//--
	dom = smart.StrTrimWhitespaces(dom)
	if(dom == "") {
		return noData, smart.NewError("Server Domain is Empty")
	} //end if
	port = smart.StrTrimWhitespaces(port)
	if(port == "") {
		return noData, smart.NewError("Server Port is Empty")
	} //end if
	//--
	userName = smart.StrTrimWhitespaces(userName)
	if(userName == "") {
		return noData, smart.NewError("User Name is Empty")
	} //end if
	//--
	userPrivKey = smart.StrTrimWhitespaces(userPrivKey)
	if(userPrivKey == "") {
		return noData, smart.NewError("User Private Key is Empty")
	} //end if
	//--
	dKeyLen, safeKey, errSafeKey := jwtSafeKey(jwtSignMethod, dom, port, userName, userPrivKey)
	if(errSafeKey != nil) {
		return noData, errSafeKey
	} //end if
	if(smart.StrTrimWhitespaces(safeKey) == "") {
		return noData, smart.NewError("SafeKey is Empty")
	} //end if
	if((dKeyLen <= 0) || (len(safeKey) != int(dKeyLen))) {
		return noData, smart.NewError("SafeKey have an Invalid Length")
	} //end if
	//--
	var issuer string = dom + ":" + port
	timeNow := time.Now().UTC() // {{{SYNC-SMART-JWT-UTC-TIME}}}
	expirationTime := timeNow.Add(time.Duration(expirationMinutes) * time.Minute)
	claims := JwtClaims{
		Username: userName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // In JWT, the expiry time is expressed as unix milliseconds
			IssuedAt: jwt.NewNumericDate(timeNow),
			Issuer: issuer,
		},
	}
	//--
	var token *jwt.Token = nil
	var tokenString string = ""
	var tokenErr error = smart.NewError("Token Not Generated")
	var publicKey string = ""
	var havePublicKey bool = false
	token = jwt.NewWithClaims(jwt.GetSigningMethod(jwtSignMethod), &claims)
	if(token == nil) {
		return noData, smart.NewError("Token is NULL")
	} //end if
	switch(jwtSignMethod) {
		case "HS224":  fallthrough // sha-224
		case "HS384":  fallthrough // sha-384
		case "H3S224": fallthrough // sha3-224
		case "H3S256": fallthrough // sha3-256
		case "H3S384": fallthrough // sha3-384
		case "H3S512": // sha3-512
			//-- {{{SYNC-JWT-HS*-KEYS}}}
			if(len(safeKey) != 64) { // {{{SYNC-JWT-HS-KEY-LEN}}}
				return noData, smart.NewError("Derived Private Key (" + jwtSignMethod + ") ERR: `Key Size must be 64 bytes`")
			} //end if
			//-- #
			tokenString, tokenErr = token.SignedString([]byte(safeKey))
			break
		case "Ed25519":
			havePublicKey = true
			//-- {{{SYNC-JWT-ED25519-KEYS}}}
			pK, pbKey, errK := jwt.GenerateEdPrivateAndPublicKeys([]byte(safeKey))
			if(errK != nil) {
				return noData, smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
			} //end if
			if(pK == nil) {
				return noData, smart.NewError("Private Key is NULL")
			} //end if
			if(len(pbKey) != int(dKeyLen)) {
				return noData, smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
			} //end if
			publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
			if(publicKey == "") {
				return noData, smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
			} //end if
			//-- #
			tokenString, tokenErr = token.SignedString(pK)
			break
		case "Edx25519":
			havePublicKey = true
			//-- {{{SYNC-JWT-EDX25519-KEYS}}}
			pK, pbKey, errK := jwt.GenerateEdxPrivateAndPublicKeys([]byte(safeKey))
			if(errK != nil) {
				return noData, smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
			} //end if
			if(pK == nil) {
				return noData, smart.NewError("Private Key is NULL")
			} //end if
			if(len(pbKey) != int(dKeyLen)) {
				return noData, smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
			} //end if
			publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
			if(publicKey == "") {
				return noData, smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
			} //end if
			//-- #
			tokenString, tokenErr = token.SignedString(pK)
			break
		case "Ed448":
			havePublicKey = true
			//-- {{{SYNC-JWT-ED448-KEYS}}}
			pK, pbKey, errK := jwt.GenerateEdzPrivateAndPublicKeys([]byte(safeKey))
			if(errK != nil) {
				return noData, smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
			} //end if
			if(pK == nil) {
				return noData, smart.NewError("Private Key is NULL")
			} //end if
			if(len(pbKey) != int(dKeyLen)) {
				return noData, smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
			} //end if
			publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
			if(publicKey == "") {
				return noData, smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
			} //end if
			//-- #
			tokenString, tokenErr = token.SignedString(pK)
			break
		default:
			return noData, smart.NewError("Unsupported JWT Algorithm: `" + jwtSignMethod + "`")
	} //end switch
	//--
	if(tokenErr != nil) {
		return noData, smart.NewError("Token Creation ERR: `" + tokenErr.Error() + "`")
	} //end if
	tokenString = smart.StrTrimWhitespaces(tokenString)
	if(tokenString == "") {
		return noData, smart.NewError("Token Creation Failed, Empty Data")
	} //end if
	//--
	if(havePublicKey == true) {
		errVfyWithPubKey := JwtVerifyWithPublicKey(tokenString, jwtSignMethod, dom, port, userName, publicKey) // verify using the current Public Key
		if(errVfyWithPubKey != nil) {
			return noData, errVfyWithPubKey
		} //end if
	} //end if
	//--
	errVfyWithoutPubKey := JwtVerifyWithUserPrivKey(tokenString, jwtSignMethod, dom, port, userName, userPrivKey) // verify only by secret, Public Key will be derived
	if(errVfyWithoutPubKey != nil) {
		return noData, errVfyWithoutPubKey
	} //end if
	//--
	data := JwtData{
		Type: JwtGetFullNameSigningAlgo(jwtSignMethod),
		Size: uint64(len(tokenString)),
		Token: tokenString,
		TimeNow: timeNow.Unix(),
		ExpMinutes: expirationMinutes,
		ExpAt: smart.DateFromTime(expirationTime),
		PublicKey: publicKey,
		MetaInfo: claims,
	}
	//--
	return data, nil
	//--
} //END FUNCTION


func jwtVerify(tokenString string, jwtSignMethod string, dom string, port string, userName string, userPrivKey string, publicKey string) error {
	//--
	// publicKey is required just for Ed* ; should be empty for HS*
	//--
	defer smart.PanicHandler() // req. by base64 decode, inside JWT with malformed data
	//--
	tokenString = smart.StrTrimWhitespaces(tokenString)
	if(tokenString == "") {
		return smart.NewError("Token is Empty")
	} //end if
	if(len(tokenString) < int(JwtMinLength)) {
		return smart.NewError("Token is Too Short")
	} //end if
	if(len(tokenString) > int(JwtMaxLength)) {
		return smart.NewError("Token is Too Long")
	} //end if
	//--
	dom = smart.StrTrimWhitespaces(dom)
	if(dom == "") {
		return smart.NewError("Server Domain is Empty")
	} //end if
	port = smart.StrTrimWhitespaces(port)
	if(port == "") {
		return smart.NewError("Server Port is Empty")
	} //end if
	//--
	userName = smart.StrTrimWhitespaces(userName)
	if(userName == "") {
		return smart.NewError("User Name is Empty")
	} //end if
	//--
	dKeyLen, safeKey, errSafeKey := jwtSafeKey(jwtSignMethod, dom, port, userName, userPrivKey)
	if(publicKey == "") { // if publicKey is provided, skip this verification because userPrivKey is optional
		if(errSafeKey != nil) {
			return errSafeKey
		} //end if
		if(smart.StrTrimWhitespaces(safeKey) == "") {
			return smart.NewError("SafeKey is Empty")
		} //end if
		if((dKeyLen <= 0) || (len(safeKey) != int(dKeyLen))) {
			return smart.NewError("SafeKey have an Invalid Length")
		} //end if
	} //end if
	//--
	var issuer string = dom + ":" + port
	vfyClms := JwtClaims{}
	//--
	var tkn *jwt.Token = nil
	var errTkn error = smart.NewError("Token Not Verified")
	//--
	switch(jwtSignMethod) {
		case "HS224":  fallthrough // sha-224
		case "HS384":  fallthrough // sha-384
		case "H3S224": fallthrough // sha3-224
		case "H3S256": fallthrough // sha3-256
		case "H3S384": fallthrough // sha3-384
		case "H3S512": // sha3-512
			//-- {{{SYNC-JWT-HS*-KEYS}}}
			if(len(safeKey) != 64) { // {{{SYNC-JWT-HS-KEY-LEN}}}
				return smart.NewError("Derived Private Key (" + jwtSignMethod + ") ERR: `Key Size must be 64 bytes`")
			} //end if
			//-- #
			tkn, errTkn = jwt.ParseWithClaims(tokenString, &vfyClms, func(token *jwt.Token) (interface{}, error) {
				ky := []byte(safeKey) // can be verified only with the private (secret) key, these are symmetric algos
				return ky, nil
			})
			break
		case "Ed25519":
			if(publicKey == "") {
				//-- {{{SYNC-JWT-ED25519-KEYS}}}
				_, pbKey, errK := jwt.GenerateEdPrivateAndPublicKeys([]byte(safeKey))
				if(errK != nil) {
					return smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
				} //end if
				if(len(pbKey) != int(dKeyLen)) {
					return smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
				} //end if
				publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
				if(publicKey == "") {
					return smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
				} //end if
				//-- #
			} //end if
			tkn, errTkn = jwt.ParseWithClaims(tokenString, &vfyClms, func(token *jwt.Token) (interface{}, error) {
			//	ky := pK // verify with private key
			//	ky := pK.Public(), nil // verify with public key
				ky := jwt.GetEdPublicKeyFromBytes([]byte(smart.Base64Decode(publicKey))) // verify with B64 public key
				return ky, nil
			})
			break
		case "Edx25519":
			if(publicKey == "") {
				//-- {{{SYNC-JWT-EDX25519-KEYS}}}
				_, pbKey, errK := jwt.GenerateEdxPrivateAndPublicKeys([]byte(safeKey))
				if(errK != nil) {
					return smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
				} //end if
				if(len(pbKey) != int(dKeyLen)) {
					return smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
				} //end if
				publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
				if(publicKey == "") {
					return smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
				} //end if
				//-- #
			} //end if
			tkn, errTkn = jwt.ParseWithClaims(tokenString, &vfyClms, func(token *jwt.Token) (interface{}, error) {
			//	ky := pK // verify with private key
			//	ky := pK.Public(), nil // verify with public key
				ky := jwt.GetEdxPublicKeyFromBytes([]byte(smart.Base64Decode(publicKey))) // verify with B64 public key
				return ky, nil
			})
			break
		case "Ed448":
			if(publicKey == "") {
				//-- {{{SYNC-JWT-ED448-KEYS}}}
				_, pbKey, errK := jwt.GenerateEdzPrivateAndPublicKeys([]byte(safeKey))
				if(errK != nil) {
					return smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
				} //end if
				if(len(pbKey) != int(dKeyLen)) {
					return smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
				} //end if
				publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
				if(publicKey == "") {
					return smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
				} //end if
				//-- #
			} //end if
			tkn, errTkn = jwt.ParseWithClaims(tokenString, &vfyClms, func(token *jwt.Token) (interface{}, error) {
			//	ky := pK // verify with private key
			//	ky := pK.Public(), nil // verify with public key
				ky := jwt.GetEdzPublicKeyFromBytes([]byte(smart.Base64Decode(publicKey))) // verify with B64 public key
				return ky, nil
			})
			break
		default:
			return smart.NewError("Unsupported JWT Algorithm: `" + jwtSignMethod + "`")
	} //end switch
	//--
	if(errTkn != nil) {
		return smart.NewError("Token Verification Error: `" + errTkn.Error() + "`")
	} //end if
	if(tkn == nil) {
		return smart.NewError("Token Verification is NULL")
	} //end if
	if(!tkn.Valid) {
		return smart.NewError("Token Verification is Not Valid")
	} //end if
	clms, okClms := tkn.Claims.(*JwtClaims)
	if((okClms != true) || (clms == nil)) {
		return smart.NewError("Token Claims are Not Valid")
	} //end if
	if(clms.RegisteredClaims.Issuer != issuer) { // verify if the issuer is dom:port
		return smart.NewError("Token Issuer is Not Valid: `" + clms.RegisteredClaims.Issuer + "`")
	} //end if
	vfyBExpAt, errVfyAt := clms.RegisteredClaims.ExpiresAt.MarshalJSON()
	if(errVfyAt != nil) {
		return smart.NewError("Token ExpiresAt Marshal Error: " + errVfyAt.Error())
	} //end if
	var vfyExpAt string = smart.StrTrimWhitespaces(string(vfyBExpAt))
	if(vfyExpAt == "") {
		return smart.NewError("Token ExpiresAt is Empty")
	} //end if
	var vfyExpInt64At int64 = smart.ParseStrAsInt64(vfyExpAt)
	if(vfyExpInt64At <= 0) {
		return smart.NewError("Token ExpiresAt is Malformed")
	} //end if
	if(vfyExpInt64At <= smart.TimeNowUtc()) { // {{{SYNC-SMART-JWT-UTC-TIME}}} ; this is an extra safety check, it is actually verified at errTkn and tkn.Valid ; here must use: <= to cmply with above verification at errTkn
		return smart.NewError("Token ExpiresAt is Expired")
	} //end if
	if(smart.AuthSafeCompare(clms.Username, userName) != true) { // {{{SYNC-HTTP-AUTH-CHECKS-GO-SMART}}}
		return smart.NewError("Token UserName MisMatch: `" + clms.Username + "` ; `" + userName + "`")
	} //end if
	if((smart.StrTrimWhitespaces(clms.Username) == "") || (smart.AuthIsValidUserName(clms.Username) != true)) { // {{{SYNC-HTTP-AUTH-CHECKS-2ND-GO-SMART}}}
		return smart.NewError("Token UserName is Not Valid: `" + clms.Username + "`")
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func jwtSafeKey(jwtSignMethod string, dom string, port string, userName string, userPrivKey string) (uint16, string, error) {
	//--
	defer smart.PanicHandler() // req. by key derive
	//--
	var issuer string = dom + ":" + port
	var dKeyLen uint16 = 64 // {{{SYNC-JWT-HS-KEY-LEN}}}
	switch(jwtSignMethod) { // {{{SYNC-SMARTGO-AUTH-JWT-ALGOS}}}
		//-- sha2:  sha-256 and sha-512 are unsafe to use for signature, they may be vulnerable to length attacks, not supported in this scenario ...
		// only sha-224 and sha-384 are safe from the sha2 !
		// https://crypto.stackexchange.com/questions/89561/known-text-attack-on-hash-function-sha-256-or-sha512
		case "HS224":   fallthrough  // sha-224
		case "HS384":   fallthrough  // sha-384
		//-- sha3: all safe
		case "H3S224":  fallthrough  // sha3-224
		case "H3S256":  fallthrough  // sha3-256
		case "H3S384":  fallthrough  // sha3-384
		case "H3S512":               // sha3-512 ; best symmetric security level
			break
		case "Ed25519": fallthrough
		case "Edx25519":
			dKeyLen = 32
			break
		case "Ed448":                // best asymmetric security level
			dKeyLen = 57
			break
		default:
			return 0, "", smart.NewError("Unsupported Algorithm: `" + jwtSignMethod + "`")
	} //end switch
	//--
	safeKey, errSafeKey := smart.Pbkdf2DerivedKey("sha3-512", userPrivKey, userName + "@" + issuer, dKeyLen, smart.DERIVE_CENTITER_TK, true) // b92
	if(errSafeKey != nil) {
		return dKeyLen, "", smart.NewError("Derived Key ERR: `" + errSafeKey.Error() + "`")
	} //end if
	if((len(safeKey) != int(dKeyLen)) || (len(safeKey) != len(smart.StrTrimWhitespaces(safeKey)))) {
		return dKeyLen, "", smart.NewError("Derived Key Length is Invalid: [" + smart.ConvertIntToStr(len(safeKey) * 8) + " bit]")
	} //end if
	//--
	return dKeyLen, safeKey, nil
	//--
} //END FUNCTION


//-----


func AuthTokenJwtIsEnabled() bool {
	//--
	if(smart.StrTrimWhitespaces(authJwtAlgo) == "") {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func authTokenJwtAlgoValidGet(algo string) string {
	//--
	switch(algo) { // {{{SYNC-SMARTGO-AUTH-JWT-ALGOS}}}
		//-- sha2:  sha-256 and sha-512 are unsafe to use for signature, they may be vulnerable to length attacks, not supported in this scenario ...
		// only sha-224 and sha-384 are safe from the sha2 !
		// https://crypto.stackexchange.com/questions/89561/known-text-attack-on-hash-function-sha-256-or-sha512
		case "HS224":    fallthrough  // sha-224
		case "HS384":    fallthrough  // sha-384
		//-- sha3: all safe
		case "H3S224":   fallthrough  // sha3-224
		case "H3S256":   fallthrough  // sha3-256
		case "H3S384":   fallthrough  // sha3-384
		case "H3S512":   fallthrough  // sha3-512 ; best symmetric security level
		case "Ed25519":  fallthrough
		case "Edx25519": fallthrough
		case "Ed448":                 // best asymmetric security level
			return algo
			break
		default:
			// N/A
	} //end switch
	//--
	return ""
	//--
} //END FUNCTION


func AuthTokenJwtAlgoGet() string {
	//--
	return authTokenJwtAlgoValidGet(authJwtAlgo)
	//--
} //END FUNCTION


func AuthTokenJwtAlgoSet(jwtAlgo string) bool {
	//--
	var ok bool = false
	//--
	if(authJwtAlgo != "") {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Failed to Set JWT Algo to: `" + jwtAlgo + "`, already set")
		return false
	} //end if
	//--
	if(jwtAlgo == "") {
		if(authJwtAlgo == "") {
			return true // no change
		} else {
			return false // dissalow unset
		} //end if else
	} //end if
	//--
	algo := smart.StrTrimWhitespaces(authTokenJwtAlgoValidGet(jwtAlgo))
	if(algo != "") {
		authJwtAlgo = algo
		ok = true
	} //end if else
	//--
	if(ok) {
		log.Println("[INFO]", smart.CurrentFunctionName(), "JWT Algo was Set to `" + authJwtAlgo + "`: Success")
	} else {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Failed to Set JWT Algo to: `" + jwtAlgo + "`")
	} //end if else
	//--
	return ok
	//--
} //END FUNCTION


//-----


// #END
