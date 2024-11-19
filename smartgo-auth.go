
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241116.2358 :: STABLE
// [ AUTH ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"crypto/subtle"
)

const (
	ALGO_PASS_SMART_SAFE_SF_PASS 		uint8 =   1
	ALGO_PASS_SMART_SAFE_ARGON_PASS 	uint8 =   2
	ALGO_PASS_SMART_UNSAFE_BF_PASS 		uint8 = 254 // Cookie Pre-Auth: BF[usr,pw] ; this is unsafe, it is reversible, must be converted to a JWT
	ALGO_PASS_SMART_SAFE_JWT_TOKEN 		uint8 = 255 // JWT
	// 0 is reserved for none ; 10..200 other pass algos ; 2..10 and 201..255 is reserved for internal use

	HTTP_AUTH_MODE_NONE   uint8 =   0
	HTTP_AUTH_MODE_BASIC  uint8 =   1
	HTTP_AUTH_MODE_BEARER uint8 =   2
	HTTP_AUTH_MODE_TOKEN  uint8 =   3
	HTTP_AUTH_MODE_COOKIE uint8 =   4
	HTTP_AUTH_MODE_RAW    uint8 = 255 // used for 3rd party

	HTTP_AUTH_DEFAULT_AREA  string = "DEFAULT"
	HTTP_AUTH_DEFAULT_PRIVS string = "<admin>"
	HTTP_AUTH_DEFAULT_RESTR string = "<none>"

	REGEX_SAFE_HTTP_USER_NAME string = `^[a-z0-9\.]+$`  // Safe UserName Regex
	REGEX_SAFE_AUTH_2FA_TOKEN string = `^[0-9]{6,8}$`   // Safe 2FA Regex 6..8 digits

	HTTP_AUTH_USER_BEARER string = "@BEARER@"
	HTTP_AUTH_USER_TOKEN  string = "@TOKEN@"
	HTTP_AUTH_USER_RAW    string = "@TOKEN@" // used for 3rd party
)

var (
	authBasicEnabled bool = true 		// default is TRUE,  does accept Auth Basic if HTTP Server ask for it ; to disable, set to FALSE
	authBearerEnabled bool = false 		// default is FALSE, does not accept Auth Bearer ; to accept Auth Bearer, set to TRUE
	authTokenEnabled bool = false 		// default is FALSE, does not accept Auth Apikey ; to accept Auth Apikey, set to TRUE
	authJwtAlgo string = "" 			// if this is empty, will dissalow JWT use ; allowed values: "Ed448" ; "Edx25519" ; "Ed25519" ; "H3S512" ; "H3S384" ; "H3S256" ; "H3S224" ; "HS384" ; "HS224"
	authCookieName string = "" 			// [2..16 characters ; valid REGEX_SAFE_VAR_NAME] ; default is EMPTY, does not accept Auth by Cookies ; to accept Auth by Cookie, set to ~ "Sf_Auth" ; this is intended to store a Token inside this Cookie for Cookie based auth
	auth2FACookieName string = "" 		// [2..16 characters ; valid REGEX_SAFE_VAR_NAME] ; default is EMPTY, to Enable 2FA (TOTP), set to ~ "Sf_2FA" ; this is intended to be used with Basic Auth, but for custom auth can be implemented also with Cookie or Bearer ...
)


//-----


func AuthBasicIsEnabled() bool { // Basic
	//--
	return authBasicEnabled
	//--
} //END FUNCTION


func AuthBasicModeSet(mode bool) bool { // Basic
	//--
	if(mode == true) { // disallow reset ! default is true, only allow set once to false
		log.Println("[WARNING]", CurrentFunctionName(), "Auth Basic cannot be Re-Set to: [", mode, "]: Success")
		return false
	} //end if
	//--
	authBasicEnabled = mode
	//--
	log.Println("[INFO]", CurrentFunctionName(), "Auth Basic was Set to: [", authBasicEnabled, "]: Success")
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthBearerIsEnabled() bool { // Bearer
	//--
	return authBearerEnabled
	//--
} //END FUNCTION


func AuthBearerModeSet(mode bool) bool { // Bearer
	//--
	if(mode != true) { // disallow reset ! default is false, only allow set once to true
		log.Println("[WARNING]", CurrentFunctionName(), "Auth Bearer cannot be Re-Set to: [", mode, "]: Success")
		return false
	} //end if
	//--
	authBearerEnabled = mode
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthTokenIsEnabled() bool { // Apikey
	//--
	return authTokenEnabled
	//--
} //END FUNCTION


func AuthTokenModeSet(mode bool) bool { // Apikey
	//--
	if(mode != true) { // disallow reset ! default is false, only allow set once to true
		log.Println("[WARNING]", CurrentFunctionName(), "Auth Token cannot be Re-Set to: [", mode, "]: Success")
		return false
	} //end if
	//--
	authTokenEnabled = mode
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthTokenJwtIsEnabled() bool {
	//--
	if(StrTrimWhitespaces(authJwtAlgo) == "") {
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
		log.Println("[WARNING]", CurrentFunctionName(), "Failed to Set JWT Algo to: `" + jwtAlgo + "`, already set")
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
	algo := StrTrimWhitespaces(authTokenJwtAlgoValidGet(jwtAlgo))
	if(algo != "") {
		authJwtAlgo = algo
		ok = true
	} //end if else
	//--
	if(ok) {
		log.Println("[INFO]", CurrentFunctionName(), "JWT Algo was Set to `" + authJwtAlgo + "`: Success")
	} else {
		log.Println("[ERROR]", CurrentFunctionName(), "Failed to Set JWT Algo to: `" + jwtAlgo + "`")
	} //end if else
	//--
	return ok
	//--
} //END FUNCTION


//-----


func AuthCookieIsEnabled() bool {
	//--
	if(AuthCookieNameGet() != "") {
		return true
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func AuthCookieNameGet() string {
	//--
	var cookieName string = StrTrimWhitespaces(authCookieName)
	if(!ValidateCookieName(cookieName)) {
		cookieName = "" // invalid, clear
	} //end if
	//--
	if(cookieName != "") {
		if((cookieName == auth2FACookieName) || (cookieName == sessionUUIDCookieName)) { // avoid collision with auth2FACookieName or sessionUUIDCookieName
			cookieName = "" // invalid, clear
		} //end if
	} //end if
	//--
	return cookieName
	//--
} //END FUNCTION


func AuthCookieNameSet(cookieName string) bool {
	//--
	var ok bool = true
	//--
	cookieName = StrTrimWhitespaces(cookieName)
	if(cookieName == "") { // do not check below for empty cookie name, must be a way to be unset by passing empty string to this method
		if(authCookieName == "") {
			return true // empty: both
		} else {
			ok = false // invalid, empty ; unset is not allowed
		} //end if else
	} else if(AuthCookieNameGet() == "") { // allow set just once
		if(ValidateCookieName(cookieName)) {
			if((cookieName != auth2FACookieName) && (cookieName != sessionUUIDCookieName)) { // avoid collision with auth2FACookieName or sessionUUIDCookieName
				authCookieName = cookieName // set
			} else {
				ok = false // was non-empty, colission
			} //end if else
		} else {
			ok = false // was non-empty, but invalid
		} //end if
	} else {
		ok = false // don't allow set it again, if already was set
	} //end if
	//--
	if(ok) {
		log.Println("[INFO]", CurrentFunctionName(), "Auth Cookie Name was Set to `" + authCookieName + "`: Success")
	} else {
		log.Println("[ERROR]", CurrentFunctionName(), "Failed to Set Auth Cookie Name to: `" + cookieName + "`")
	} //end if else
	//--
	return ok
	//--
} //END FUNCTION


//-----


func Auth2FACookieIsEnabled() bool {
	//--
	if(Auth2FACookieNameGet() != "") {
		return true
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func Auth2FACookieNameGet() string {
	//--
	var cookieName string = StrTrimWhitespaces(auth2FACookieName)
	if(!ValidateCookieName(cookieName)) {
		cookieName = "" // invalid, clear
	} //end if
	//--
	if(cookieName != "") {
		if((cookieName == authCookieName) || (cookieName == sessionUUIDCookieName)) { // avoid collision with authCookieName or sessionUUIDCookieName
			cookieName = "" // invalid, clear
		} //end if
	} //end if
	//--
	return cookieName
	//--
} //END FUNCTION


func Auth2FACookieNameSet(cookieName string) bool {
	//--
	var ok bool = true
	//--
	cookieName = StrTrimWhitespaces(cookieName)
	if(cookieName == "") { // do not check below for empty cookie name, must be a way to be unset by passing empty string to this method
		if(auth2FACookieName == "") {
			return true // empty: both
		} else {
			ok = false // invalid, empty ; unset is not allowed
		} //end if else
	} else if(Auth2FACookieNameGet() == "") { // allow set just once
		if(ValidateCookieName(cookieName)) {
			if((cookieName != authCookieName) && (cookieName != sessionUUIDCookieName)) { // avoid collision with authCookieName or sessionUUIDCookieName
				auth2FACookieName = cookieName // set
			} else {
				ok = false // was non-empty, colission
			} //end if else
		} else {
			ok = false // was non-empty, but invalid
		} //end if
	} else {
		ok = false // don't allow set it again, if already was set
	} //end if
	//--
	if(ok) {
		log.Println("[INFO]", CurrentFunctionName(), "Auth 2FA Cookie Name was Set to `" + auth2FACookieName + "`: Success")
	} else {
		log.Println("[ERROR]", CurrentFunctionName(), "Failed to Set Auth 2FA Cookie Name to: `" + cookieName + "`")
	} //end if else
	//--
	return ok
	//--
} //END FUNCTION


//-----


// PRIVATE
type AuthDataStruct struct {
	OK           bool               `json:"ok"` 			// TRUE | FALSE
	ErrMsg       string             `json:"errMsg"` 		// error message (if any) or empty string
	Method       uint8              `json:"method"` 		// see: HTTP_AUTH_MODE_*
	Area         string             `json:"area"` 			// Auth Area
	Realm        string             `json:"-"` 				// Auth Realm
	UserID       string             `json:"-"` 				// User ID (if no specific ID can be the same as User Name) ; it may be different than UserName ; UserID is intended only for internal use in contrast with UserName which is public
	UserName     string             `json:"userName"` 		// User Name
	PassHash     string             `json:"-"` 				// Password Hash
	PassAlgo     uint8              `json:"-"` 				// Password Hash Algo ; 0 for SafePassHashSmart ; 1..255 for the rest
	RawAuthData  string             `json:"-"` 				// Auth Raw Data, reserved for special usage, ex: auth cookie pre-auth
	TokenData    string             `json:"-"` 				// Auth Token Data (Ex: JWT Token)
	TokenAlgo    string             `json:"-"` 				// Token Algo (Ex: `JWT:Ed448`)
	EmailAddr    string             `json:"emailAddr"` 		// User Email Address
	FullName     string             `json:"fullName"` 		// Full Name
	Privileges   string             `json:"privileges"` 	// Privileges: <priv1>,<priv2>,...
	Restrictions string             `json:"restrictions"` 	// Restrictions: <restr1>,<restr2>,...
	PrivKey      string             `json:"-"` 				// Private Key
	Quota        uint64             `json:"-"` 				// Quota
	MetaData     map[string]string  `json:"-"` 				// MetaData ... Associative Array {"key1":"Val1", "key2":"Val2", ...}
	// TODO: add clientIP, userAgent, ...
}

//-----


func AuthDataGet(ok bool, errMsg string, method uint8, area string, realm string, userID string, userName string, passHash string, passAlgo uint8, tokenData string, tokenAlgo string, emailAddr string, fullName string, privileges string, restrictions string, privKey string, quota uint64, metaData map[string]string) AuthDataStruct {
	//--
	errMsg 			= StrTrimWhitespaces(errMsg)
	area 			= StrToUpper(StrTrimWhitespaces(area))
	realm 			= StrToUpper(StrTrimWhitespaces(realm))
	userID 			= StrToLower(StrTrimWhitespaces(userID))
	userName 		= StrToLower(StrTrimWhitespaces(userName))
	passHash 		= StrTrimWhitespaces(passHash)
	tokenData 		= StrTrimWhitespaces(tokenData)
	tokenAlgo 		= StrTrimWhitespaces(tokenAlgo) // case sensitive
	emailAddr 		= StrToLower(StrTrimWhitespaces(emailAddr))
	fullName 		= StrTrimWhitespaces(fullName)
	privileges 		= StrTrimWhitespaces(privileges)
	restrictions 	= StrTrimWhitespaces(restrictions)
	privKey 		= StrTrimWhitespaces(privKey)
	//--
	if(userID == "") { // fix if username or id is missing
		userID = userName
	} else if(userName == "") {
		userName = userID
	} //end if
	//-- can be empty: emailAddr, fullName, privileges, restrictions, privKey
	if(errMsg != "") {
		ok = false
	} //end if
	if(area == "") {
		ok = false
		if(errMsg == "") {
			errMsg = "Area is Empty"
		} //end if
	} //end if
	if(realm == "") {
		ok = false
		if(errMsg == "") {
			errMsg = "Realm is Empty"
		} //end if
	} //end if
	if((userID == "") || (AuthIsValidUserName(userID) != true)) {
		ok = false
		if(errMsg == "") {
			errMsg = "UserID is Empty or Invalid"
		} //end if
	} //end if
	if((userName == "") || (AuthIsValidUserName(userName) != true)) {
		ok = false
		if(errMsg == "") {
			errMsg = "UserName is Empty or Invalid"
		} //end if
	} //end if
	if((passAlgo <= 0) && (passHash != "")) {
		ok = false
		if(errMsg == "") {
			errMsg = "PassHash must have a valid Pass Algo"
		} //end if
	} //end if
	if((passHash == "") && (tokenData == "")) { // cannot be both empty, at least one must be available
		ok = false
		if(errMsg == "") {
			errMsg = "PassHash and TokenData can not be both Empty"
		} //end if
	} //end if
	if((tokenData != "") && (tokenAlgo == "")) {
		ok = false
		if(errMsg == "") {
			errMsg = "TokenAlgo cannot be Empty when TokenData is Set"
		} //end if
	} //end if
	//--
	if(passAlgo == ALGO_PASS_SMART_SAFE_JWT_TOKEN) {
		if(passHash != "") {
			ok = false
			if(errMsg == "") {
				errMsg = "The Token Pass Algo must be used without a PassHash"
			} //end if
		} //end if
		if(tokenData == "") {
			ok = false
			if(errMsg == "") {
				errMsg = "The Token Pass Algo must have a non-empty TokenData"
			} //end if
		} //end if
		if(tokenAlgo == "") {
			ok = false
			if(errMsg == "") {
				errMsg = "The Token Pass Algo must have a non-empty TokenAlgo"
			} //end if
		} //end if
	} else {
		if(passHash == "") {
			ok = false
			if(errMsg == "") {
				errMsg = "The PassHash cannot be empty for this Pass Algo"
			} //end if
		} //end if
	} //end if
	//--
	privAuthData := AuthDataStruct {
		OK:           ok,
		ErrMsg:       errMsg,
		Method:       method,
		Area:         area,
		Realm:        realm,
		UserID:       userID,
		UserName:     userName,
		PassHash:     passHash, // do not store clear passwords here, only valid passhash in sync with the below PassAlgo
		PassAlgo:     passAlgo,
		TokenData:    tokenData,
		TokenAlgo:    tokenAlgo,
		EmailAddr:    emailAddr,
		FullName:     fullName,
		Privileges:   privileges,
		Restrictions: restrictions,
		PrivKey:      privKey,
		Quota:        quota,
		MetaData:     metaData,
	}
	//--
	return privAuthData
	//--
} //END FUNCTION


//-----


func AuthIsValidUserName(user string) bool {
	//--
	if(len(user) != len(StrTrimWhitespaces(user))) {
		return false
	} //end if
	if(StrTrimWhitespaces(user) == "") {
		return false
	} //end if
	if((len(user) < 3) || (len(user) > 128)) { // {{{SYNC-GO-SMART-AUTH-USER-LEN}}} ; std max username length is 128 ; min 3, from Smart.Framework
		return false
	} //end if
	if(!StrRegexMatchString(REGEX_SAFE_HTTP_USER_NAME, user)) { // {{{SYNC-SF:REGEX_VALID_USER_NAME}}}
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthIsValidPassword(pass string) bool {
	//--
	if(len(pass) != len(StrTrimWhitespaces(pass))) {
		return false
	} //end if
	if(StrTrimWhitespaces(pass) == "") {
		return false
	} //end if
	if((len(StrTrimWhitespaces(pass)) < 7) || (len(pass) > 512)) { // {{{SYNC-GO-SMART-AUTH-PASS-LEN}}} ; allow tokens, length can be up to 512 (ex: JWT) ; min 7, from Smart.Framework (security)
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthIsValidPrivKey(pkey string) bool { // {{{SYNC-GO-SMART-CRYPTO-SEURITY-KEY-OR-AUTH-PKEY}}}
	//--
	if(len(pkey) != len(StrTrimWhitespaces(pkey))) {
		return false
	} //end if
	//--
	pkey = StrTrimWhitespaces(pkey)
	//--
	if(pkey == "") {
		return false
	} //end if
	if(len(pkey) < 16) {
		return false
	} //end if
	if(len(pkey) > 255) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthIsValid2FACode(code string) bool {
	//--
	if(len(code) != len(StrTrimWhitespaces(code))) {
		return false
	} //end if
	if(StrTrimWhitespaces(code) == "") {
		return false
	} //end if
	if((len(code) < 6) || (len(code) > 8)) { // flexible, between 6 and 8 characters
		return false
	} //end if
	if(!StrRegexMatchString(REGEX_SAFE_AUTH_2FA_TOKEN, code)) { // {{{SYNC-SF:REGEX_SAFE_AUTH_2FA_TOKEN}}}
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func AutAnyIsEnabled() bool {
	//--
	if((AuthBasicIsEnabled() != true) && (AuthBearerIsEnabled() != true) && (AuthTokenIsEnabled() != true) && (AuthCookieIsEnabled() != true)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthUserPassDefaultCheck(authRealm string, clientIP string, user string, pass string, authMode uint8, requiredUsername string, requiredPassword string) (bool, AuthDataStruct) {
	//--
	authData := AuthDataStruct{
		OK: false,
		ErrMsg: "??",
		Method: authMode,
	}
	//--
	if(AutAnyIsEnabled() != true) { // {{{SYNC-AUTH-CHECK-ANY}}} ; will check if any auth is available: basic, bearer, token, cookie
		//--
		authData.ErrMsg = "Auth is Disabled: No Active Auth Providers are Available"
		//--
		return false, authData
		//--
	} //end if
	//-- {{{SYNC-HTTP-AUTH-CHECKS-GO-SMART}}}
	if(AuthIsValidUserName(user) != true) {
		authData.ErrMsg = "Invalid UserName"
		return false, authData
	} //end if
	if(AuthIsValidPassword(pass) != true) {
		authData.ErrMsg = "Invalid Password"
		return false, authData
	} //end if
	//--
	if( // {{{SYNC-HTTP-AUTH-CHECKS-GO-SMART}}}
		//--
		(len(user) != len(requiredUsername)) ||
		(len(pass) != len(requiredPassword)) ||
		(subtle.ConstantTimeCompare([]byte(user), []byte(requiredUsername)) != 1) ||
		(subtle.ConstantTimeCompare([]byte(pass), []byte(requiredPassword)) != 1) ||
		(user != requiredUsername) || (pass != requiredPassword)) {
		//--
		authData.ErrMsg = "Invalid UserName / Password"
		//--
		return false, authData
		//--
	} //end if
	//--
	authData = AuthDataGet(true, "", authMode, HTTP_AUTH_DEFAULT_AREA, authRealm, user, user, SafePassHashSmart(pass, user, false), ALGO_PASS_SMART_SAFE_SF_PASS, "", "", "", "", HTTP_AUTH_DEFAULT_PRIVS, HTTP_AUTH_DEFAULT_RESTR, "", 0, nil)
	//--
	return true, authData
	//--
} //END FUNCTION


//-----


func AuthGetDefaultUserPrivKey() string {
	//--
	pkey, err := CryptoGetSecurityKey()
	if(err != nil) {
		return ""
	} //end if
	//--
	return BaseEncode([]byte(Sh3a512(pkey)), "b85") // use this when not having per/user security key
	//--
} //END FUNCTION


func AuthMethodGetNameById(methodId uint8) string {
	//--
	var name string = "Unknown"
	switch(methodId) {
		case HTTP_AUTH_MODE_NONE:
			name = "None"
			break
		case HTTP_AUTH_MODE_BASIC:
			name = "Basic"
			break
		case HTTP_AUTH_MODE_BEARER:
			name = "Bearer"
			break
		case HTTP_AUTH_MODE_TOKEN:
			name = "Token"
			break
		case HTTP_AUTH_MODE_COOKIE:
			name = "Cookie"
			break
	} //end switch
	//--
	return name
	//--
} //END FUNCTION


//-----


// #END
