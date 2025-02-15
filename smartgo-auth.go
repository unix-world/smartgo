
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250214.2358 :: STABLE
// [ AUTH ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"crypto/subtle"
)

const (
	// {{{SYNC-AUTH-PASS-ALGOS}}}
	ALGO_PASS_NONE 						uint8 =   0
	ALGO_PASS_PLAIN 					uint8 =   1
	ALGO_PASS_SMART_SAFE_SF_PASS 		uint8 =  77
	ALGO_PASS_SMART_SAFE_ARGON_PASS 	uint8 =  78
	ALGO_PASS_SMART_SAFE_BCRYPT 		uint8 = 123
	ALGO_PASS_SMART_SAFE_OPQ_TOKEN 		uint8 = 204 // Opaque Token
	ALGO_PASS_SMART_SAFE_WEB_TOKEN 		uint8 = 216 // Web (Signed) Token / JWT
	ALGO_PASS_SMART_SAFE_SWT_TOKEN 		uint8 = 228 // SWT Tokens (only available in PHP)
	ALGO_PASS_CUSTOM_TOKEN 				uint8 = 244 // other, custom implementations of token logic
	ALGO_PASS_CUSTOM_HASH_PASS 			uint8 = 255 // other, custom implementations of pass hashing

	// {{{SYNC-AUTH-MODES}}}
	HTTP_AUTH_MODE_NONE   uint8 =   0
	HTTP_AUTH_MODE_BASIC  uint8 =   1
	HTTP_AUTH_MODE_TOKEN  uint8 =  28
	HTTP_AUTH_MODE_BEARER uint8 =  29
	HTTP_AUTH_MODE_COOKIE uint8 = 129
	HTTP_AUTH_MODE_APIKEY uint8 = 229
	HTTP_AUTH_MODE_RAW    uint8 = 255 // used for 3rd party

	HTTP_AUTH_DEFAULT_AREA  string = "[DEFAULT]" // this is a special area, surrounded by [] ; any other areas must allow just: A-Z 0-9 -
	HTTP_AUTH_DEFAULT_PRIV  string = "<default>" // must include only (one) the default privilege   for a valid user, not admin ; NOT FOR external JWT Auth
	HTTP_AUTH_ADMIN_PRIV    string = "<admin>"   // must include only (one) the admin privilege     for a valid user,     admin ; NOT FOR external JWT Auth
	HTTP_AUTH_DEFAULT_RESTR string = "<none>"    // must include only (one) the default restriction for a valid user, not admin ; NOT FOR external JWT Auth

	REGEX_SAFE_METAKEY 		string = `^[a-z0-9\-\.]+$` // {{{SYNC-METADATA-VALID-KEY-REGEX}}} ; must be lowercase (insensitive case) to avoid duplicates

	REGEX_SAFE_AUTH_AREA 		string 	= `^[A-Z0-9\-\.]{4,48}` 							// this must not allow [] to conflict with the default area ; {{{SYNC-AUTH-EXT-AREA-REGEX}}}
	REGEX_VALID_PRIV_RESTR_KEY 	string 	= `^([a-z]{1}[a-z0-9\-\:]{0,20}[a-z0-9]{1})$` 		// valid name for one privilege key from list of privileges ; a valid privilege key can have 2..22 characters and can contain only: `a-z`, `0-9`, `:` and `-` ; must start with `a-z` only ; must not end with `:` or `-`

	REGEX_SAFE_HTTP_USER_NAME 		string = `^[a-z0-9\.]{5,25}$` 							// Safe HTTP Auth UserName Regex ; intended as a safe user ID for all cases
	REGEX_SAFE_AUTH_EMAIL_ADDRESS 	string = `^[_a-z0-9\-\.]{1,41}@[a-z0-9\-\.]{3,30}$` 	// Safe Auth Email regex ; internet email@(subdomain.)domain.name ; max 72 ; practical
	REGEX_SAFE_AUTH_USER_NAME 		string = `^[_a-z0-9\-\.@]{5,72}$` 						// Safe Auth Username Regex ; cover boths above

	REGEX_SAFE_AUTH_OPAQUE_TOKEN 	string = `^[a-zA-Z0-9\-]{44,126}$` 	// Safe (Opaque) Token Regex ; {{{SYNC-MAX-AUTH-TOKEN-LENGTH}}}
	REGEX_SAFE_AUTH_2FA_CODE 		string = `^[0-9]{6,8}$` 			// Safe 2FA Regex 6..8 digits

	OPAQUE_TOKEN_FULL_NAME string = "Opaque:UUID"

	HTTP_AUTH_USER_TOKEN  string = ":TOKEN" 	// used for http client to add header: 				`Authorization: Token ****`  where `****` is the opaque token
	HTTP_AUTH_USER_BEARER string = ":BEARER" 	// used for http client to add header: 				`Authorization: Bearer ****` where `****` is the jwt signed token
	HTTP_AUTH_USER_APIKEY string = ":APIKEY" 	// used for http client to add header: 				`Authorization: Apikey ****` where `****` is the external jwt signed token for non-existing accounts
	HTTP_AUTH_USER_RAW    string = ":RAW" 		// used for http client to add custom header like: 	`Authorization: %Custom% ****` where `%Custom% ****` is the password ; ex: `Authorization: OAuth ****`
)

var (
	authBasicEnabled bool = false 		// default is FALSE, does not accept Auth Basic if HTTP Server ask for it ; to enable, set to TRUE
	authTokenEnabled bool = false 		// default is FALSE, does not accept Auth Token  ; to accept Auth Token,  set to TRUE
	authBearerEnabled bool = false 		// default is FALSE, does not accept Auth Bearer ; to accept Auth Bearer, set to TRUE
	authApikeyEnabled bool = false 		// default is FALSE, does not accept Auth ApiKey ; to accept Auth ApiKey, set to TRUE
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
	authBasicEnabled = mode
	//--
	log.Println("[INFO]", CurrentFunctionName(), "Auth Basic was Set to: [", authBasicEnabled, "]: Success")
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthTokenIsEnabled() bool { // Token
	//--
	return authTokenEnabled
	//--
} //END FUNCTION


func AuthTokenModeSet(mode bool) bool { // Token
	//--
	authTokenEnabled = mode
	//--
	log.Println("[INFO]", CurrentFunctionName(), "Auth Token was Set to: [", authTokenEnabled, "]: Success")
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
	authBearerEnabled = mode
	//--
	log.Println("[INFO]", CurrentFunctionName(), "Auth Bearer was Set to: [", authBearerEnabled, "]: Success")
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthApikeyIsEnabled() bool { // ApiKey
	//--
	return authApikeyEnabled
	//--
} //END FUNCTION


func AuthApikeyModeSet(mode bool) bool { // ApiKey
	//--
	authApikeyEnabled = mode
	//--
	log.Println("[INFO]", CurrentFunctionName(), "Auth ApiKey was Set to: [", authApikeyEnabled, "]: Success")
	//--
	return true
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
	Realm        string             `json:"realm"` 			// Auth Realm
	UserID       string             `json:"userId"` 		// User ID (if no specific ID can be the same as User Name) ; it may be different than UserName ; UserID is intended only for internal use in contrast with UserName which is public
	UserName     string             `json:"userName"` 		// User Name
	PassHash     string             `json:"-"` 				// Password Hash
	PassAlgo     uint8              `json:"-"` 				// Password Hash Algo ; 0 for SafePassHashSmart ; 1..255 for the rest
	RawAuthData  string             `json:"-"` 				// Auth Raw Data, reserved for special usage, ex: auth cookie pre-auth
	TokenData    string             `json:"-"` 				// Auth Token Data (Ex: JWT Token)
	TokenAlgo    string             `json:"-"` 				// Token Algo (Ex: `JWT:Ed448`)
	SecurityKey  string             `json:"-"` 				// Security Key
	PubKey       string             `json:"pubKey"` 		// Public Key
	PrivKey      string             `json:"-"` 				// Private Key
	Privileges   string             `json:"privileges"` 	// Privileges: <priv1>,<priv2>,...
	Restrictions string             `json:"restrictions"` 	// Restrictions: <restr1>,<restr2>,...
	EmailAddr    string             `json:"emailAddr"` 		// User Email Address
	FullName     string             `json:"fullName"` 		// Full Name
	Quota        int64              `json:"quota"` 			// Quota: -1 no quota ; 0 unlimited ; > 1 MB
	MetaData     map[string]string  `json:"metaData"` 		// MetaData ... Associative Array {"key1":"Val1", "key2":"Val2", ...}
}


//-----


func AuthGetMetaData(authData AuthDataStruct, key string) (string, error) {
	//--
	if(authData.MetaData == nil) {
		return "", NewError("Auth MetaData is Null")
	} //end if
	if(len(authData.MetaData) <= 0) {
		return "", NewError("Auth MetaData is Empty")
	} //end if
	//--
	key = StrToLower(StrTrimWhitespaces(key))
	if(key == "") {
		return "", NewError("Auth MetaData Key is Empty")
	} //end if
	//--
	if(!StrRegexMatch(REGEX_SAFE_METAKEY, key)) { // {{{SYNC-METADATA-VALID-KEY-REGEX}}}
		return "", NewError("Auth MetaData Key is Invalid")
	} //end if
	//--
	val, ok := authData.MetaData[key]
	if(!ok) {
		return "", NewError("Auth MetaData Key is Missing")
	} //end if
	//--
	return val, nil
	//--
} //END FUNCTION


func AuthDataInit(ok bool, errMsg string, method uint8, area string, realm string, userID string, userName string, passHash string, passAlgo uint8, tokenData string, tokenAlgo string, emailAddr string, fullName string, privileges string, restrictions string, privKey string, pubKey string, secKey string, quota int64, metaData map[string]string) AuthDataStruct {
	//--
	// {{{SYNC-AUTH-PASS-ALGOS}}}
	//--
	errMsg 			= StrTrimWhitespaces(errMsg)
	area 			= StrToUpper(StrTrimWhitespaces(area))
	realm 			= StrTrimWhitespaces(realm)
	userID 			= StrToLower(StrTrimWhitespaces(userID))
	userName 		= StrToLower(StrTrimWhitespaces(userName))
	passHash 		= StrTrimWhitespaces(passHash)
	tokenData 		= StrTrimWhitespaces(tokenData)
	tokenAlgo 		= StrTrimWhitespaces(tokenAlgo) // case sensitive
	emailAddr 		= StrToLower(StrTrimWhitespaces(emailAddr))
	fullName 		= StrTrimWhitespaces(fullName)
	privileges 		= AuthSafeListPrivsRestr(privileges)
	restrictions 	= AuthSafeListPrivsRestr(restrictions)
	privKey 		= StrTrimWhitespaces(privKey)
	pubKey 			= StrTrimWhitespaces(pubKey)
	secKey 			= StrTrimWhitespaces(secKey)
	//--
	if(userID == "") { // fix if username or id is missing
		userID = userName
	} else if(userName == "") {
		userName = userID
	} //end if
	//-- can be empty: emailAddr, fullName, privileges, restrictions, privKey, pubKey, secKey
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
	if(userID == "") {
		ok = false
		if(errMsg == "") {
			errMsg = "UserID is Empty"
		} //end if
	} //end if
	if(userName == "") {
		ok = false
		if(errMsg == "") {
			errMsg = "UserName is Empty"
		} //end if
	} //end if
	if(area == HTTP_AUTH_DEFAULT_AREA) { // standard ; default area requires more constraints because the username/id can be used as a HTTP auth user
		if(AuthIsValidUserName(userID) != true) {
			ok = false
			if(errMsg == "") {
				errMsg = "UserID is Invalid"
			} //end if
		} //end if
		if(AuthIsValidUserName(userName) != true) {
			ok = false
			if(errMsg == "") {
				errMsg = "UserName is Invalid"
			} //end if
		} //end if
	} else { // extended ; custom implementations for external auth
		if(AuthIsValidExtArea(area) != true) {
			ok = false
			if(errMsg == "") {
				errMsg = "Ext. Area is Invalid"
			} //end if
		} //end if
		if(AuthIsValidExtUserName(userID) != true) {
			ok = false
			if(errMsg == "") {
				errMsg = "Ext. UserID is Invalid"
			} //end if
		} //end if
		if(AuthIsValidExtUserName(userName) != true) {
			ok = false
			if(errMsg == "") {
				errMsg = "Ext. UserName is Invalid"
			} //end if
		} //end if
	} //end if else
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
	if((passAlgo == ALGO_PASS_SMART_SAFE_OPQ_TOKEN) || (passAlgo == ALGO_PASS_SMART_SAFE_WEB_TOKEN) || (passAlgo == ALGO_PASS_SMART_SAFE_SWT_TOKEN)) {
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
	if(emailAddr != "") {
		if(AuthIsValidUserEmail(emailAddr) != true) {
			ok = false
			if(errMsg == "") {
				errMsg = "The Email Address is Invalid"
			} //end if
		} //end if
	} //end if
	//--
	//
	if(privKey != "") {
		if(!AuthIsValidPrivKey(privKey)) {
			ok = false
			if(errMsg == "") {
				errMsg = "The Private Key is Invalid"
			} //end if
		} //end if
	} //end if
	if(pubKey != "") {
		if(!AuthIsValidPubKey(pubKey)) {
			ok = false
			if(errMsg == "") {
				errMsg = "The Public Key is Invalid"
			} //end if
		} //end if
	} //end if
	if(secKey != "") {
		if(!AuthIsValidSecurityKey(secKey)) {
			ok = false
			if(errMsg == "") {
				errMsg = "The Security Key is Invalid"
			} //end if
		} //end if
	} //end if
	//--
	if(quota < -1) {
		ok = false
		if(errMsg == "") {
			errMsg = "The Quota is Invalid"
		} //end if
	} //end if
	//--
	var safeMetaData map[string]string = map[string]string{}
	if(metaData != nil) {
		if(len(metaData) > 0) {
			if(len(metaData) < 16) {
				for kk,vv := range metaData {
					kk = StrToLower(StrTrimWhitespaces(kk)) // {{{SYNC-METADATA-VALID-KEY-LOWERCASE}}}
					if(kk == "") { // {{{SYNC-METADATA-VALID-KEY-NON-EMPTY}}}
						safeMetaData = nil
						ok = false
						if(errMsg == "") {
							errMsg = "MetaData contains an Empty Key"
						} //end if
						break
					} //end if
					if(len(kk) > 64) { // {{{SYNC-METADATA-VALID-KEY-MAX-LEN}}}
						safeMetaData = nil
						ok = false
						if(errMsg == "") {
							errMsg = "MetaData contains an OverSized Key"
						} //end if
						break
					} //end if
					if(!StrRegexMatch(REGEX_SAFE_METAKEY, kk)) { // {{{SYNC-METADATA-VALID-KEY-REGEX}}}
						safeMetaData = nil
						ok = false
						if(errMsg == "") {
							errMsg = "MetaData contains an Invalid Key"
						} //end if
						break
					} //end if
					if(len(vv) > 4096) { // {{{SYNC-METADATA-VALID-VAL-MAX-SIZE}}}
						safeMetaData = nil
						ok = false
						if(errMsg == "") {
							errMsg = "MetaData contains an OverSized Value"
						} //end if
						break
					} //end if
					safeMetaData[kk] = vv
				} //end for
			} else {
				safeMetaData = nil
				ok = false
				if(errMsg == "") {
					errMsg = "MetaData contains too many keys"
				} //end if
			} //end if
		} //end if
	} //end if
	//--
	metaDT, okDT := safeMetaData["datetime"]
	metaDT = StrTrimWhitespaces(metaDT)
	if(!okDT || (metaDT == "")) {
		safeMetaData["datetime"] = DateNowLocal() // {{{SYNC-ACOUNT-AUTH-REGISTER-METADATA-DATETIME}}} ;  this is mandatory to be set, will be check by auth default route
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
		SecurityKey:  secKey,
		PrivKey:      privKey,
		PubKey:       pubKey,
		Privileges:   privileges,
		Restrictions: restrictions,
		EmailAddr:    emailAddr,
		FullName:     fullName,
		Quota:        quota,
		MetaData:     safeMetaData,
	}
	//--
	return privAuthData
	//--
} //END FUNCTION


//-----


func AuthIsValidExtArea(area string) bool {
	//--
	// for validating extra area(s), except HTTP_AUTH_DEFAULT_AREA which is not validated by this method because is protected
	//--
	area = StrTrimWhitespaces(area)
	if(area == "") {
		return false
	} //end if
	//--
	if(StrStartsWith(area, "[")) { // protect against default area which must not be validated here
		return false
	} //end if
	if(StrEndsWith(area, "]")) { // protect against default area which must not be validated here
		return false
	} //end if
	//--
	if((len(area) < 4) || (len(area) > 48) || (!StrRegexMatch(REGEX_SAFE_AUTH_AREA, area))) { // {{{SYNC-AUTH-EXT-AREA-CHECK}}}
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthIsValidUserEmail(email string) bool {
	//--
	if(StrTrimWhitespaces(email) == "") {
		return false
	} //end if
	//--
	if(!AuthIsValidExtUserName(email)) {
		return false
	} //end if
	//--
	if(!StrRegexMatch(REGEX_SAFE_AUTH_EMAIL_ADDRESS, email)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthIsValidExtUserName(user string) bool {
	//--
	if(StrTrimWhitespaces(user) == "") {
		return false
	} //end if
	if(StrLen(user) != StrLen(StrTrimWhitespaces(user))) {
		return false
	} //end if
	if((StrLen(user) < 5) || (StrLen(user) > 72)) { // extended max username length is 72 ; min is 5 ; {{{SYNC-SMART-EXT-USERNAME-LENGTH}}}
		return false
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_AUTH_USER_NAME, user)) {
		return false
	} //end if
	//--
	if(StrContains(user, "..")) {
		return false
	} //end if
	if(StrStartsWith(user, ".")) {
		return false
	} //end if
	if(StrEndsWith(user, ".")) {
		return false
	} //end if
	//--
	if(StrContains(user, "--")) {
		return false
	} //end if
	if(StrStartsWith(user, "-")) {
		return false
	} //end if
	if(StrEndsWith(user, "-")) {
		return false
	} //end if
	//--
	if(StrContains(user, "__")) {
		return false
	} //end if
	if(StrStartsWith(user, "_")) {
		return false
	} //end if
	if(StrEndsWith(user, "_")) {
		return false
	} //end if
	//--
	if(StrContains(user, "@@")) {
		return false
	} //end if
	if(StrStartsWith(user, "@")) {
		return false
	} //end if
	if(StrEndsWith(user, "@")) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthIsValidUserName(user string) bool {
	//--
	if(StrTrimWhitespaces(user) == "") {
		return false
	} //end if
	if(StrLen(user) != StrLen(StrTrimWhitespaces(user))) {
		return false
	} //end if
	if((StrLen(user) < 5) || (StrLen(user) > 25)) { // std max username length is 25 ; min is 5 ; {{{SYNC-SMART-USERNAME-LENGTH}}}
		return false
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_HTTP_USER_NAME, user)) {
		return false
	} //end if
	//--
	if(StrContains(user, "..")) {
		return false
	} //end if
	if(StrStartsWith(user, ".")) {
		return false
	} //end if
	if(StrEndsWith(user, ".")) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthIsValidPassword(pass string) bool {
	//--
	if(StrTrimWhitespaces(pass) == "") {
		return false
	} //end if
	if(StrLen(pass) != StrLen(StrTrimWhitespaces(pass))) {
		return false
	} //end if
	if((StrLen(StrTrimWhitespaces(pass)) < 7) || (StrLen(pass) > int(PASSWORD_PLAIN_MAX_LENGTH))) { // {{{SYNC-PASS-MAX-SAFE-LENGTH}}} ; std max password length is 55 (compatible with PHP BCrypt) ; min is 7
		return false
	} //end if
	//--
	if(StrNormalizeSpaces(pass) != pass) { // disallow null and other weird characters
		return false
	} //end if
	//--
	if( // password min complexity check ; disallow too simple passwords for security reasons ...
		(StrRegexMatch(`[A-Z]+`, pass) != true) || // must have at least one caps letter
		(StrRegexMatch(`[a-z]+`, pass) != true) || // must have at least one small letter
		(StrRegexMatch(`[0-9]+`, pass) != true) || // must have at least one digit
		(StrRegexMatch(`[^A-Za-z0-9]+`, pass) != true)) { // must have at least one special character
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthIsValidTokenOpaque(token string) bool {
	//--
	if(StrTrimWhitespaces(token) == "") {
		return false
	} //end if
	if(StrLen(token) != StrLen(StrTrimWhitespaces(token))) {
		return false
	} //end if
	if((StrLen(token) < 44) || (StrLen(token) > 126)) { // {{{SYNC-MAX-AUTH-TOKEN-LENGTH}}} ; 44 is in SF ; allow just 126 do not encourage sha hex
		return false
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_AUTH_OPAQUE_TOKEN, token)) { // {{{SYNC-SF:REGEX_SAFE_AUTH_OPAQUE_TOKEN}}}
		return false
	} //end if
	//--
	if(StrContains(token, "--")) {
		return false
	} //end if
	if(StrStartsWith(token, "-")) {
		return false
	} //end if
	if(StrEndsWith(token, "-")) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthIsValid2FACode(code string) bool {
	//--
	if(StrTrimWhitespaces(code) == "") {
		return false
	} //end if
	if(StrLen(code) != StrLen(StrTrimWhitespaces(code))) {
		return false
	} //end if
	if((StrLen(code) < 6) || (StrLen(code) > 8)) { // flexible, between 6 and 8 characters
		return false
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_AUTH_2FA_CODE, code)) { // {{{SYNC-SF:REGEX_SAFE_AUTH_2FA_CODE}}}
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthIsValidSecurityKey(key string) bool { // {{{SYNC-GO-SMART-CRYPTO-SECURITY-KEY-OR-AUTH-PKEY}}}
	//--
	if(StrTrimWhitespaces(key) == "") {
		return false
	} //end if
	if(StrLen(key) != StrLen(StrTrimWhitespaces(key))) {
		return false
	} //end if
	if((StrLen(key) < 16) || (StrLen(key) > 256)) { // 256 is req. by the msgpak server ...
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthIsValidPrivKey(key string) bool {
	//--
	if(StrTrimWhitespaces(key) == "") {
		return false
	} //end if
	if(StrLen(key) != StrLen(StrTrimWhitespaces(key))) {
		return false
	} //end if
	if((StrLen(key) < 64) || (StrLen(key) > 512)) { // 64 B = 512 b ; 512 B = 4096 b ; ex: Ed448 / Edx448 Pub: # 152 bytes ; Ed25519 / Edx25519 Pub: 88 bytes
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthIsValidPubKey(key string) bool {
	//--
	if(StrTrimWhitespaces(key) == "") {
		return false
	} //end if
	if(StrLen(key) != StrLen(StrTrimWhitespaces(key))) {
		return false
	} //end if
	if((StrLen(key) < 32) || (StrLen(key) > 256)) { // 64 B = 256 b ; 256 B = 2048 b ; ex: Ed448 / Edx448 Pub: # 76 bytes ; Ed25519 / Edx25519 Pub: 44 bytes
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthAnyIsEnabled() bool {
	//--
	if((AuthBasicIsEnabled() != true) && (AuthTokenIsEnabled() != true) && (AuthBearerIsEnabled() != true) && (AuthApikeyIsEnabled() != true) && (AuthCookieIsEnabled() != true)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthSafeCompare(val1 string, val2 string) bool {
	//--
	// the logic of the checks before is for security not for speed or memory or cpu !
	//--
	if(subtle.ConstantTimeCompare([]byte(val1), []byte(val2)) != 1) { // compare first values (and length too) as bytes, in constant time, safe against timing attacks
		return false
	} //end if
	//--
	if(len(val1) != len(val2)) { // second redundant check, length as strings
		return false
	} //end if
	//--
	if(val1 != val2) { // third, redundant check as strings
		return false
	} //end if
	//--
	if((StrTrimWhitespaces(val1) == "") || (StrTrimWhitespaces(val2) == "")) { // finally, disallow empty values
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthUserPassDefaultCheck(authRealm string, user string, pass string, authMode uint8, requiredUsername string, requiredPassword string, passHashAlgo uint8, emailAddr string, fullName string, privileges string, restrictions string, privKey string, pubKey string, secKey string, quota int64, metaData map[string]string) (bool, AuthDataStruct) {
	//--
	// the requiredPassword must be the plain password just if passHashAlgo = ALGO_PASS_PLAIN
	// otherwise must be the already hashed password as:
	// 	* SafePassHashSmart(pass, user, false) for ALGO_PASS_SMART_SAFE_SF_PASS
	// 	* SafePassHashSmart(pass, user, true)  for ALGO_PASS_SMART_SAFE_ARGON_PASS
	// 	* SafePassHashBcrypt(pass, 0)          for ALGO_PASS_SMART_SAFE_BCRYPT
	//--
	authData := AuthDataStruct{
		OK: false,
		ErrMsg: "??",
		Method: authMode,
		UserName: user, // for logging purposes
	}
	//--
	if((AuthBasicIsEnabled() != true) && (AuthCookieIsEnabled() != true)) { // this only supports: Auth Basic (default or custom check) or Auth Cookie (custom check only)
		authData.ErrMsg = "Auth is Disabled: No Active Auth Providers are Available"
		return false, authData
	} //end if
	//-- {{{SYNC-AUTH-MODES}}}
	if((authMode != HTTP_AUTH_MODE_BASIC) && (authMode != HTTP_AUTH_MODE_COOKIE)) {
		authData.ErrMsg = "Unsupported Auth Mode: " + ConvertUInt8ToStr(authMode)
		return false, authData
	} //end if
	//-- {{{SYNC-HTTP-AUTH-CHECKS-2ND-GO-SMART}}}
	if(StrTrimWhitespaces(user) == "") {
		authData.ErrMsg = "Empty UserName"
		return false, authData
	} //end if
	if(AuthIsValidUserName(user) != true) {
		authData.ErrMsg = "Invalid UserName"
		return false, authData
	} //end if
	if(StrTrimWhitespaces(pass) == "") {
		authData.ErrMsg = "Empty Password"
		return false, authData
	} //end if
	if(AuthIsValidPassword(pass) != true) {
		authData.ErrMsg = "Invalid Password"
		return false, authData
	} //end if
	//-- #end: sync
	var useArgonId bool = false
	var hashedPass string = ""
	switch(passHashAlgo) { // {{{SYNC-AUTH-PASS-ALGOS}}}
		case ALGO_PASS_SMART_SAFE_SF_PASS:
			hashedPass, _ = SafePassHashSmart(pass, user, false)
			break
		case ALGO_PASS_SMART_SAFE_ARGON_PASS: // recommended just with Auth Cookie, will be used one time, then JWT ... ; auth basic is doing auth at every page entry, it is to costly ...
			useArgonId = true
			hashedPass, _ = SafePassHashSmart(pass, user, true)
			break
		case ALGO_PASS_SMART_SAFE_BCRYPT:
			hashedPass = requiredPassword // bcrypt hashes are never are the same, keep the entry value ...
			break
		case ALGO_PASS_PLAIN: // encode as Blowfish using the app secret key, to avoid display plain password accidentally
			sKey, errSKey := AppGetSecurityKey()
			if(errSKey != nil) {
				log.Println("[ERROR]", CurrentFunctionName(), ": Algo: Pass Plain: App Security Key ERR:", errSKey)
				authData.ErrMsg = "Password Internal Encryption is Unavailable"
				return false, authData
			} //end if
			hashedPass = BlowfishEncryptCBC(pass, sKey, true) // randomize
			break
		default:
			authData.ErrMsg = "Invalid Pass Hashing Algo: [" + ConvertUInt8ToStr(passHashAlgo) + "]"
			return false, authData
	} //end if
	//-- {{{SYNC-HTTP-AUTH-CHECKS-GO-SMART}}}
	if(AuthSafeCompare(user, requiredUsername) != true) {
		authData.ErrMsg = "UserName does not match"
		return false, authData
	} //end if
	if(passHashAlgo == ALGO_PASS_PLAIN) {
		if(AuthSafeCompare(pass, requiredPassword) != true) {
			authData.ErrMsg = "Password does not match (1)"
			return false, authData
		} //end if
	} else if(passHashAlgo == ALGO_PASS_SMART_SAFE_BCRYPT) {
		if(SafePassHashBcryptVerify(requiredPassword, pass) != true) {
			authData.ErrMsg = "Password does not match (2)"
			return false, authData
		} //end if
	} else { // SmartPass
		if(SafePassHashSmartVerify(requiredPassword, pass, user, useArgonId) != true) { // compare the plain passwords, the hash has been created only at this step to be safe stored in auth data ; step 1 verification
			authData.ErrMsg = "Password does not match (3." + ConvertBoolToStr(useArgonId) + ")" // 3.0 default ; 3.1 argon
			return false, authData
		} //end if
		if(AuthSafeCompare(hashedPass, requiredPassword) != true) { // compare with the entry hash of this method with the hash created in this method, required too ; step 2 verification
			authData.ErrMsg = "Password Hash does not match"
			return false, authData
		} //end if
	} //end if else
	//-- #end: sync
	authChkData := AuthDataInit(true, "", authMode, HTTP_AUTH_DEFAULT_AREA, authRealm, user, user, hashedPass, passHashAlgo, "", "", emailAddr, fullName, privileges, restrictions, privKey, pubKey, secKey, quota, metaData)
	if(authChkData.ErrMsg != "") {
		return false, authChkData
	} //end if
	if(authChkData.OK != true) {
		authChkData.ErrMsg = "Invalid Auth Data Status"
		return false, authChkData
	} //end if
	//--
	return authChkData.OK, authChkData
	//--
} //END FUNCTION


func AuthUserTokenDefaultCheck(authRealm string, user string, token string, authMode uint8, requiredUsername string, requiredToken string, emailAddr string, fullName string, privileges string, restrictions string, privKey string, pubKey string, secKey string, quota int64, metaData map[string]string) (bool, AuthDataStruct) {
	//--
	authData := AuthDataStruct{
		OK: false,
		ErrMsg: "??",
		Method: authMode,
		UserName: user, // for logging purposes
	}
	//--
	if((AuthTokenIsEnabled() != true) && (AuthBearerIsEnabled() != true)) { // can be used just with Auth Token in the default or custom check implementations ; may be also used with Auth Bearer (if Auth Bearer is with Opaque Tokens only, not with JWT) in the custom check implementation mode
		authData.ErrMsg = "Auth is Disabled: No Active Auth Providers are Available"
		return false, authData
	} //end if
	//-- {{{SYNC-AUTH-MODES}}}
	if((authMode != HTTP_AUTH_MODE_BASIC) && (authMode != HTTP_AUTH_MODE_TOKEN) && (authMode != HTTP_AUTH_MODE_BEARER)) {
		authData.ErrMsg = "Unsupported Auth Mode: " + ConvertUInt8ToStr(authMode)
		return false, authData
	} //end if
	//-- {{{SYNC-HTTP-AUTH-CHECKS-2ND-GO-SMART}}}
	if(StrTrimWhitespaces(user) == "") {
		authData.ErrMsg = "Empty UserName"
		return false, authData
	} //end if
	if(AuthIsValidUserName(user) != true) {
		authData.ErrMsg = "Invalid UserName"
		return false, authData
	} //end if
	if(StrTrimWhitespaces(token) == "") {
		authData.ErrMsg = "Empty Token"
		return false, authData
	} //end if
	if(AuthIsValidTokenOpaque(token) != true) {
		authData.ErrMsg = "Invalid Token"
		return false, authData
	} //end if
	//-- {{{SYNC-HTTP-AUTH-CHECKS-GO-SMART}}}
	if(AuthSafeCompare(user, requiredUsername) != true) {
		authData.ErrMsg = "UserName does not match"
		return false, authData
	} //end if
	if(AuthSafeCompare(token, requiredToken) != true) {
		authData.ErrMsg = "Token does not match"
		return false, authData
	} //end if
	//-- #end: sync
	authChkData := AuthDataInit(true, "", authMode, HTTP_AUTH_DEFAULT_AREA, authRealm, user, user, "", ALGO_PASS_SMART_SAFE_OPQ_TOKEN, token, OPAQUE_TOKEN_FULL_NAME, emailAddr, fullName, privileges, restrictions, privKey, pubKey, secKey, quota, metaData)
	if(authChkData.ErrMsg != "") {
		return false, authChkData
	} //end if
	if(authChkData.OK != true) {
		authChkData.ErrMsg = "Invalid Auth Data Status"
		return false, authChkData
	} //end if
	//--
	return authChkData.OK, authChkData
	//--
} //END FUNCTION


func AuthUserTokenDefaultSepareParts(token string) (string, string, error) { // returns: userName, tokenHash, errTokenSepare
	//--
	// expects: `user#token-hash` ; to be used with HTTP Headers as: `Authorization: Token user#token-hash`
	//--
	token = StrTrimWhitespaces(token)
	if(token == "") {
		return "", "", NewError("Token is Empty")
	} //end if
	//--
	if(!StrContains(token, "#")) {
		return "", "", NewError("Token is Malformed")
	} //end if
	arrParts := ExplodeWithLimit("#", token, 3)
	if(len(arrParts) != 2) {
		return "", "", NewError("Invalid Token Format")
	} //end if
	//--
	var userName string = StrTrimWhitespaces(arrParts[0]) // username part
	if((userName == "") || (AuthIsValidUserName(userName) != true)) {
		return userName, "", NewError("Invalid Token UserName Format")
	} //end if
	//--
	var tokenHash string = StrTrimWhitespaces(arrParts[1]) // hash (uuid) part, the real token
	if((tokenHash == "") || (AuthIsValidTokenOpaque(tokenHash) != true)) {
		return userName, tokenHash, NewError("Invalid Token Hash Format")
	} //end if
	//--
	return userName, tokenHash, nil
	//--
} //END FUNCTION


func AuthUserTokenBasicSepareParts(usernameWithTokenSuffix string, passAsTokenHash string) (string, string, error) { // returns: userName, suffix, errTokenSepare
	//--
	// expects `user#token` ; to be used via Auth Basic as the userName part ; the password will be the token hash, but is not managed in this method
	//--
	usernameWithTokenSuffix = StrTrimWhitespaces(usernameWithTokenSuffix)
	if(usernameWithTokenSuffix == "") {
		return "", "", NewError("Raw UserName is Empty")
	} //end if
	//--
	passAsTokenHash = StrTrimWhitespaces(passAsTokenHash)
	if(passAsTokenHash == "") {
		return "", "", NewError("Token is Empty")
	} //end if
	if(AuthIsValidTokenOpaque(passAsTokenHash) != true) {
		return "", "", NewError("Invalid Token Format")
	} //end if
	var tokenHash string = passAsTokenHash
	//--
	if(!StrContains(usernameWithTokenSuffix, "#")) {
		return "", "", NewError("Raw UserName is Malformed")
	} //end if
	arrParts := ExplodeWithLimit("#", usernameWithTokenSuffix, 3)
	if(len(arrParts) != 2) {
		return "", "", NewError("Invalid Raw UserName Format")
	} //end if
	//--
	var userName string = StrTrimWhitespaces(arrParts[0]) // username part
	if((userName == "") || (AuthIsValidUserName(userName) != true)) {
		return userName, "", NewError("Invalid Raw UserName Format: UserName")
	} //end if
	//--
	var suffix string = StrTrimWhitespaces(arrParts[1]) // hash (uuid) part, the real token
	if((suffix == "") || (suffix != "token")) {
		return userName, suffix, NewError("Invalid Raw UserName Format: Suffix")
	} //end if
	//--
	return userName, tokenHash, nil
	//--
} //END FUNCTION


//-----


func AuthGetUserDefaultPrivKey(username string) string { // for internal use only ! for default auth or when a user does not have a private key, compose one by secure hashing the username and the default app key
	//--
	username = StrTrimWhitespaces(username)
	if((username == "") || (AuthIsValidExtUserName(username) != true)) {
		return ""
	} //end if
	//--
	pkey, err := AppGetSecurityKey()
	if(err != nil) {
		log.Println("[ERROR]", CurrentFunctionName(), ": App Security Key ERR:", err)
		return ""
	} //end if
	//--
	key := BaseEncode([]byte(Sha512(username + NULL_BYTE + pkey)), "b85") // use this when not having per/user security key
	if(!AuthIsValidPrivKey(key)) {
		log.Println("[ERROR]", CurrentFunctionName(), ": Key is Invalid")
		return ""
	} //end if
	//--
	return key // valid: 64..512
	//--
} //END FUNCTION


func AuthGetUserDefaultSecurityKey(username string) string { // for internal use only ! for default auth or when a user does not have a security key, compose one by secure hashing the username and the default app key
	//--
	username = StrTrimWhitespaces(username)
	if((username == "") || (AuthIsValidExtUserName(username) != true)) {
		return ""
	} //end if
	//--
	pkey, err := AppGetSecurityKey()
	if(err != nil) {
		log.Println("[ERROR]", CurrentFunctionName(), ": App Security Key ERR:", err)
		return ""
	} //end if
	//--
	key := BaseEncode([]byte(Sha256(username + FORM_FEED + pkey)), "b92") // use this when not having per/user security key
	if(!AuthIsValidSecurityKey(key)) {
		log.Println("[ERROR]", CurrentFunctionName(), ": Key is Invalid")
		return ""
	} //end if
	//--
	return key // valid: 16..256
	//--
} //END FUNCTION


//-----


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
		case HTTP_AUTH_MODE_TOKEN:
			name = "Token"
			break
		case HTTP_AUTH_MODE_BEARER:
			name = "Bearer"
			break
		case HTTP_AUTH_MODE_COOKIE:
			name = "Cookie"
			break
		case HTTP_AUTH_MODE_APIKEY:
			name = "ApiKey"
			break
		case HTTP_AUTH_MODE_RAW:
			name = "Raw"
			break
	} //end switch
	//--
	return name
	//--
} //END FUNCTION


//-----


func AuthPassHashAlgoGetNameById(algo uint8) string {
	//--
	var name string = "Unknown"
	switch(algo) { // {{{SYNC-AUTH-PASS-ALGOS}}}
		case ALGO_PASS_NONE:
			name = "None"
			break
		case ALGO_PASS_PLAIN:
			name = "Plain"
			break
		case ALGO_PASS_SMART_SAFE_SF_PASS:
			name = "SafePass.Smart"
			break
		case ALGO_PASS_SMART_SAFE_ARGON_PASS:
			name = "SafePass.Smart.Argon"
			break
		case ALGO_PASS_SMART_SAFE_BCRYPT:
			name = "BCrypt"
			break
		case ALGO_PASS_SMART_SAFE_OPQ_TOKEN:
			name = "Token.Opaque"
			break
		case ALGO_PASS_SMART_SAFE_WEB_TOKEN:
			name = "Token.Signed"
			break
		case ALGO_PASS_SMART_SAFE_SWT_TOKEN:
			name = "Token.SWT"
			break
		case ALGO_PASS_CUSTOM_TOKEN:
			name = "Custom.Token"
			break
		case ALGO_PASS_CUSTOM_HASH_PASS:
			name = "Custom.Pass.Hash"
			break
	} //end if
	//--
	return name
	//--
} //END FUNCTION


//-----


// conforms list `<one>, <two>` to a safe one
func AuthSafeListPrivsRestr(list string) string {
	//--
	arr := SmartListToArr(list, true)
	if(len(arr) <= 0) {
		return ""
	} //end if
	//--
	var safeArr []string = []string{}
	//--
	for i:=0; i<len(arr); i++ {
		//--
		var val string = arr[i]
		//--
		val = StrToLower(StrTrimWhitespaces(val))
		//--
		if(
			(val != "") &&
			(len(val) >= 2) &&
			(len(val) <= 22) &&
			(!StrContains(val, "--")) &&
			(!StrContains(val, "::")) &&
			(StrRegexMatch(REGEX_VALID_PRIV_RESTR_KEY, val))) {
				if(!InListArr(val, safeArr)) {
					safeArr = append(safeArr, val)
				} //end if
		} //end if
		//--
	} //end for
	//--
	return SmartArrToList(safeArr, false)
	//--
} //END FUNCTION


// test if priv or restr `one` is in list `<one>,<two>`
func AuthSafeTestPrivsRestr(list string, entry string) bool {
	//--
	list = StrTrimWhitespaces(list)
	if(list == "") {
		return false
	} //end if
	//--
	entry = StrToLower(StrTrimWhitespaces(StrTrim(entry, "<>")))
	if(entry == "") {
		return false
	} //end if
	//--
	return StrContains(list, "<" + entry + ">")
	//--
} //END FUNCTION


//-----


// #END
