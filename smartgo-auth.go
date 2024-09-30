
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240930.1531 :: STABLE
// [ AUTH ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"crypto/subtle"
)

const (
	ALGO_PASS_SMART_SAFE_PASS uint8 		= 0
	ALGO_PASS_SMART_SAFE_ARGON_PASS uint8 	= 1
	// 10..255 other pass algos ; 2..10 is reserved for internal use

	HTTP_AUTH_MODE_NONE   uint8 = 0
	HTTP_AUTH_MODE_BASIC  uint8 = 1
	HTTP_AUTH_MODE_BEARER uint8 = 2
	HTTP_AUTH_MODE_COOKIE uint8 = 3
	HTTP_AUTH_MODE_TOKEN  uint8 = 4

	REGEX_SAFE_HTTP_USER_NAME string = `^[a-z0-9\.]+$` // Safe UserName Regex
)

var (
	authBasicEnabled bool = true 		// default is TRUE,  does accept Auth Basic if HTTP Server ask for it ; to disable, set to FALSE
	authBearerEnabled bool = false 		// default is FALSE, does not accept Auth Bearer ; to accept Auth Bearer, set to TRUE
	authCookieName string = "" 			// [2..16 characters ; valid REGEX_SAFE_VAR_NAME] ; default is EMPTY, does not accept Auth by Cookies ; to accept Auth by Cookie, set to ~ "Sf_Auth"

	auth2FACookieName string = "" 		// [2..16 characters ; valid REGEX_SAFE_VAR_NAME] ; default is EMPTY, to Enable 2FA (TOTP), set to ~ "Sf_2FA" ; this is intended to be used with Basic Auth, but for custom auth can be implemented also with Cookie or Bearer ...
)

//-----


func AuthBasicIsEnabled() bool {
	//--
	return authBasicEnabled
	//--
} //END FUNCTION


func AuthBasicModeSet(mode bool) bool {
	//--
	authBasicEnabled = mode
	//--
	return true
	//--
} //END FUNCTION


//-----


func AuthBearerIsEnabled() bool {
	//--
	return authBearerEnabled
	//--
} //END FUNCTION


func AuthBearerModeSet(mode bool) bool {
	//--
	authBearerEnabled = mode
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
	if(cookieName != "") { // do not check below for empty cookie name, must be a way to be unset by passing empty string to this method
		if(!ValidateCookieName(cookieName)) {
			cookieName = "" // reset, invalid
			ok = false // was non-empty, but invalid
		} //end if
	} //end if
	//--
	if(cookieName != "") {
		if((cookieName == auth2FACookieName) || (cookieName == sessionUUIDCookieName)) { // avoid collision with auth2FACookieName or sessionUUIDCookieName
			cookieName = "" // reset, invalid
			ok = false // was non-empty, but invalid
		} //end if
	} //end if
	//--
	authCookieName = cookieName // set or unset
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
	if(cookieName != "") { // do not check below for empty cookie name, must be a way to be unset by passing empty string to this method
		if(!ValidateCookieName(cookieName)) {
			cookieName = "" // reset, invalid
			ok = false // was non-empty, but invalid
		} //end if
	} //end if
	//--
	if(cookieName != "") {
		if((cookieName == authCookieName) || (cookieName == sessionUUIDCookieName)) { // avoid collision with authCookieName or sessionUUIDCookieName
			cookieName = "" // reset, invalid
			ok = false // was non-empty, but invalid
		} //end if
	} //end if
	//--
	auth2FACookieName = cookieName // set or unset
	//--
	return ok
	//--
} //END FUNCTION


//-----


// PRIVATE
type AuthDataStruct struct {
	OK           bool               // TRUE | FALSE
	ErrMsg       string             // error message (if any) or empty string
	Method       uint8              // see: HTTP_AUTH_MODE_*
	Area         string             // Auth Area
	Realm        string             // Auth Realm
	UserID       string             // User ID (if no specific ID can be the same as User Name)
	UserName     string             // User Name
	PassHash     string             // Password Hash
	PassAlgo     uint8              // Password Hash Algo ; 0 for SafePassHashSmart ; 1..255 for the rest
	EmailAddr    string             // User Email Address
	FullName     string             // Full Name
	Privileges   string             // Privileges: <priv1>,<priv2>,...
	Restrictions string             // Restrictions: <restr1>,<restr2>,...
	PrivKey      string             // Private Key
	Quota        uint64             // Quota
	MetaData     map[string]string  // MetaData ... Associative Array {"key1":"Val1", "key2":"Val2", ...}
	// TODO: add clientIP, userAgent, ...
}

//-----


func AuthDataGet(ok bool, errMsg string, method uint8, area string, realm string, userID string, userName string, passHash string, passAlgo uint8, emailAddr string, fullName string, privileges string, restrictions string, privKey string, quota uint64, metaData map[string]string) AuthDataStruct {
	//--
	errMsg 			= StrTrimWhitespaces(errMsg)
	area 			= StrToUpper(StrTrimWhitespaces(area))
	realm 			= StrToUpper(StrTrimWhitespaces(realm))
	userID 			= StrToLower(StrTrimWhitespaces(userID)) // TODO: validate
	userName 		= StrToLower(StrTrimWhitespaces(userName)) // TODO: validate
	passHash 		= StrTrimWhitespaces(passHash) // TODO: validate
	emailAddr 		= StrToLower(StrTrimWhitespaces(emailAddr)) // TODO: validate
	fullName 		= StrTrimWhitespaces(fullName)
	privileges 		= StrTrimWhitespaces(privileges) // TODO: validate
	restrictions 	= StrTrimWhitespaces(restrictions) // TODO: validate
	privKey 		= StrTrimWhitespaces(privKey)
	//--
	if(userID == "") {
		userID = userName
	} else if(userName == "") {
		userName = userID
	} //end if
	//--
//	metaData["#"] = "authMetaData:v1.0"
	//--
	privAuthData := AuthDataStruct {
		OK:           ok,
		ErrMsg:       errMsg,
		Method:       method,
		Area:         area,
		Realm:        realm,
		UserID:       userID,
		UserName:     userName,
		PassHash:     passHash,
		PassAlgo:     passAlgo,
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


func AuthUserPassDefaultCheck(authRealm string, authMode uint8, user string, pass string, cookies map[string]string, requiredUsername string, requiredPassword string) (bool, AuthDataStruct) {
	//--
	// TODO: cookies will be used for 2FA (if enabled) in combination with Basic Auth
	//--
	authData := AuthDataStruct{
		OK: false,
		ErrMsg: "??",
		Method: authMode,
	}
	//--
	if(AuthBasicIsEnabled() != true) {
		//--
		authData.ErrMsg = "Auth Basic is Disabled"
		//--
		return false, authData
		//--
	} //end if
	if( // {{{SYNC-HTTP-AUTH-CHECKS-GO-SMART}}}
		(StrTrimWhitespaces(user) == "") ||
		((len(user) < 3) || (len(user) > 128)) || // {{{SYNC-GO-SMART-AUTH-USER-LEN}}} ; std max username length is 128 ; min 3, from Smart.Framework
		(!StrRegexMatchString(REGEX_SAFE_HTTP_USER_NAME, user)) || // {{{SYNC-SF:REGEX_VALID_USER_NAME}}}
		//--
		(StrTrimWhitespaces(pass) == "") ||
		((len(StrTrimWhitespaces(pass)) < 7) || (len(pass) > 2048)) || // {{{SYNC-GO-SMART-AUTH-PASS-LEN}}} ; allow tokens, length can be up to 2048 (ex: JWT) ; min 7, from Smart.Framework (security)
		//--
		(len(user) != len(requiredUsername)) ||
		(len(pass) != len(requiredPassword)) ||
		(subtle.ConstantTimeCompare([]byte(user), []byte(requiredUsername)) != 1) ||
		(subtle.ConstantTimeCompare([]byte(pass), []byte(requiredPassword)) != 1) ||
		(user != requiredUsername) || (pass != requiredPassword)) {
		//--
		authData.ErrMsg = "Invalid UserName or Password"
		//--
		return false, authData
		//--
	} //end if
	//--
	authData = AuthDataGet(true, "", authMode, "DEFAULT", authRealm, user, user, SafePassHashSmart(pass, user, false), ALGO_PASS_SMART_SAFE_PASS, "", "", "<default>", "<none>", "", 0, nil)
	//--
	return true, authData
	//--
} //END FUNCTION


func AuthTokenDefaultCheck(authRealm string, authMode uint8, clientIP string, token string, cookies map[string]string) (bool, AuthDataStruct) {
	//--
	// TODO: cookies will be used for 2FA (if enabled) in combination with Bearer Auth
	//--
	// TODO: ...
	// 	* implement SWT
	// 	* requiredPassword hash by using SafePassHashSmart() for SWT
	//--
	errMsg := "Auth by Token (Bearer) is Not (yet) Implemented ... TODO ..."
	if(AuthBearerIsEnabled() != true) {
		errMsg = "Auth by Token (Bearer) is Disabled"
	} //end if
	//--
	authData := AuthDataStruct{
		OK: false,
		ErrMsg: errMsg,
		Method: authMode,
	}
	//--
	return false, authData
	//--
} //END FUNCTION


func AuthCookieDefaultCheck(authRealm string, authMode uint8, clientIP string, cookies map[string]string) (bool, AuthDataStruct) {
	//--
	// TODO: ...
	// 	* implement SWT
	// 	* requiredPassword hash by using SafePassHashSmart() for SWT
	//--
	errMsg := "Auth by Cookie is Not (yet) Implemented ... TODO ..."
	if(AuthCookieIsEnabled() != true) {
		errMsg = "Auth by Cookie is Disabled"
	} else {
		var ckName string = AuthCookieNameGet()
		if(ckName == "") {
			errMsg += " # ERR: Empty Cookie Name"
		} else {
			errMsg += " # Cookie Name [" + ckName + "]"
		} //end if
	} //end if else
	//--
	authData := AuthDataStruct{
		OK: false,
		ErrMsg: errMsg,
		Method: authMode,
	}
	//--
	return false, authData
	//--
} //END FUNCTION


//-----


// #END
