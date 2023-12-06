
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231206.2358 :: STABLE
// [ AUTH ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"crypto/subtle"
)

const (
	ALGO_PASS_SMART_SAFE_PASS uint8 = 0
	ALGO_PASS_SMART_SAFE_ARGON_PASS uint8 = 1
	// 10..255 other pass algos ; 2..10 is reserved for internal use

	HTTP_AUTH_MODE_NONE   uint8 = 0
	HTTP_AUTH_MODE_BASIC  uint8 = 1
	HTTP_AUTH_MODE_BEARER uint8 = 2
	HTTP_AUTH_MODE_COOKIE uint8 = 3

	REGEX_SAFE_HTTP_USER_NAME string = `^[a-z0-9\.]+$` // Safe UserName Regex
)


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


func AuthUserPassDefaultCheck(authRealm string, authMode uint8, user string, pass string, requiredUsername string, requiredPassword string) (bool, AuthDataStruct) {
	//--
	authData := AuthDataStruct{
		OK: false,
		ErrMsg: "??",
	}
	//--
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


func AuthTokenDefaultCheck(authRealm string, authMode uint8, clientIP string, token string, requiredUsername string, requiredPassword string) (bool, AuthDataStruct) {
	//--
	// TODO: ...
	// 	* implement SWT
	// 	* requiredPassword hash by using SafePassHashSmart() for SWT
	//--
	authData := AuthDataStruct{
		OK: false,
		ErrMsg: "Not Implemented ...",
	}
	//--
	return false, authData
	//--
} //END FUNCTION


//-----


// #END
